//! A pure-Rust implementation of SFTP client independent to transport layer.

use crate::consts::*;
use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
    os::unix::prelude::*,
    sync::{Arc, Mutex, Weak},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

// Refs:
// * https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
// * https://tools.ietf.org/html/rfc4251
// * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sftp-server.c?rev=1.120&content-type=text/x-cvsweb-markup

pub mod consts {
    pub const SFTP_PROTOCOL_VERSION: u32 = 3;

    // defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-3
    pub const SSH_FXP_INIT: u8 = 1;
    pub const SSH_FXP_VERSION: u8 = 2;
    pub const SSH_FXP_OPEN: u8 = 3;
    pub const SSH_FXP_CLOSE: u8 = 4;
    pub const SSH_FXP_READ: u8 = 5;
    pub const SSH_FXP_WRITE: u8 = 6;
    pub const SSH_FXP_LSTAT: u8 = 7;
    pub const SSH_FXP_FSTAT: u8 = 8;
    pub const SSH_FXP_SETSTAT: u8 = 9;
    pub const SSH_FXP_FSETSTAT: u8 = 10;
    pub const SSH_FXP_OPENDIR: u8 = 11;
    pub const SSH_FXP_READDIR: u8 = 12;
    pub const SSH_FXP_REMOVE: u8 = 13;
    pub const SSH_FXP_MKDIR: u8 = 14;
    pub const SSH_FXP_RMDIR: u8 = 15;
    pub const SSH_FXP_REALPATH: u8 = 16;
    pub const SSH_FXP_STAT: u8 = 17;
    pub const SSH_FXP_RENAME: u8 = 18;
    pub const SSH_FXP_READLINK: u8 = 19;
    pub const SSH_FXP_SYMLINK: u8 = 20;
    pub const SSH_FXP_STATUS: u8 = 101;
    pub const SSH_FXP_HANDLE: u8 = 102;
    pub const SSH_FXP_DATA: u8 = 103;
    pub const SSH_FXP_NAME: u8 = 104;
    pub const SSH_FXP_ATTRS: u8 = 105;
    pub const SSH_FXP_EXTENDED: u8 = 200;
    pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

    // defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-7
    pub const SSH_FX_OK: u32 = 0;
    pub const SSH_FX_EOF: u32 = 1;
    pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
    pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
    pub const SSH_FX_FAILURE: u32 = 4;
    pub const SSH_FX_BAD_MESSAGE: u32 = 5;
    pub const SSH_FX_NO_CONNECTION: u32 = 6;
    pub const SSH_FX_CONNECTION_LOST: u32 = 7;
    pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

    // defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
    pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
    pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
    pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
    pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
    pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

    // defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.3
    pub const SSH_FXF_READ: u32 = 0x00000001;
    pub const SSH_FXF_WRITE: u32 = 0x00000002;
    pub const SSH_FXF_APPEND: u32 = 0x00000004;
    pub const SSH_FXF_CREAT: u32 = 0x00000008;
    pub const SSH_FXF_TRUNC: u32 = 0x00000010;
    pub const SSH_FXF_EXCL: u32 = 0x00000020;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("errored in underlying transport I/O")]
    Transport(
        #[from]
        #[source]
        io::Error,
    ),

    #[error("protocol error")]
    Protocol { msg: Cow<'static, str> },

    #[error("from remote: {}", _0)]
    Remote(#[source] RemoteError),

    #[error("session has already been closed")]
    SessionClosed,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// described in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct FileAttr {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    pub permissions: Option<u32>,
    pub ac_mod_time: Option<(u32, u32)>,
    pub extended: Vec<(OsString, OsString)>,
}

impl FileAttr {
    pub fn uid(&self) -> Option<u32> {
        self.uid_gid.map(|(uid, _)| uid)
    }

    pub fn gid(&self) -> Option<u32> {
        self.uid_gid.map(|(_, gid)| gid)
    }

    pub fn atime(&self) -> Option<u32> {
        self.ac_mod_time.map(|(atime, _)| atime)
    }

    pub fn mtime(&self) -> Option<u32> {
        self.ac_mod_time.map(|(_, mtime)| mtime)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct DirEntry {
    pub filename: OsString,
    pub longname: OsString,
    pub attrs: FileAttr,
}

#[derive(Debug)]
pub struct FileHandle(OsString);

#[derive(Debug, thiserror::Error)]
#[error("from remote server")]
pub struct RemoteError(RemoteStatus);

impl RemoteError {
    pub fn code(&self) -> u32 {
        self.0.code
    }

    pub fn message(&self) -> &OsStr {
        &self.0.message
    }

    pub fn language_tag(&self) -> &OsStr {
        &self.0.language_tag
    }
}

/// The handle for communicating with associated SFTP session.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Weak<Inner>,
}

impl Session {
    async fn request(&self, request: Request) -> Result<Response> {
        let inner = self.inner.upgrade().ok_or(Error::SessionClosed)?;

        let rx = {
            let pending_requests = &mut *inner.pending_requests.lock().unwrap();
            let id = pending_requests.next_request_id;

            inner.incoming_requests.send((id, request)).map_err(|_| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "session is not available")
            })?;

            let (tx, rx) = oneshot::channel();
            pending_requests.senders.insert(id, tx);

            pending_requests.next_request_id = pending_requests.next_request_id.wrapping_add(1);

            rx
        };

        rx.await.map_err(|_| Error::SessionClosed)
    }

    /// Request to open a file.
    pub async fn open(
        &self,
        filename: impl AsRef<OsStr>,
        pflags: u32,
        attrs: FileAttr,
    ) -> Result<FileHandle> {
        let response = self
            .request(Request::Open {
                filename: filename.as_ref().to_owned(),
                pflags,
                attrs,
            })
            .await?;
        match response {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to close a file corresponding to the specified handle.
    pub async fn close(&self, handle: &FileHandle) -> Result<()> {
        let response = self
            .request(Request::Close {
                handle: handle.0.clone(),
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to read a range of data from an opened file corresponding to the specified handle.
    pub async fn read(&self, handle: &FileHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let response = self
            .request(Request::Read {
                handle: handle.0.clone(),
                offset,
                len,
            })
            .await?;
        match response {
            Response::Data(data) => Ok(data),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to write a range of data to an opened file corresponding to the specified handle.
    pub async fn write(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<()> {
        let response = self
            .request(Request::Write {
                handle: handle.0.clone(),
                offset,
                data: data.to_owned(),
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[inline]
    pub async fn lstat(&self, filename: impl AsRef<OsStr>) -> Result<FileAttr> {
        let response = self
            .request(Request::LStat {
                path: filename.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub async fn fstat(&self, handle: &FileHandle) -> Result<FileAttr> {
        let response = self
            .request(Request::FStat {
                handle: handle.0.clone(),
            })
            .await?;
        match response {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn setstat(&self, path: impl AsRef<OsStr>, attrs: FileAttr) -> Result<()> {
        let response = self
            .request(Request::SetStat {
                path: path.as_ref().to_owned(),
                attrs,
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn fsetstat(&self, handle: &FileHandle, attrs: FileAttr) -> Result<()> {
        let response = self
            .request(Request::FSetStat {
                handle: handle.0.clone(),
                attrs,
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a directory for reading.
    pub async fn opendir(&self, path: impl AsRef<OsStr>) -> Result<FileHandle> {
        let response = self
            .request(Request::Opendir {
                path: path.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to list files and directories contained in an opened directory.
    pub async fn readdir(&self, handle: &FileHandle) -> Result<Vec<DirEntry>> {
        let response = self
            .request(Request::Readdir {
                handle: handle.0.clone(),
            })
            .await?;
        match response {
            Response::Name(entries) => Ok(entries),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn remove(&self, filename: impl AsRef<OsStr>) -> Result<()> {
        let response = self
            .request(Request::Remove {
                filename: filename.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn mkdir(&self, path: impl AsRef<OsStr>, attrs: FileAttr) -> Result<()> {
        let response = self
            .request(Request::Mkdir {
                path: path.as_ref().to_owned(),
                attrs,
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn rmdir(&self, path: impl AsRef<OsStr>) -> Result<()> {
        let response = self
            .request(Request::Rmdir {
                path: path.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn realpath(&self, filename: impl AsRef<OsStr>) -> Result<OsString> {
        let response = self
            .request(Request::Realpath {
                path: filename.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub async fn stat(&self, filename: impl AsRef<OsStr>) -> Result<FileAttr> {
        let response = self
            .request(Request::Stat {
                path: filename.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn rename(
        &self,
        oldpath: impl AsRef<OsStr>,
        newpath: impl AsRef<OsStr>,
    ) -> Result<()> {
        let response = self
            .request(Request::Rename {
                oldpath: oldpath.as_ref().to_owned(),
                newpath: newpath.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn readlink(&self, path: impl AsRef<OsStr>) -> Result<OsString> {
        let response = self
            .request(Request::Readlink {
                path: path.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn symlink(
        &self,
        linkpath: impl AsRef<OsStr>,
        targetpath: impl AsRef<OsStr>,
    ) -> Result<()> {
        let response = self
            .request(Request::Symlink {
                linkpath: linkpath.as_ref().to_owned(),
                targetpath: targetpath.as_ref().to_owned(),
            })
            .await?;
        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn extended(&self, request: impl AsRef<OsStr>, data: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .request(Request::Extended {
                request: request.as_ref().to_owned(),
                data: data.to_owned(),
            })
            .await?;
        match response {
            Response::Extended(data) => Ok(data),
            Response::Status(st) if st.code != SSH_FX_OK => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }
}

// ==== session drivers ====

#[derive(Debug)]
struct Inner {
    extensions: Vec<(OsString, OsString)>,
    reverse_symlink_arguments: bool,
    incoming_requests: mpsc::UnboundedSender<(u32, Request)>,
    pending_requests: Mutex<PendingRequests>,
}

#[derive(Debug)]
struct PendingRequests {
    senders: HashMap<u32, oneshot::Sender<Response>>,
    next_request_id: u32,
}

#[derive(Debug)]
#[must_use]
pub struct SendRequest<W> {
    writer: W,
    inner: Arc<Inner>,
    incoming_requests: mpsc::UnboundedReceiver<(u32, Request)>,
}

impl<W> SendRequest<W>
where
    W: AsyncWrite + Unpin,
{
    pub async fn run(self) -> Result<()> {
        let mut me = self;

        while let Some((id, req)) = me.incoming_requests.recv().await {
            match req {
                Request::Open {
                    filename,
                    pflags,
                    attrs,
                } => {
                    me.send_open_request(id, &filename, pflags, &attrs).await?;
                }

                Request::Close { handle } => {
                    me.send_string_request(id, SSH_FXP_CLOSE, &handle).await?;
                }

                Request::Read {
                    handle,
                    offset,
                    len,
                } => {
                    me.send_read_request(id, &handle, offset, len).await?;
                }

                Request::Write {
                    handle,
                    offset,
                    data,
                } => {
                    me.send_write_request(id, &handle, offset, &data).await?;
                }

                Request::LStat { path } => {
                    me.send_string_request(id, SSH_FXP_LSTAT, &path).await?;
                }

                Request::FStat { handle } => {
                    me.send_string_request(id, SSH_FXP_FSTAT, &handle).await?;
                }

                Request::SetStat { path, attrs } => {
                    me.send_string_attrs_request(id, SSH_FXP_SETSTAT, &path, &attrs)
                        .await?;
                }

                Request::FSetStat { handle, attrs } => {
                    me.send_string_attrs_request(id, SSH_FXP_FSETSTAT, &handle, &attrs)
                        .await?;
                }

                Request::Opendir { path } => {
                    me.send_string_request(id, SSH_FXP_OPENDIR, &path).await?;
                }

                Request::Readdir { handle } => {
                    me.send_string_request(id, SSH_FXP_READDIR, &handle).await?;
                }

                Request::Remove { filename } => {
                    me.send_string_request(id, SSH_FXP_REMOVE, &filename)
                        .await?;
                }

                Request::Mkdir { path, attrs } => {
                    me.send_string_attrs_request(id, SSH_FXP_MKDIR, &path, &attrs)
                        .await?;
                }

                Request::Rmdir { path } => {
                    me.send_string_request(id, SSH_FXP_RMDIR, &path).await?;
                }

                Request::Realpath { path } => {
                    me.send_string_request(id, SSH_FXP_REALPATH, &path).await?;
                }

                Request::Stat { path } => {
                    me.send_string_request(id, SSH_FXP_STAT, &path).await?;
                }

                Request::Rename {
                    oldpath: oldname,
                    newpath: newname,
                } => {
                    me.send_string_2_request(id, SSH_FXP_RENAME, &oldname, &newname)
                        .await?;
                }

                Request::Readlink { path } => {
                    me.send_string_request(id, SSH_FXP_READLINK, &path).await?;
                }

                Request::Symlink {
                    ref linkpath,
                    ref targetpath,
                } if me.inner.reverse_symlink_arguments => {
                    // In OpenSSH's sftp-server implementation, the order of arguments to SSH_FXP_SYMLINK
                    // is inadvertently reversed and it is not fixed for compatibility reason.
                    me.send_string_2_request(id, SSH_FXP_SYMLINK, &targetpath, &linkpath)
                        .await?;
                }

                Request::Symlink {
                    linkpath,
                    targetpath,
                } => {
                    me.send_string_2_request(id, SSH_FXP_SYMLINK, &linkpath, &targetpath)
                        .await?;
                }

                Request::Extended { request, data } => {
                    me.send_extended_request(id, &request, &data).await?;
                }
            }

            me.writer.flush().await?;
        }

        Ok(())
    }

    async fn send_string_request(&mut self, id: u32, packet_type: u8, s: &OsStr) -> Result<()> {
        // type(u8) + id(u32) + s(string)
        let length = 1 + 4 + string_len(s.len());

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, packet_type).await?;
        write_u32(&mut self.writer, id).await?;

        write_string(&mut self.writer, s.as_bytes()).await?;

        Ok(())
    }

    async fn send_string_2_request(
        &mut self,
        id: u32,
        packet_type: u8,
        s1: &OsStr,
        s2: &OsStr,
    ) -> Result<()> {
        // type(u8) + id(u32) + s1(string) + s2(string)
        let length = 1 + 4 + string_len(s1.len()) + string_len(s2.len());

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, packet_type).await?;
        write_u32(&mut self.writer, id).await?;

        write_string(&mut self.writer, s1.as_bytes()).await?;
        write_string(&mut self.writer, s2.as_bytes()).await?;

        Ok(())
    }

    async fn send_string_attrs_request(
        &mut self,
        id: u32,
        packet_type: u8,
        s: &OsStr,
        attrs: &FileAttr,
    ) -> Result<()> {
        // type(u8) + id(u32) + s(string) + attrs
        let length = 1 + 4 + string_len(s.len()) + attrs_len(attrs);

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, packet_type).await?;
        write_u32(&mut self.writer, id).await?;

        write_string(&mut self.writer, s.as_bytes()).await?;
        write_attrs(&mut self.writer, attrs).await?;

        Ok(())
    }

    async fn send_open_request(
        &mut self,
        id: u32,
        filename: &OsStr,
        pflags: u32,
        attrs: &FileAttr,
    ) -> Result<()> {
        // type(u8) + id(u32) + filename(string) + pflags(u32) + attrs
        let length = 1 + 4 + string_len(filename.len()) + 4 + attrs_len(attrs);

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, SSH_FXP_OPEN).await?;
        write_u32(&mut self.writer, id).await?;
        write_string(&mut self.writer, filename.as_bytes()).await?;
        write_u32(&mut self.writer, pflags).await?;
        write_attrs(&mut self.writer, &attrs).await?;
        Ok(())
    }

    async fn send_read_request(
        &mut self,
        id: u32,
        handle: &OsStr,
        offset: u64,
        len: u32,
    ) -> Result<()> {
        // type(u8) + id(u32) + handle(string) + offset(u64) + len(u32)
        let length = 1 + 4 + string_len(handle.len()) + 8 + 4;

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, SSH_FXP_READ).await?;
        write_u32(&mut self.writer, id).await?;
        write_string(&mut self.writer, handle.as_bytes()).await?;
        write_u64(&mut self.writer, offset).await?;
        write_u32(&mut self.writer, len).await?;

        Ok(())
    }

    async fn send_write_request(
        &mut self,
        id: u32,
        handle: &OsStr,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        // type(u8) + id(u32) + handle(string) + offset(u64) + data(string)
        let length = 1 + 4 + string_len(handle.len()) + 8 + string_len(data.len());

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, SSH_FXP_WRITE).await?;
        write_u32(&mut self.writer, id).await?;
        write_string(&mut self.writer, handle.as_bytes()).await?;
        write_u64(&mut self.writer, offset).await?;
        write_string(&mut self.writer, data).await?;

        Ok(())
    }

    async fn send_extended_request(&mut self, id: u32, request: &OsStr, data: &[u8]) -> Result<()> {
        // type(u8) + id(u32) + reqeust(string) + data(opaque bytes)
        let length = 1 + 4 + string_len(request.len()) + data.len() as u32;

        write_u32(&mut self.writer, length).await?;
        write_u8(&mut self.writer, SSH_FXP_EXTENDED).await?;
        write_u32(&mut self.writer, id).await?;

        write_string(&mut self.writer, request.as_bytes()).await?;
        self.writer.write_all(data).await?;

        Ok(())
    }
}

#[derive(Debug)]
#[must_use]
pub struct ReceiveResponse<R> {
    reader: R,
    inner: Arc<Inner>,
}

impl<R> ReceiveResponse<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn run(self) -> Result<()> {
        let mut me = self;

        loop {
            let (id, resp) = me.receive_response().await?;

            let pending_requests = &mut *me.inner.pending_requests.lock().unwrap();
            if let Some(tx) = pending_requests.senders.remove(&id) {
                let _ = tx.send(resp);
            }
        }
    }

    async fn receive_response(&mut self) -> Result<(u32, Response)> {
        let length = read_u32(&mut self.reader).await?;
        let mut reader = AsyncReadExt::take(&mut self.reader, length as u64);

        let typ = read_u8(&mut reader).await?;
        let id = read_u32(&mut reader).await?;

        let response = match typ {
            SSH_FXP_STATUS => {
                let code = read_u32(&mut reader).await?;
                let message = read_string(&mut reader).await?;
                let language_tag = read_string(&mut reader).await?;
                Response::Status(RemoteStatus {
                    code,
                    message,
                    language_tag,
                })
            }

            SSH_FXP_HANDLE => {
                let handle = read_string(&mut reader).await?;
                Response::Handle(FileHandle(handle))
            }

            SSH_FXP_DATA => {
                let data = read_string(&mut reader).await?;
                Response::Data(data.into_vec())
            }

            SSH_FXP_ATTRS => {
                let attrs = read_file_attr(&mut reader).await?;
                Response::Attrs(attrs)
            }

            SSH_FXP_NAME => {
                let count = read_u32(&mut reader).await?;
                let mut entries = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let filename = read_string(&mut reader).await?;
                    let longname = read_string(&mut reader).await?;
                    let attrs = read_file_attr(&mut reader).await?;
                    entries.push(DirEntry {
                        filename,
                        longname,
                        attrs,
                    });
                }
                Response::Name(entries)
            }

            SSH_FXP_EXTENDED_REPLY => {
                let mut data = vec![];
                reader.read_to_end(&mut data).await?;
                Response::Extended(data)
            }

            typ => {
                let mut data = vec![];
                reader.read_to_end(&mut data).await?;
                Response::Unknown { typ, data }
            }
        };

        debug_assert_eq!(reader.limit(), 0);

        Ok((id, response))
    }
}

#[derive(Debug)]
enum Request {
    Open {
        filename: OsString,
        pflags: u32,
        attrs: FileAttr,
    },
    Close {
        handle: OsString,
    },
    Read {
        handle: OsString,
        offset: u64,
        len: u32,
    },
    Write {
        handle: OsString,
        offset: u64,
        data: Vec<u8>,
    },
    LStat {
        path: OsString,
    },
    FStat {
        handle: OsString,
    },
    SetStat {
        path: OsString,
        attrs: FileAttr,
    },
    FSetStat {
        handle: OsString,
        attrs: FileAttr,
    },
    Opendir {
        path: OsString,
    },
    Readdir {
        handle: OsString,
    },
    Remove {
        filename: OsString,
    },
    Mkdir {
        path: OsString,
        attrs: FileAttr,
    },
    Rmdir {
        path: OsString,
    },
    Realpath {
        path: OsString,
    },
    Stat {
        path: OsString,
    },
    Rename {
        oldpath: OsString,
        newpath: OsString,
    },
    Readlink {
        path: OsString,
    },
    Symlink {
        linkpath: OsString,
        targetpath: OsString,
    },

    Extended {
        request: OsString,
        data: Vec<u8>,
    },
}

/// The kind of response values received from the server.
#[derive(Debug)]
enum Response {
    /// The operation is failed.
    Status(RemoteStatus),

    /// An opened file handle.
    Handle(FileHandle),

    /// Received data.
    Data(Vec<u8>),

    /// Retrieved attribute values.
    Attrs(FileAttr),

    /// Directory entries.
    Name(Vec<DirEntry>),

    /// Reply from an vendor-specific extended request.
    Extended(Vec<u8>),

    /// The response type is unknown or currently not supported.
    Unknown { typ: u8, data: Vec<u8> },
}

#[derive(Debug)]
struct RemoteStatus {
    code: u32,
    message: OsString,
    language_tag: OsString,
}

/// Start a SFTP session on the provided transport I/O.
///
/// This is a shortcut to `InitSession::default().init(r, w)`.
pub async fn init<R, W>(r: R, w: W) -> Result<(Session, SendRequest<W>, ReceiveResponse<R>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    InitSession::default().init(r, w).await
}

#[derive(Debug)]
pub struct InitSession {
    reverse_symlink_arguments: bool,
    extensions: Vec<(OsString, OsString)>,
}

impl Default for InitSession {
    fn default() -> Self {
        Self {
            reverse_symlink_arguments: true,
            extensions: vec![],
        }
    }
}

impl InitSession {
    /// Reverse the order of arguments in symlink request.
    ///
    /// For historical reason, the SFTP server implementation provied by OpenSSH
    /// (`sftp-server`) requiers that the order of arguments in the `SSH_FXP_SYMLINK`
    /// requests be the opposite of what is defined in RFC draft.
    ///
    /// This flag is enabled by default, as most SFTP servers are expected to
    /// use OpenSSH's implementation.
    pub fn reverse_symlink_arguments(&mut self, enabled: bool) -> &mut Self {
        self.reverse_symlink_arguments = enabled;
        self
    }

    pub fn extension(&mut self, name: OsString, data: OsString) -> &mut Self {
        self.extensions.push((name, data));
        self
    }

    /// Start a SFTP session on the provided transport I/O.
    ///
    /// This function first exchanges some packets with the server and negotiates
    /// the settings of SFTP protocol to use.  When the initialization process is
    /// successed, it returns a handle to send subsequent SFTP requests from the
    /// client and objects to drive the underlying communication with the server.
    pub async fn init<R, W>(
        &self,
        r: R,
        w: W,
    ) -> Result<(Session, SendRequest<W>, ReceiveResponse<R>)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut r = r;
        let mut w = w;

        // send SSH_FXP_INIT packet.
        w.write_all(&5u32.to_be_bytes()).await?; // length = type(= 1byte) + version(= 4byte)
        w.write_all(&SSH_FXP_INIT.to_be_bytes()).await?;
        w.write_all(&SFTP_PROTOCOL_VERSION.to_be_bytes()).await?;
        for (name, data) in &self.extensions {
            write_string(&mut w, name.as_bytes()).await?;
            write_string(&mut w, data.as_bytes()).await?;
        }
        w.flush().await?;

        // receive SSH_FXP_VERSION packet.
        let mut extensions = vec![];
        {
            let length = read_u32(&mut r).await?;
            let mut r = AsyncReadExt::take(&mut r, length as u64);

            let typ = read_u8(&mut r).await?;
            if typ != SSH_FXP_VERSION {
                return Err(Error::Protocol {
                    msg: "incorrect message type during initialization".into(),
                });
            }

            let version = read_u32(&mut r).await?;
            if version < SFTP_PROTOCOL_VERSION {
                return Err(Error::Protocol {
                    msg: "server supports older SFTP protocol".into(),
                });
            }

            loop {
                match read_string(&mut r).await {
                    Ok(name) => {
                        let data = read_string(&mut r).await?;
                        extensions.push((name, data));
                    }
                    Err(Error::Transport(ref err))
                        if err.kind() == io::ErrorKind::UnexpectedEof =>
                    {
                        break
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        let (tx, rx) = mpsc::unbounded_channel();

        let inner = Arc::new(Inner {
            extensions,
            reverse_symlink_arguments: self.reverse_symlink_arguments,
            incoming_requests: tx,
            pending_requests: Mutex::new(PendingRequests {
                senders: HashMap::new(),
                next_request_id: 0,
            }),
        });

        let session = Session {
            inner: Arc::downgrade(&inner),
        };

        let send = SendRequest {
            writer: w,
            inner: Arc::clone(&inner),
            incoming_requests: rx,
        };

        let recv = ReceiveResponse { reader: r, inner };

        Ok((session, send, recv))
    }
}

// ==== misc ====

#[inline(always)]
fn string_len(n: usize) -> u32 {
    4 + n as u32
}

async fn write_u8<W>(mut w: W, val: u8) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&val.to_be_bytes()).await?;
    Ok(())
}

async fn write_u32<W>(mut w: W, val: u32) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&val.to_be_bytes()).await?;
    Ok(())
}

async fn write_u64<W>(mut w: W, val: u64) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&val.to_be_bytes()).await?;
    Ok(())
}

async fn write_string<W>(mut w: W, s: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&(s.len() as u32).to_be_bytes()).await?;
    w.write_all(s).await?;
    Ok(())
}

fn attrs_len(attrs: &FileAttr) -> u32 {
    let mut len = 4u32; // flags
    if attrs.size.is_some() {
        len += 8; // size(u64)
    }
    if attrs.uid_gid.is_some() {
        len += 8; // uid(u32) + gid(u32)
    }
    if attrs.permissions.is_some() {
        len += 4; // permissions(u32)
    }
    if attrs.ac_mod_time.is_some() {
        len += 8; // atime(u32) + mtime(u32)
    }
    if !attrs.extended.is_empty() {
        len += 4; // extended_count(u32)
        len += attrs
            .extended
            .iter()
            .map(|(k, v)| {
                // type_len(u32) + type(string) + data_len(4) + data(string)
                4 + k.len() as u32 + 4 + v.len() as u32
            })
            .sum::<u32>();
    }
    len
}

async fn write_attrs<W>(mut w: W, attrs: &FileAttr) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    #[inline(always)]
    fn flag(b: bool, flag: u32) -> u32 {
        if b {
            flag
        } else {
            0
        }
    }

    let flags = flag(attrs.size.is_some(), SSH_FILEXFER_ATTR_SIZE)
        | flag(attrs.uid_gid.is_some(), SSH_FILEXFER_ATTR_UIDGID)
        | flag(attrs.permissions.is_some(), SSH_FILEXFER_ATTR_PERMISSIONS)
        | flag(attrs.ac_mod_time.is_some(), SSH_FILEXFER_ATTR_ACMODTIME)
        | flag(!attrs.extended.is_empty(), SSH_FILEXFER_ATTR_EXTENDED);

    write_u32(&mut w, flags).await?;
    if let Some(size) = attrs.size {
        write_u64(&mut w, size).await?;
    }
    if let Some((uid, gid)) = attrs.uid_gid {
        write_u32(&mut w, uid).await?;
        write_u32(&mut w, gid).await?;
    }
    if let Some(perm) = attrs.permissions {
        write_u32(&mut w, perm).await?;
    }
    if let Some((atime, mtime)) = attrs.ac_mod_time {
        write_u32(&mut w, atime).await?;
        write_u32(&mut w, mtime).await?;
    }
    if !attrs.extended.is_empty() {
        write_u32(&mut w, attrs.extended.len() as u32).await?;
        for (typ, data) in &attrs.extended {
            write_string(&mut w, typ.as_bytes()).await?;
            write_string(&mut w, data.as_bytes()).await?;
        }
    }

    Ok(())
}

async fn read_u8<R>(mut r: R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf).await?;
    Ok(u8::from_be_bytes(buf))
}

async fn read_u32<R>(mut r: R) -> Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).await?;
    Ok(u32::from_be_bytes(buf))
}

async fn read_u64<R>(mut r: R) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf).await?;
    Ok(u64::from_be_bytes(buf))
}

async fn read_string<R>(mut r: R) -> Result<OsString>
where
    R: AsyncRead + Unpin,
{
    let len = read_u32(&mut r).await?;

    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf[..]).await?;
    let s = OsString::from_vec(buf);

    Ok(s)
}

async fn read_file_attr<R>(mut r: R) -> Result<FileAttr>
where
    R: AsyncRead + Unpin,
{
    let flags = read_u32(&mut r).await?;

    let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
        let size = read_u64(&mut r).await?;
        Some(size)
    } else {
        None
    };

    let uid_gid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = read_u32(&mut r).await?;
        let gid = read_u32(&mut r).await?;
        Some((uid, gid))
    } else {
        None
    };

    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        let perm = read_u32(&mut r).await?;
        Some(perm)
    } else {
        None
    };

    let ac_mod_time = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let atime = read_u32(&mut r).await?;
        let mtime = read_u32(&mut r).await?;
        Some((atime, mtime))
    } else {
        None
    };

    let mut extended = vec![];

    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = read_u32(&mut r).await?;
        for _ in 0..count {
            let ex_type = read_string(&mut r).await?;
            let ex_data = read_string(&mut r).await?;
            extended.push((ex_type, ex_data));
        }
    }

    Ok(FileAttr {
        size,
        uid_gid,
        permissions,
        ac_mod_time,
        extended,
    })
}
