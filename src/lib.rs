//! A pure-Rust implementation of SFTP client independent to transport layer.

use crate::consts::*;
use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::{self, prelude::*},
    os::unix::prelude::*,
    sync::{mpsc, Arc, Condvar, Mutex, Weak},
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
    inner: Weak<Mutex<Inner>>,
}

impl Session {
    fn send_request(&self, request: Request) -> Result<Arc<WaitResponse>> {
        let inner = self.inner.upgrade().ok_or(Error::SessionClosed)?;
        let inner = &mut *inner.lock().unwrap();

        let id = inner.next_request_id;

        inner.incoming_requests.send((id, request)).map_err(|_| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "session is not available")
        })?;

        let pending = Arc::new(WaitResponse {
            response: Mutex::new(None),
            condvar: Condvar::new(),
        });
        inner.pending_requests.insert(id, Arc::downgrade(&pending));

        inner.next_request_id = inner.next_request_id.wrapping_add(1);

        Ok(pending)
    }

    /// Request to open a file.
    pub fn open(
        &self,
        filename: impl AsRef<OsStr>,
        pflags: u32,
        attrs: FileAttr,
    ) -> Result<FileHandle> {
        let pending = self.send_request(Request::Open {
            filename: filename.as_ref().to_owned(),
            pflags,
            attrs,
        })?;
        match pending.wait() {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to close a file corresponding to the specified handle.
    pub fn close(&self, handle: &FileHandle) -> Result<()> {
        let pending = self.send_request(Request::Close {
            handle: handle.0.clone(),
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to read a range of data from an opened file corresponding to the specified handle.
    pub fn read(&self, handle: &FileHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let pending = self.send_request(Request::Read {
            handle: handle.0.clone(),
            offset,
            len,
        })?;
        match pending.wait() {
            Response::Data(data) => Ok(data),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to write a range of data to an opened file corresponding to the specified handle.
    pub fn write(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<()> {
        let pending = self.send_request(Request::Write {
            handle: handle.0.clone(),
            offset,
            data: data.to_owned(),
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[inline]
    pub fn lstat(&self, filename: impl AsRef<OsStr>) -> Result<FileAttr> {
        let pending = self.send_request(Request::LStat {
            path: filename.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub fn fstat(&self, handle: &FileHandle) -> Result<FileAttr> {
        let pending = self.send_request(Request::FStat {
            handle: handle.0.clone(),
        })?;

        match pending.wait() {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn setstat(&self, path: impl AsRef<OsStr>, attrs: FileAttr) -> Result<()> {
        let pending = self.send_request(Request::SetStat {
            path: path.as_ref().to_owned(),
            attrs,
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn fsetstat(&self, handle: &FileHandle, attrs: FileAttr) -> Result<()> {
        let pending = self.send_request(Request::FSetStat {
            handle: handle.0.clone(),
            attrs,
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a directory for reading.
    pub fn opendir(&self, path: impl AsRef<OsStr>) -> Result<FileHandle> {
        let pending = self.send_request(Request::Opendir {
            path: path.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to list files and directories contained in an opened directory.
    pub fn readdir(&self, handle: &FileHandle) -> Result<Vec<DirEntry>> {
        let pending = self.send_request(Request::Readdir {
            handle: handle.0.clone(),
        })?;
        match pending.wait() {
            Response::Name(entries) => Ok(entries),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn remove(&self, filename: impl AsRef<OsStr>) -> Result<()> {
        let pending = self.send_request(Request::Remove {
            filename: filename.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn mkdir(&self, path: impl AsRef<OsStr>, attrs: FileAttr) -> Result<()> {
        let pending = self.send_request(Request::Mkdir {
            path: path.as_ref().to_owned(),
            attrs,
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn rmdir(&self, path: impl AsRef<OsStr>) -> Result<()> {
        let pending = self.send_request(Request::Rmdir {
            path: path.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    ///
    pub fn realpath(&self, filename: impl AsRef<OsStr>) -> Result<OsString> {
        let pending = self.send_request(Request::Realpath {
            path: filename.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub fn stat(&self, filename: impl AsRef<OsStr>) -> Result<FileAttr> {
        let pending = self.send_request(Request::Stat {
            path: filename.as_ref().to_owned(),
        })?;

        match pending.wait() {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn rename(&self, oldpath: impl AsRef<OsStr>, newpath: impl AsRef<OsStr>) -> Result<()> {
        let pending = self.send_request(Request::Rename {
            oldpath: oldpath.as_ref().to_owned(),
            newpath: newpath.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn readlink(&self, path: impl AsRef<OsStr>) -> Result<OsString> {
        let pending = self.send_request(Request::Readlink {
            path: path.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn symlink(
        &self,
        linkpath: impl AsRef<OsStr>,
        targetpath: impl AsRef<OsStr>,
    ) -> Result<()> {
        let pending = self.send_request(Request::Symlink {
            linkpath: linkpath.as_ref().to_owned(),
            targetpath: targetpath.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub fn extended(&self, request: impl AsRef<OsStr>, data: &[u8]) -> Result<Vec<u8>> {
        let pending = self.send_request(Request::Extended {
            request: request.as_ref().to_owned(),
            data: data.to_owned(),
        })?;
        match pending.wait() {
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
    incoming_requests: mpsc::Sender<(u32, Request)>,
    pending_requests: HashMap<u32, Weak<WaitResponse>>,
    next_request_id: u32,
}

#[derive(Debug)]
struct WaitResponse {
    response: Mutex<Option<Response>>,
    condvar: Condvar,
}

impl WaitResponse {
    fn wait(&self) -> Response {
        let mut response = self.response.lock().unwrap();
        if let Some(resp) = response.take() {
            return resp;
        }

        let mut response = self
            .condvar
            .wait_while(response, |resp| resp.is_none())
            .unwrap();

        response.take().expect("response must be set")
    }

    fn send(&self, resp: Response) {
        let mut response = self.response.lock().unwrap();
        response.replace(resp);
        self.condvar.notify_one();
    }
}

#[derive(Debug)]
#[must_use]
pub struct SendRequest<W> {
    writer: W,
    inner: Arc<Mutex<Inner>>,
    incoming_requests: mpsc::Receiver<(u32, Request)>,
}

impl<W> SendRequest<W>
where
    W: io::Write,
{
    pub fn run(mut self) -> Result<()> {
        while let Ok((id, req)) = self.incoming_requests.recv() {
            self.send_request(id, req)?;
        }
        Ok(())
    }

    fn send_request(&mut self, id: u32, req: Request) -> Result<()> {
        match req {
            Request::Open {
                filename,
                pflags,
                attrs,
            } => {
                // filename_len(u32) + filename(string) + pflags(u32) + attrs;
                let data_len = 4 + filename.len() as u32 + 4 + attrs_packet_length(&attrs);

                self.send_request_common(id, SSH_FXP_OPEN, data_len, |w| {
                    write_string(&mut *w, filename.as_bytes())?;
                    w.write_u32::<NetworkEndian>(pflags)?;
                    write_attrs(w, &attrs)?;
                    Ok(())
                })?;
            }

            Request::Close { handle } => {
                self.send_str_request(id, SSH_FXP_CLOSE, &handle)?;
            }

            Request::Read {
                handle,
                offset,
                len,
            } => {
                // handle_len(u32) + handle(string) + offset(u64) + len(u32)
                let data_len = 4 + handle.len() as u32 + 8 + 4;

                self.send_request_common(id, SSH_FXP_READ, data_len, |w| {
                    write_string(&mut *w, handle.as_bytes())?;
                    w.write_u64::<NetworkEndian>(offset)?;
                    w.write_u32::<NetworkEndian>(len)?;
                    Ok(())
                })?;
            }

            Request::Write {
                handle,
                offset,
                data,
            } => {
                // handle_len(u32) + handle(string) + offset(u64) + data_len(u32) + data(string)
                let data_len = 4 + handle.len() as u32 + 8 + 4 + data.len() as u32;

                self.send_request_common(id, SSH_FXP_WRITE, data_len, |w| {
                    write_string(&mut *w, handle.as_bytes())?;
                    w.write_u64::<NetworkEndian>(offset)?;
                    write_string(w, &data)?;
                    Ok(())
                })?;
            }

            Request::LStat { path } => {
                self.send_str_request(id, SSH_FXP_LSTAT, &path)?;
            }

            Request::FStat { handle } => {
                self.send_str_request(id, SSH_FXP_FSTAT, &handle)?;
            }

            Request::SetStat { path, attrs } => {
                // path_len(u32) + path(string) + attrs
                let data_len = 4 + path.len() as u32 + attrs_packet_length(&attrs);

                self.send_request_common(id, SSH_FXP_SETSTAT, data_len, |w| {
                    write_string(&mut *w, path.as_bytes())?;
                    write_attrs(w, &attrs)?;
                    Ok(())
                })?;
            }

            Request::FSetStat { handle, attrs } => {
                // handle_len(u32) + path(string) + attrs
                let data_len = 4 + handle.len() as u32 + attrs_packet_length(&attrs);

                self.send_request_common(id, SSH_FXP_FSETSTAT, data_len, |w| {
                    write_string(&mut *w, handle.as_bytes())?;
                    write_attrs(w, &attrs)?;
                    Ok(())
                })?;
            }

            Request::Opendir { path } => {
                self.send_str_request(id, SSH_FXP_OPENDIR, &path)?;
            }

            Request::Readdir { handle } => {
                self.send_str_request(id, SSH_FXP_READDIR, &handle)?;
            }

            Request::Remove { filename } => {
                self.send_str_request(id, SSH_FXP_REMOVE, &filename)?;
            }

            Request::Mkdir { path, attrs } => {
                // path_len(u32) + path(string) + attrs
                let data_len = 4 + path.len() as u32 + attrs_packet_length(&attrs);

                self.send_request_common(id, SSH_FXP_MKDIR, data_len, |w| {
                    write_string(&mut *w, path.as_bytes())?;
                    write_attrs(w, &attrs)?;
                    Ok(())
                })?;
            }

            Request::Rmdir { path } => {
                self.send_str_request(id, SSH_FXP_RMDIR, &path)?;
            }

            Request::Realpath { path } => {
                self.send_str_request(id, SSH_FXP_REALPATH, &path)?;
            }

            Request::Stat { path } => {
                self.send_str_request(id, SSH_FXP_STAT, &path)?;
            }

            Request::Rename {
                oldpath: oldname,
                newpath: newname,
            } => {
                // oldname_len(u32) + oldname(string) + newname_len(u32) + newname(string)
                let data_len = 4 + oldname.len() as u32 + 4 + newname.len() as u32;

                self.send_request_common(id, SSH_FXP_RENAME, data_len, |w| {
                    write_string(&mut *w, oldname.as_bytes())?;
                    write_string(&mut *w, newname.as_bytes())?;
                    Ok(())
                })?;
            }

            Request::Readlink { path } => {
                self.send_str_request(id, SSH_FXP_READLINK, &path)?;
            }

            Request::Symlink {
                linkpath,
                targetpath,
            } => {
                // linkpath_len(u32) + linkpath(string) + targetpath_len(u32) + targetpath(string)
                let data_len = 4 + linkpath.len() as u32 + 4 + targetpath.len() as u32;

                self.send_request_common(id, SSH_FXP_SYMLINK, data_len, |w| {
                    write_string(&mut *w, linkpath.as_bytes())?;
                    write_string(&mut *w, targetpath.as_bytes())?;
                    Ok(())
                })?;
            }

            Request::Extended { request, data } => {
                // request_len(u32) + reqeust(string) + data(opaque)
                let data_len = 4 + request.len() as u32 + data.len() as u32;

                self.send_request_common(id, SSH_FXP_EXTENDED, data_len, |w| {
                    write_string(&mut *w, request.as_bytes())?;
                    w.write_all(&data)?;
                    Ok(())
                })?;
            }
        }
        self.writer.flush()?;
        Ok(())
    }

    fn send_str_request(&mut self, id: u32, packet_type: u8, s: &OsStr) -> Result<()> {
        let data_len = s.len() as u32 + 4;
        self.send_request_common(id, packet_type, data_len, |w| {
            w.write_u32::<NetworkEndian>(s.len() as u32)?;
            w.write_all(s.as_bytes())?;
            Ok(())
        })?;
        Ok(())
    }

    fn send_request_common<F>(
        &mut self,
        id: u32,
        packet_type: u8,
        data_len: u32,
        f: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut W) -> Result<()>,
    {
        let length = 1 + 4 + data_len; // type(1 byte) + id(4 byte) + data_len

        self.writer.write_u32::<NetworkEndian>(length)?;
        self.writer.write_u8(packet_type)?;
        self.writer.write_u32::<NetworkEndian>(id)?;

        f(&mut self.writer)?;

        Ok(())
    }
}

fn write_string<W>(mut w: W, s: &[u8]) -> Result<()>
where
    W: io::Write,
{
    w.write_u32::<NetworkEndian>(s.len() as u32)?;
    w.write_all(s)?;
    Ok(())
}

fn attrs_packet_length(attrs: &FileAttr) -> u32 {
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

fn write_attrs<W>(mut w: W, attrs: &FileAttr) -> Result<()>
where
    W: io::Write,
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

    w.write_u32::<NetworkEndian>(flags)?;
    if let Some(size) = attrs.size {
        w.write_u64::<NetworkEndian>(size)?;
    }
    if let Some((uid, gid)) = attrs.uid_gid {
        w.write_u32::<NetworkEndian>(uid)?;
        w.write_u32::<NetworkEndian>(gid)?;
    }
    if let Some(perm) = attrs.permissions {
        w.write_u32::<NetworkEndian>(perm)?;
    }
    if let Some((atime, mtime)) = attrs.ac_mod_time {
        w.write_u32::<NetworkEndian>(atime)?;
        w.write_u32::<NetworkEndian>(mtime)?;
    }
    if !attrs.extended.is_empty() {
        w.write_u32::<NetworkEndian>(attrs.extended.len() as u32)?;
        for (typ, data) in &attrs.extended {
            write_string(&mut w, typ.as_bytes())?;
            write_string(&mut w, data.as_bytes())?;
        }
    }

    Ok(())
}

#[derive(Debug)]
#[must_use]
pub struct ReceiveResponse<R> {
    reader: R,
    inner: Arc<Mutex<Inner>>,
}

impl<R> ReceiveResponse<R>
where
    R: io::Read,
{
    pub fn run(mut self) -> Result<()> {
        loop {
            let (id, resp) = self.receive_response()?;

            let inner = &mut *self.inner.lock().unwrap();
            if let Some(tx) = inner.pending_requests.remove(&id).and_then(|p| p.upgrade()) {
                tx.send(resp);
            }
        }
    }

    fn receive_response(&mut self) -> Result<(u32, Response)> {
        let length = self.reader.read_u32::<NetworkEndian>()?;
        let mut reader = io::Read::take(&mut self.reader, length as u64);

        let typ = reader.read_u8()?;
        let id = reader.read_u32::<NetworkEndian>()?;

        let response = match typ {
            SSH_FXP_STATUS => {
                let code = reader.read_u32::<NetworkEndian>()?;
                let message = read_string(&mut reader)?;
                let language_tag = read_string(&mut reader)?;
                Response::Status(RemoteStatus {
                    code,
                    message,
                    language_tag,
                })
            }

            SSH_FXP_HANDLE => {
                let handle = read_string(&mut reader)?;
                Response::Handle(FileHandle(handle))
            }

            SSH_FXP_DATA => {
                let data = read_string(&mut reader)?;
                Response::Data(data.into_vec())
            }

            SSH_FXP_ATTRS => {
                let attrs = read_file_attr(&mut reader)?;
                Response::Attrs(attrs)
            }

            SSH_FXP_NAME => {
                let count = reader.read_u32::<NetworkEndian>()?;
                let mut entries = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let filename = read_string(&mut reader)?;
                    let longname = read_string(&mut reader)?;
                    let attrs = read_file_attr(&mut reader)?;
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
                reader.read_to_end(&mut data)?;
                Response::Extended(data)
            }

            typ => {
                let mut data = vec![];
                reader.read_to_end(&mut data)?;
                Response::Unknown { typ, data }
            }
        };

        debug_assert_eq!(reader.limit(), 0);

        Ok((id, response))
    }
}

fn read_string<R>(mut r: R) -> Result<OsString>
where
    R: io::Read,
{
    let len = r.read_u32::<NetworkEndian>()?;

    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf[..])?;
    let s = OsString::from_vec(buf);

    Ok(s)
}

fn read_file_attr<R>(mut r: R) -> Result<FileAttr>
where
    R: io::Read,
{
    let flags = r.read_u32::<NetworkEndian>()?;

    let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
        Some(r.read_u64::<NetworkEndian>()?)
    } else {
        None
    };

    let uid_gid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = r.read_u32::<NetworkEndian>()?;
        let gid = r.read_u32::<NetworkEndian>()?;
        Some((uid, gid))
    } else {
        None
    };

    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        Some(r.read_u32::<NetworkEndian>()?)
    } else {
        None
    };

    let ac_mod_time = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let atime = r.read_u32::<NetworkEndian>()?;
        let mtime = r.read_u32::<NetworkEndian>()?;
        Some((atime, mtime))
    } else {
        None
    };

    let mut extended = vec![];

    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = r.read_u32::<NetworkEndian>()?;
        for _ in 0..count {
            let ex_type = read_string(&mut r)?;
            let ex_data = read_string(&mut r)?;
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
/// This function first exchanges some packets with the server and negotiates
/// the settings of SFTP protocol to use.  When the initialization process is
/// successed, it returns a handle to send subsequent SFTP requests from the
/// client and objects to drive the underlying communication with the server.
pub fn init<R, W>(
    mut r: R,
    mut w: W,
    extensions: Vec<(OsString, OsString)>,
) -> Result<(Session, SendRequest<W>, ReceiveResponse<R>)>
where
    R: io::Read,
    W: io::Write,
{
    // send SSH_FXP_INIT packet.
    w.write_u32::<NetworkEndian>(5)?; // length = type(= 1byte) + version(= 4byte)
    w.write_u8(SSH_FXP_INIT)?;
    w.write_u32::<NetworkEndian>(SFTP_PROTOCOL_VERSION)?;
    for (name, data) in extensions {
        write_string(&mut w, name.as_bytes())?;
        write_string(&mut w, data.as_bytes())?;
    }
    w.flush()?;

    // receive SSH_FXP_VERSION packet.
    let mut extensions = vec![];
    {
        let length = r.read_u32::<NetworkEndian>()?;
        let mut r = io::Read::take(&mut r, length as u64);

        let typ = r.read_u8()?;
        if typ != SSH_FXP_VERSION {
            return Err(Error::Protocol {
                msg: "incorrect message type during initialization".into(),
            });
        }

        let version = r.read_u32::<NetworkEndian>()?;
        if version < SFTP_PROTOCOL_VERSION {
            return Err(Error::Protocol {
                msg: "server supports older SFTP protocol".into(),
            });
        }

        loop {
            match read_string(&mut r) {
                Ok(name) => {
                    let data = read_string(&mut r)?;
                    extensions.push((name, data));
                }
                Err(Error::Transport(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    break
                }
                Err(err) => return Err(err),
            }
        }
    }

    let (tx, rx) = mpsc::channel();

    let inner = Arc::new(Mutex::new(Inner {
        extensions,
        incoming_requests: tx,
        pending_requests: HashMap::new(),
        next_request_id: 0,
    }));

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
