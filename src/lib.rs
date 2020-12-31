//! A pure-Rust implementation of SFTP client independent to transport layer.

use crate::consts::*;
use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::{self, prelude::*},
    os::unix::prelude::*,
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
    Io(#[from] io::Error),

    #[error("protocol error")]
    Protocol { msg: Cow<'static, str> },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct FileHandle(OsString);

// described in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
#[derive(Debug)]
#[non_exhaustive]
pub struct FileAttr {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub extended: Vec<(OsString, OsString)>,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct DirEntry {
    pub filename: OsString,
    pub longname: OsString,
    pub attrs: FileAttr,
}

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

/// SFTP session.
#[derive(Debug)]
pub struct Session<I> {
    stream: I,
    extensions: Vec<(OsString, OsString)>,
    next_request_id: u32,
    pending_responses: HashMap<u32, Response>,
}

impl<I> Session<I>
where
    I: io::Read + io::Write,
{
    /// Start a SFTP session.
    pub fn init(mut stream: I) -> Result<Self> {
        // send SSH_FXP_INIT packet.
        stream.write_u32::<NetworkEndian>(5)?; // length = type(= 1byte) + version(= 4byte)
        stream.write_u8(SSH_FXP_INIT)?;
        stream.write_u32::<NetworkEndian>(SFTP_PROTOCOL_VERSION)?;
        // TODO: send extension data
        stream.flush()?;

        // receive SSH_FXP_VERSION packet.
        let mut extensions = vec![];
        {
            let length = stream.read_u32::<NetworkEndian>()?;
            let mut io = io::Read::take(&mut stream, length as u64);

            let typ = io.read_u8()?;
            if typ != SSH_FXP_VERSION {
                return Err(Error::Protocol {
                    msg: "incorrect message type during initialization".into(),
                });
            }

            let version = io.read_u32::<NetworkEndian>()?;
            if version < SFTP_PROTOCOL_VERSION {
                return Err(Error::Protocol {
                    msg: "server supports older SFTP protocol".into(),
                });
            }

            loop {
                match read_packet_string(&mut io) {
                    Ok(name) => {
                        let value = read_packet_string(&mut io)?;
                        extensions.push((name, value));
                    }
                    Err(Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(Self {
            stream,
            extensions,
            next_request_id: 0,
            pending_responses: HashMap::new(),
        })
    }

    /// Return a list of extensions.
    #[inline]
    pub fn extensions(&self) -> &[(OsString, OsString)] {
        &self.extensions
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub fn stat(&mut self, path: impl AsRef<OsStr>) -> Result<Result<FileAttr, RemoteError>> {
        self.stat_common(SSH_FXP_STAT, path.as_ref())
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[inline]
    pub fn lstat(&mut self, path: impl AsRef<OsStr>) -> Result<Result<FileAttr, RemoteError>> {
        self.stat_common(SSH_FXP_LSTAT, path.as_ref())
    }

    fn stat_common(&mut self, typ: u8, path: &OsStr) -> Result<Result<FileAttr, RemoteError>> {
        let path_len = path.len() as u32;

        let request_id = self.send_request(
            typ,
            4 + path_len, // len(u32) + path
            |stream| {
                stream.write_u32::<NetworkEndian>(path_len)?;
                stream.write_all(path.as_bytes())?;
                Ok(())
            },
        )?;

        match self.receive_response(request_id)? {
            Response::Attrs(attrs) => Ok(Ok(attrs)),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a file.
    pub fn open(
        &mut self,
        filename: impl AsRef<OsStr>,
        pflags: u32,
    ) -> Result<Result<FileHandle, RemoteError>> {
        let filename = filename.as_ref();
        let data_len = 4 + filename.len() as u32 + 4 + 4; // filename_len(4byte) + filename + pflags + attr_flags;

        let request_id = self.send_request(SSH_FXP_OPEN, data_len, |stream| {
            stream.write_u32::<NetworkEndian>(filename.len() as u32)?;
            stream.write_all(filename.as_bytes())?;
            stream.write_u32::<NetworkEndian>(pflags)?;

            // TODO: write `attrs` field
            stream.write_u32::<NetworkEndian>(0u32)?;

            Ok(())
        })?;

        match self.receive_response(request_id)? {
            Response::Handle(handle) => Ok(Ok(handle)),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to read a range of data from an opened file corresponding to the specified handle.
    pub fn read(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        len: u32,
    ) -> Result<Result<Vec<u8>, RemoteError>> {
        let FileHandle(ref handle) = handle;

        let request_id = self.send_request(
            SSH_FXP_READ,
            4 + handle.len() as u32 + 8 + 4, // len(u32) + handle + offset(u64) + len(u32)
            |stream| {
                stream.write_u32::<NetworkEndian>(handle.len() as u32)?;
                stream.write_all(handle.as_bytes())?;
                stream.write_u64::<NetworkEndian>(offset)?;
                stream.write_u32::<NetworkEndian>(len)?;
                Ok(())
            },
        )?;

        match self.receive_response(request_id)? {
            Response::Data(data) => Ok(Ok(data)),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to write a range of data to an opened file corresponding to the specified handle.
    pub fn write(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        data: &[u8],
    ) -> Result<Result<(), RemoteError>> {
        let FileHandle(ref handle) = handle;

        let request_id = self.send_request(
            SSH_FXP_WRITE,
            4 + handle.len() as u32 + 8 + 4 + data.len() as u32, // len(u32) + handle + offset(u64) + data_len(u32) + data
            |stream| {
                stream.write_u32::<NetworkEndian>(handle.len() as u32)?;
                stream.write_all(handle.as_bytes())?;
                stream.write_u64::<NetworkEndian>(offset)?;
                stream.write_u32::<NetworkEndian>(data.len() as u32)?;
                stream.write_all(data)?;
                Ok(())
            },
        )?;

        match self.receive_response(request_id)? {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(Ok(())),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to close a file corresponding to the specified handle.
    pub fn close(&mut self, handle: &FileHandle) -> Result<Result<(), RemoteError>> {
        let FileHandle(ref handle) = handle;

        let request_id = self.send_request(
            SSH_FXP_CLOSE,
            4 + handle.len() as u32, // len(u32) + handle
            |stream| {
                stream.write_u32::<NetworkEndian>(handle.len() as u32)?;
                stream.write_all(handle.as_bytes())?;
                Ok(())
            },
        )?;

        match self.receive_response(request_id)? {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(Ok(())),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a directory for reading.
    pub fn opendir(&mut self, path: impl AsRef<OsStr>) -> Result<Result<FileHandle, RemoteError>> {
        let path = path.as_ref();
        let path_len = path.len() as u32;

        let request_id = self.send_request(
            SSH_FXP_OPENDIR,
            4 + path_len, // len(u32) + path
            |stream| {
                stream.write_u32::<NetworkEndian>(path_len)?;
                stream.write_all(path.as_bytes())?;
                Ok(())
            },
        )?;

        match self.receive_response(request_id)? {
            Response::Handle(handle) => Ok(Ok(handle)),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a directory for reading.
    pub fn readdir(&mut self, handle: &FileHandle) -> Result<Result<Vec<DirEntry>, RemoteError>> {
        let FileHandle(handle) = handle;
        let handle_len = handle.len() as u32;

        let request_id = self.send_request(
            SSH_FXP_READDIR,
            4 + handle_len, // len(u32) + path
            |stream| {
                stream.write_u32::<NetworkEndian>(handle_len)?;
                stream.write_all(handle.as_bytes())?;
                Ok(())
            },
        )?;

        match self.receive_response(request_id)? {
            Response::Name(entries) => Ok(Ok(entries)),
            Response::Status(st) => Ok(Err(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    fn send_request<F>(&mut self, packet_type: u8, data_len: u32, f: F) -> Result<u32>
    where
        F: FnOnce(&mut I) -> Result<()>,
    {
        let request_id = self.next_request_id;
        let length = 1 + 4 + data_len; // type(1 byte) + id(4 byte) + data_len

        self.stream.write_u32::<NetworkEndian>(length)?;
        self.stream.write_u8(packet_type)?;
        self.stream.write_u32::<NetworkEndian>(request_id)?;
        f(&mut self.stream)?;
        self.stream.flush()?;

        self.next_request_id = self.next_request_id.wrapping_add(1);

        Ok(request_id)
    }

    fn receive_response(&mut self, request_id: u32) -> Result<Response> {
        if let Some(response) = self.pending_responses.remove(&request_id) {
            return Ok(response);
        }

        loop {
            let length = self.stream.read_u32::<NetworkEndian>()?;
            let mut stream = io::Read::take(&mut self.stream, length as u64);

            let typ = stream.read_u8()?;
            let response_id = stream.read_u32::<NetworkEndian>()?;

            let response = match typ {
                SSH_FXP_STATUS => {
                    let code = stream.read_u32::<NetworkEndian>()?;
                    let message = read_packet_string(&mut stream)?;
                    let language_tag = read_packet_string(&mut stream)?;
                    Response::Status(RemoteStatus {
                        code,
                        message,
                        language_tag,
                    })
                }

                SSH_FXP_HANDLE => {
                    let handle = read_packet_string(&mut stream)?;
                    Response::Handle(FileHandle(handle))
                }

                SSH_FXP_DATA => {
                    let data = read_packet_string(&mut stream)?;
                    Response::Data(data.into_vec())
                }

                SSH_FXP_ATTRS => {
                    let attrs = read_file_attr(&mut stream)?;
                    Response::Attrs(attrs)
                }

                SSH_FXP_NAME => {
                    let count = stream.read_u32::<NetworkEndian>()?;
                    let mut entries = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        let filename = read_packet_string(&mut stream)?;
                        let longname = read_packet_string(&mut stream)?;
                        let attrs = read_file_attr(&mut stream)?;
                        entries.push(DirEntry {
                            filename,
                            longname,
                            attrs,
                        });
                    }
                    Response::Name(entries)
                }

                typ => {
                    let mut data = vec![];
                    stream.read_to_end(&mut data)?;
                    Response::Unknown { typ, data }
                }
            };

            debug_assert_eq!(stream.limit(), 0);

            if response_id == request_id {
                return Ok(response);
            }

            self.pending_responses.insert(response_id, response);
        }
    }
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

    /// The response type is unknown or currently not supported.
    Unknown { typ: u8, data: Vec<u8> },
}

#[derive(Debug)]
struct RemoteStatus {
    code: u32,
    message: OsString,
    language_tag: OsString,
}

fn read_packet_string<R>(mut r: R) -> Result<OsString>
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

    let (uid, gid) = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = r.read_u32::<NetworkEndian>()?;
        let gid = r.read_u32::<NetworkEndian>()?;
        (Some(uid), Some(gid))
    } else {
        (None, None)
    };

    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        Some(r.read_u32::<NetworkEndian>()?)
    } else {
        None
    };

    let (atime, mtime) = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let atime = r.read_u32::<NetworkEndian>()?;
        let mtime = r.read_u32::<NetworkEndian>()?;
        (Some(atime), Some(mtime))
    } else {
        (None, None)
    };

    let mut extended = vec![];

    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = r.read_u32::<NetworkEndian>()?;
        for _ in 0..count {
            let ex_type = read_packet_string(&mut r)?;
            let ex_data = read_packet_string(&mut r)?;
            extended.push((ex_type, ex_data));
        }
    }

    Ok(FileAttr {
        size,
        uid,
        gid,
        permissions,
        atime,
        mtime,
        extended,
    })
}
