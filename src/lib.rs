//! A pure-Rust implementation of SFTP client independent to transport layer.

use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    io::{self, prelude::*},
    os::unix::prelude::*,
    path::Path,
};

// Refs:
// * https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
// * https://tools.ietf.org/html/rfc4251
// * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sftp-server.c?rev=1.120&content-type=text/x-cvsweb-markup

const SFTP_PROTOCOL_VERSION: u32 = 3;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-3
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;
const SSH_FXP_EXTENDED_REPLY: u8 = 201;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-7
const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_NO_SUCH_FILE: u32 = 2;
const SSH_FX_PERMISSION_DENIED: u32 = 3;
const SSH_FX_FAILURE: u32 = 4;
const SSH_FX_BAD_MESSAGE: u32 = 5;
const SSH_FX_NO_CONNECTION: u32 = 6;
const SSH_FX_CONNECTION_LOST: u32 = 7;
const SSH_FX_OP_UNSUPPORTED: u32 = 8;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("errored in underlying transport I/O")]
    Io(#[from] io::Error),

    #[error("protocol error")]
    Protocol { msg: Cow<'static, str> },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The type alias of identifier numbers assigned to each request.
pub type RequestId = u32;

/// SFTP session.
#[derive(Debug)]
pub struct Session<I> {
    stream: I,
    extensions: Vec<(OsString, OsString)>,
    next_request_id: u32,
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

            while let Some(name) = read_packet_string(&mut io)? {
                let value = read_packet_string(&mut io)? //
                    .ok_or_else(|| Error::Protocol {
                        msg: "missing extension value".into(),
                    })?;
                extensions.push((name, value));
            }
        }

        Ok(Self {
            stream,
            extensions,
            next_request_id: 0,
        })
    }

    /// Return a list of extensions.
    #[inline]
    pub fn extensions(&self) -> &[(OsString, OsString)] {
        &self.extensions
    }

    fn send_request<F>(&mut self, packet_type: u8, data_len: u32, f: F) -> Result<RequestId>
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

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub fn stat(&mut self, path: impl AsRef<Path>) -> Result<RequestId> {
        self.stat_common(SSH_FXP_STAT, path.as_ref().as_os_str())
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[inline]
    pub fn lstat(&mut self, path: impl AsRef<Path>) -> Result<RequestId> {
        self.stat_common(SSH_FXP_LSTAT, path.as_ref().as_os_str())
    }

    fn stat_common(&mut self, typ: u8, path: &OsStr) -> Result<RequestId> {
        let path_len = path.len() as u32;
        self.send_request(
            typ,
            4 + path_len, // len(u32) + path
            |stream| {
                stream.write_u32::<NetworkEndian>(path_len)?;
                stream.write_all(path.as_bytes())?;
                Ok(())
            },
        )
    }

    /// Retrieve a response packet from the peer.
    pub fn receive_response(&mut self) -> Result<(RequestId, Response)> {
        let length = self.stream.read_u32::<NetworkEndian>()?;
        let mut stream = io::Read::take(&mut self.stream, length as u64);

        let typ = stream.read_u8()?;
        let request_id = stream.read_u32::<NetworkEndian>()?;

        let response = match typ {
            SSH_FXP_STATUS => {
                let code = stream.read_u32::<NetworkEndian>()?;
                let message = read_packet_string(&mut stream)?.unwrap_or_else(OsString::new);
                let language_tag = read_packet_string(&mut stream)? //
                    .and_then(|msg| {
                        if msg.is_empty() {
                            None
                        } else {
                            Some(msg)
                        }
                    });

                Response::Status {
                    code,
                    message,
                    language_tag,
                }
            }

            SSH_FXP_ATTRS => {
                let flags = stream.read_u32::<NetworkEndian>()?;
                let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
                    Some(stream.read_u64::<NetworkEndian>()?)
                } else {
                    None
                };
                let (uid, gid) = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
                    let uid = stream.read_u32::<NetworkEndian>()?;
                    let gid = stream.read_u32::<NetworkEndian>()?;
                    (Some(uid), Some(gid))
                } else {
                    (None, None)
                };
                let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
                    Some(stream.read_u32::<NetworkEndian>()?)
                } else {
                    None
                };
                let (atime, mtime) = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
                    let atime = stream.read_u32::<NetworkEndian>()?;
                    let mtime = stream.read_u32::<NetworkEndian>()?;
                    (Some(atime), Some(mtime))
                } else {
                    (None, None)
                };

                // TODO: parse extended data
                let mut data = vec![];
                stream.read_to_end(&mut data)?;
                drop(data);

                Response::Attrs(FileAttr {
                    size,
                    uid,
                    gid,
                    permissions,
                    atime,
                    mtime,
                })
            }

            typ => {
                let mut data = vec![];
                stream.read_to_end(&mut data)?;
                Response::Unknown { typ, data }
            }
        };

        debug_assert_eq!(stream.limit(), 0);

        Ok((request_id, response))
    }
}

/// The kind of response values received from the server.
#[derive(Debug)]
#[non_exhaustive]
pub enum Response {
    /// The operation is failed.
    Status {
        code: u32,
        message: OsString,
        language_tag: Option<OsString>,
    },

    /// Retrieved attribute values.
    Attrs(FileAttr),

    /// The response type is unknown or currently not supported.
    Unknown { typ: u8, data: Vec<u8> },
}

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
}

fn read_packet_string<R>(mut reader: R) -> Result<Option<OsString>>
where
    R: io::Read,
{
    let len = match reader.read_u32::<NetworkEndian>() {
        Ok(n) => n,
        Err(ref err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf[..])?;
    let s = OsString::from_vec(buf);

    Ok(Some(s))
}
