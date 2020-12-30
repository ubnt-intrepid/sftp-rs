#![allow(dead_code)]

use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use std::{
    borrow::Cow,
    convert::TryFrom,
    ffi::OsString,
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("errored in underlying transport I/O")]
    Io(#[from] io::Error),

    #[error("protocol error")]
    Protocol { msg: Cow<'static, str> },

    #[error("from remote")]
    Remote {
        code: u32,
        message: OsString,
        language_tag: Option<OsString>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct SFTP<I> {
    stream: I,
    extensions: Vec<(OsString, OsString)>,
    next_request_id: u32,
}

impl<I> SFTP<I>
where
    I: io::Read + io::Write,
{
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

    pub fn extensions(&self) -> &[(OsString, OsString)] {
        &self.extensions
    }

    pub fn stat(&mut self, path: impl AsRef<Path>) -> Result<FileStat> {
        // send packet
        let path = path.as_ref().as_os_str();
        let path_len = path.len() as u32;

        let length = u32::try_from(1 + 4 + 4 + path.len()) // type(1 byte) + id(4 byte) + path_len(4 byte) + path
            .expect("path name is too large");

        let request_id = self.next_request_id;

        self.stream.write_u32::<NetworkEndian>(length)?;
        self.stream.write_u8(SSH_FXP_STAT)?;
        self.stream.write_u32::<NetworkEndian>(request_id)?;
        self.stream.write_u32::<NetworkEndian>(path_len)?;
        self.stream.write_all(path.as_bytes())?;
        self.stream.flush()?;

        self.next_request_id = self.next_request_id.wrapping_add(1);

        // receive packet
        let length = self.stream.read_u32::<NetworkEndian>()?;
        let mut stream = io::Read::take(&mut self.stream, length as u64);

        let packet_type = match stream.read_u8()? {
            typ @ SSH_FXP_ATTRS | typ @ SSH_FXP_STATUS => typ,
            typ => {
                return Err(Error::Protocol {
                    msg: format!("incorrect message type: {}", typ).into(),
                });
            }
        };

        if stream.read_u32::<NetworkEndian>()? != request_id {
            return Err(Error::Protocol {
                msg: "incorrect request id".into(),
            });
        }

        match packet_type {
            SSH_FXP_ATTRS => {
                let flags = stream.read_u32::<NetworkEndian>()?;
                let size = stream.read_u64::<NetworkEndian>()?;
                let uid = stream.read_u32::<NetworkEndian>()?;
                let gid = stream.read_u32::<NetworkEndian>()?;
                let permissions = stream.read_u32::<NetworkEndian>()?;
                let atime = stream.read_u32::<NetworkEndian>()?;
                let mtime = stream.read_u32::<NetworkEndian>()?;

                let mut buf = vec![];
                stream.read_to_end(&mut buf)?;

                Ok(FileStat {
                    flags,
                    size,
                    uid,
                    gid,
                    permissions,
                    atime,
                    mtime,
                    data: buf,
                })
            }

            SSH_FXP_STATUS => {
                let code = stream.read_u32::<NetworkEndian>()?;
                let message = read_packet_string(&mut stream)?.unwrap_or_else(OsString::new);
                let language_tag = read_packet_string(&mut stream)?.and_then(|msg| {
                    if msg.is_empty() {
                        None
                    } else {
                        Some(msg)
                    }
                });
                Err(Error::Remote {
                    code,
                    message,
                    language_tag,
                })
            }

            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct FileStat {
    flags: u32,
    size: u64,
    uid: u32,
    gid: u32,
    permissions: u32,
    atime: u32,
    mtime: u32,
    data: Vec<u8>,
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
