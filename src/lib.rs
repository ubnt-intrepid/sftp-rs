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

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub fn stat(&self, filename: impl AsRef<OsStr>) -> Result<FileAttr> {
        let pending = self.send_request(Request::Stat {
            filename: filename.as_ref().to_owned(),
        })?;

        match pending.wait() {
            Response::Attrs(attrs) => Ok(attrs),
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
            filename: filename.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a file.
    pub fn open(&self, filename: impl AsRef<OsStr>, pflags: u32) -> Result<FileHandle> {
        let pending = self.send_request(Request::Open {
            filename: filename.as_ref().to_owned(),
            pflags,
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

    /// Request to open a directory for reading.
    pub fn opendir(&self, path: impl AsRef<OsStr>) -> Result<FileHandle> {
        let pending = self.send_request(Request::Opendir {
            dirname: path.as_ref().to_owned(),
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

    pub fn realpath(&self, filename: impl AsRef<OsStr>) -> Result<Result<OsString, RemoteError>> {
        let pending = self.send_request(Request::Realpath {
            filename: filename.as_ref().to_owned(),
        })?;
        match pending.wait() {
            Response::Name(mut entries) => Ok(Ok(entries.remove(0).filename)),
            Response::Status(st) => Ok(Err(RemoteError(st))),
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
            match &req {
                Request::Stat { filename: s }
                | Request::LStat { filename: s }
                | Request::Close { handle: s }
                | Request::Opendir { dirname: s }
                | Request::Readdir { handle: s }
                | Request::Realpath { filename: s } => {
                    let data_len = s.len() as u32 + 4;
                    self.send_request(id, req.packet_type(), data_len, |w| {
                        w.write_u32::<NetworkEndian>(s.len() as u32)?;
                        w.write_all(s.as_bytes())?;
                        Ok(())
                    })?
                }

                Request::Open { filename, pflags } => {
                    let data_len = 4 + filename.len() as u32 + 4 + 4; // filename_len(4byte) + filename(string) + pflags(u32) + attr_flags(u32);

                    self.send_request(id, SSH_FXP_OPEN, data_len, |w| {
                        w.write_u32::<NetworkEndian>(filename.len() as u32)?;
                        w.write_all(filename.as_bytes())?;
                        w.write_u32::<NetworkEndian>(*pflags)?;
                        // TODO: write `attrs` fields
                        w.write_u32::<NetworkEndian>(0u32)?;
                        Ok(())
                    })?;
                }

                Request::Read {
                    handle,
                    offset,
                    len,
                } => {
                    // handle_len(u32) + handle(string) + offset(u64) + len(u32)
                    let data_len = 4 + handle.len() as u32 + 8 + 4;

                    self.send_request(id, SSH_FXP_READ, data_len, |w| {
                        w.write_u32::<NetworkEndian>(handle.len() as u32)?;
                        w.write_all(handle.as_bytes())?;
                        w.write_u64::<NetworkEndian>(*offset)?;
                        w.write_u32::<NetworkEndian>(*len)?;
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

                    self.send_request(id, SSH_FXP_WRITE, data_len, |stream| {
                        stream.write_u32::<NetworkEndian>(handle.len() as u32)?;
                        stream.write_all(handle.as_bytes())?;
                        stream.write_u64::<NetworkEndian>(*offset)?;
                        stream.write_u32::<NetworkEndian>(data.len() as u32)?;
                        stream.write_all(data)?;
                        Ok(())
                    })?;
                }
            }
            self.writer.flush()?;
        }

        Ok(())
    }

    fn send_request<F>(&mut self, id: u32, packet_type: u8, data_len: u32, f: F) -> Result<()>
    where
        F: FnOnce(&mut W) -> Result<()>,
    {
        let length = 1 + 4 + data_len; // type(1 byte) + id(4 byte) + data_len

        self.writer.write_u32::<NetworkEndian>(length)?;
        self.writer.write_u8(packet_type)?;
        self.writer.write_u32::<NetworkEndian>(id)?;

        f(&mut self.writer)?;

        self.writer.flush()?;

        Ok(())
    }
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
                let message = read_packet_string(&mut reader)?;
                let language_tag = read_packet_string(&mut reader)?;
                Response::Status(RemoteStatus {
                    code,
                    message,
                    language_tag,
                })
            }

            SSH_FXP_HANDLE => {
                let handle = read_packet_string(&mut reader)?;
                Response::Handle(FileHandle(handle))
            }

            SSH_FXP_DATA => {
                let data = read_packet_string(&mut reader)?;
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
                    let filename = read_packet_string(&mut reader)?;
                    let longname = read_packet_string(&mut reader)?;
                    let attrs = read_file_attr(&mut reader)?;
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
                reader.read_to_end(&mut data)?;
                Response::Unknown { typ, data }
            }
        };

        debug_assert_eq!(reader.limit(), 0);

        Ok((id, response))
    }
}

#[derive(Debug)]
enum Request {
    Stat {
        filename: OsString,
    },
    LStat {
        filename: OsString,
    },
    Open {
        filename: OsString,
        pflags: u32,
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
    Opendir {
        dirname: OsString,
    },
    Readdir {
        handle: OsString,
    },
    Realpath {
        filename: OsString,
    },
}

impl Request {
    fn packet_type(&self) -> u8 {
        match self {
            Request::Stat { .. } => SSH_FXP_STAT,
            Request::LStat { .. } => SSH_FXP_LSTAT,
            Request::Open { .. } => SSH_FXP_OPEN,
            Request::Close { .. } => SSH_FXP_CLOSE,
            Request::Read { .. } => SSH_FXP_READ,
            Request::Write { .. } => SSH_FXP_WRITE,
            Request::Opendir { .. } => SSH_FXP_OPENDIR,
            Request::Readdir { .. } => SSH_FXP_READDIR,
            Request::Realpath { .. } => SSH_FXP_REALPATH,
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

/// Start a SFTP session on the provided transport I/O.
///
/// This function first exchanges some packets with the server and negotiates
/// the settings of SFTP protocol to use.  When the initialization process is
/// successed, it returns a handle to send subsequent SFTP requests from the
/// client and objects to drive the underlying communication with the server.
pub fn init<R, W>(mut r: R, mut w: W) -> Result<(Session, SendRequest<W>, ReceiveResponse<R>)>
where
    R: io::Read,
    W: io::Write,
{
    // send SSH_FXP_INIT packet.
    w.write_u32::<NetworkEndian>(5)?; // length = type(= 1byte) + version(= 4byte)
    w.write_u8(SSH_FXP_INIT)?;
    w.write_u32::<NetworkEndian>(SFTP_PROTOCOL_VERSION)?;
    // TODO: send extension data
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
            match read_packet_string(&mut r) {
                Ok(name) => {
                    let value = read_packet_string(&mut r)?;
                    extensions.push((name, value));
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
