use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use std::{convert::TryFrom, ffi::OsString, io, os::unix::prelude::*};
use zerocopy::AsBytes;

// Refs:
// * https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
// * https://tools.ietf.org/html/rfc4251
// * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sftp-server.c?rev=1.120&content-type=text/x-cvsweb-markup

const SFTP_PROTOCOL_VERSION: u32 = 3;

const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;

pub fn send_init_packet<W>(mut writer: W) -> io::Result<()>
where
    W: io::Write,
{
    let length: u32 = 1 + 4; // type + version

    writer.write_u32::<NetworkEndian>(length)?;
    writer.write_u8(SSH_FXP_INIT)?;
    writer.write_u32::<NetworkEndian>(SFTP_PROTOCOL_VERSION)?;
    writer.flush()?;

    Ok(())
}

#[derive(Debug)]
pub struct InitResponse {
    typ: u8,
    version: u32,
    extensions: Vec<(OsString, OsString)>,
}

pub fn receive_init_packet<R>(mut reader: R) -> io::Result<InitResponse>
where
    R: io::Read,
{
    let length = reader.read_u32::<NetworkEndian>()?;
    let mut reader = reader.take(length as u64);

    let typ = reader.read_u8()?;
    let version = reader.read_u32::<NetworkEndian>()?;

    let mut extensions = vec![];
    while let Some(name) = read_packet_string(&mut reader)? {
        let value = read_packet_string(&mut reader)?.unwrap();
        extensions.push((name, value));
    }

    Ok(InitResponse {
        typ,
        version,
        extensions,
    })
}

pub fn read_packet_string<R>(mut reader: R) -> io::Result<Option<OsString>>
where
    R: io::Read,
{
    let len = match reader.read_u32::<NetworkEndian>() {
        Ok(n) => n,
        Err(ref err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf[..])?;
    Ok(Some(OsString::from_vec(buf)))
}

pub fn send_packet<W, T>(mut writer: W, packet_type: u8, data: T) -> io::Result<()>
where
    W: io::Write,
    T: AsBytes,
{
    let data = data.as_bytes();
    let length = u32::try_from(1 + 4 + data.len()).expect("too large data");

    writer.write_u32::<NetworkEndian>(length)?;
    writer.write_u8(packet_type as u8)?;
    writer.write_all(data)?;
    writer.flush()?;

    Ok(())
}
