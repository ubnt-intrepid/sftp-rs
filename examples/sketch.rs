use anyhow::{ensure, Context as _, Result};
use byteorder::{NetworkEndian, ReadBytesExt as _};
use std::{
    convert::TryFrom,
    env::var,
    ffi::OsString,
    io::{self, prelude::*},
    net::TcpStream,
    os::unix::prelude::*,
};
use zerocopy::{AsBytes, U32};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let tcp = TcpStream::connect("127.0.0.1:22").context("failed to establish TCP connection")?;

    let mut ssh2 = ssh2::Session::new().context("failed to create ssh2 session")?;
    ssh2.set_tcp_stream(tcp);

    ssh2.handshake()
        .context("errored on performing SSH handshake")?;

    authenticate(&ssh2).context("failed to authenticate SSH session")?;
    ensure!(ssh2.authenticated(), "SSH session is not authenticated");

    let mut channel = ssh2
        .channel_session()
        .context("failed to establish a session-based channel on SSH connection")?;

    channel
        .subsystem("sftp")
        .context("SFTP subsystem is not supported")?;
    tracing::debug!("start SFTP");

    // TODO: communicate SFTP

    send_init_packet(&mut channel, 6).context("failed to send SSH_FXP_INIT request packet")?;
    tracing::debug!("send SSH_FXP_INIT");

    let resp = receive_init_packet(&mut channel)
        .context("failed to receive SSH_FXP_VERSION response packet")?;
    tracing::debug!("--> {:?}", resp);

    Ok(())
}

fn authenticate(ssh2: &ssh2::Session) -> Result<()> {
    let mut agent = ssh2.agent().context("failed to init SSH agent handle")?;
    agent.connect().context("failed to connect to SSH agent")?;

    agent
        .list_identities()
        .context("failed to fetch identities from SSH agent")?;
    let identities = agent
        .identities()
        .context("failed to get identities from SSH agent")?;
    ensure!(!identities.is_empty(), "public keys is empty");

    let username = whoami::username();
    for identity in identities {
        if let Err(..) = agent.userauth(&username, &identity) {
            continue;
        }
    }

    Ok(())
}

// ====

const SFTP_PROTOCOL_VERSION: u32 = 6;

#[derive(AsBytes)]
#[allow(non_camel_case_types)]
#[repr(u8)]
enum PacketType {
    SSH_FXP_INIT = 1,
    SSH_FXP_VERSION = 2,
}

type RequestId = u32;

#[derive(AsBytes)]
#[repr(packed)]
struct InitPacket {
    length: U32<NetworkEndian>,
    typ: PacketType,
    version: U32<NetworkEndian>,
}

fn send_init_packet<W>(mut writer: W, version: u32) -> io::Result<()>
where
    W: io::Write,
{
    let packet = InitPacket {
        length: U32::new(1 + 4), // type + version
        typ: PacketType::SSH_FXP_INIT,
        version: U32::new(version),
    };
    writer.write_all(packet.as_bytes())?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug)]
struct InitResponse {
    typ: u8,
    version: u32,
    extensions: Vec<(OsString, OsString)>,
}

fn receive_init_packet<R>(mut reader: R) -> io::Result<InitResponse>
where
    R: io::Read,
{
    // at first,
    let length = reader.read_u32::<NetworkEndian>()?;

    // a
    let mut reader = reader.take(length as u64);

    let typ = reader.read_u8()?;
    let version = reader.read_u32::<NetworkEndian>()?;

    let mut extensions = vec![];
    loop {
        let name = match read_packet_string(&mut reader)? {
            Some(name) => name,
            None => break,
        };
        let value = read_packet_string(&mut reader)?.unwrap();
        extensions.push((name, value));
    }

    Ok(InitResponse {
        typ,
        version,
        extensions,
    })
}

fn read_packet_string<R>(mut reader: R) -> io::Result<Option<OsString>>
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

#[derive(AsBytes)]
#[repr(packed)]
struct PacketHeader {
    length: U32<NetworkEndian>,
    typ: PacketType,
    request_id: U32<NetworkEndian>,
}

fn send_packet<W, T>(
    mut writer: W,
    packet_type: PacketType,
    request_id: RequestId,
    data: T,
) -> io::Result<()>
where
    W: io::Write,
    T: AsBytes,
{
    let data = data.as_bytes();

    let length = u32::try_from(1 + 4 + data.len()).expect("too large data");

    let header = PacketHeader {
        length: U32::new(length),
        typ: packet_type,
        request_id: U32::new(request_id),
    };

    writer.write_all(header.as_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;

    Ok(())
}
