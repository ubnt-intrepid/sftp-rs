use anyhow::{ensure, Context as _, Result};
use std::net::TcpStream;

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

    let mut sftp = sftp::Session::init(channel).context("failed to init SFTP")?;
    tracing::debug!("extensions: {:?}", sftp.extensions());

    let _id = sftp.send_stat(".")?;
    tracing::debug!("stat(\".\")");
    match sftp.receive_response()? {
        (_id, sftp::Response::Attrs(attr)) => {
            tracing::debug!("--> {:?}", attr);
        }
        (_id, resp) => {
            tracing::error!("invalid response type: {:?}", resp);
            return Ok(());
        }
    }

    let _id = sftp.send_open(
        "test.txt",
        sftp::consts::SSH_FXF_WRITE | sftp::consts::SSH_FXF_TRUNC,
    )?;
    tracing::debug!("open(\"test.txt\")");
    let handle = match sftp.receive_response()? {
        (_id, sftp::Response::Handle(handle)) => {
            tracing::debug!("--> ok(handle = {:?})", handle);
            handle
        }
        (_id, sftp::Response::Status { code, message, .. }) => {
            tracing::debug!("--> error(code = {}, message = {:?})", code, message);
            return Ok(());
        }

        (_id, resp) => {
            tracing::error!("invalid response type: {:?}", resp);
            return Ok(());
        }
    };

    let _id = sftp.send_write(&handle, 0, b"Hello, from SFTP!\n")?;
    tracing::debug!("write(..)");
    match sftp.receive_response()? {
        (
            _id,
            sftp::Response::Status {
                code: sftp::consts::SSH_FX_OK,
                ..
            },
        ) => {
            tracing::debug!("--> ok");
        }

        (_id, sftp::Response::Status { code, message, .. }) => {
            tracing::debug!("--> error(code = {}, message = {:?})", code, message);
            return Ok(());
        }

        (_id, resp) => {
            tracing::error!("invalid response type: {:?}", resp);
            return Ok(());
        }
    }

    let _id = sftp.send_close(&handle)?;
    tracing::debug!("close()");
    match sftp.receive_response()? {
        (
            _id,
            sftp::Response::Status {
                code: sftp::consts::SSH_FX_OK,
                ..
            },
        ) => {
            tracing::debug!("--> ok");
        }

        (_id, sftp::Response::Status { code, message, .. }) => {
            tracing::debug!("--> error(code = {}, message = {:?})", code, message);
        }

        (_id, resp) => {
            tracing::error!("invalid response type: {:?}", resp);
            return Ok(());
        }
    };

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
