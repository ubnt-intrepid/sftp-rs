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
