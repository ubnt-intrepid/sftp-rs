use anyhow::{ensure, Context as _, Result};
use std::net::{IpAddr, SocketAddr, TcpStream};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut args = pico_args::Arguments::from_env();

    let host = args
        .opt_value_from_str(["-h", "--host"])?
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));
    let port = args.opt_value_from_str(["-p", "--port"])?.unwrap_or(22u16);
    let username = args.free_from_str()?.unwrap_or_else(whoami::username);

    let addr = SocketAddr::from((host, port));
    tracing::debug!(?addr);
    tracing::debug!(?username);

    let mut ssh2 = ssh2::Session::new().context("failed to create ssh2 session")?;

    let stream = TcpStream::connect(&addr).context("failed to establish TCP connection")?;
    ssh2.set_tcp_stream(stream);

    ssh2.handshake()
        .context("errored on performing SSH handshake")?;

    authenticate(&ssh2, &username).context("failed to authenticate SSH session")?;
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

    tracing::debug!("stat(\".\")");
    match sftp.stat(".")? {
        Ok(attrs) => {
            tracing::debug!("--> {:?}", attrs);
        }
        Err(err) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
    }

    tracing::debug!("opendir(\".\")");
    let handle = match sftp.opendir(".")? {
        Ok(handle) => {
            tracing::debug!("--> ok(handle = {:?})", handle);
            handle
        }
        Err(err) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
    };

    tracing::debug!("readdir(..)");
    match sftp.readdir(&handle)? {
        Ok(entries) => {
            tracing::debug!("--> ok(entries = {:#?})", entries);
        }
        Err(err) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
    }

    tracing::debug!("close()");
    match sftp.close(&handle)? {
        Ok(()) => {
            tracing::debug!("--> ok");
        }
        Err(err) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
    };

    Ok(())
}

fn authenticate(ssh2: &ssh2::Session, username: &str) -> Result<()> {
    let mut agent = ssh2.agent().context("failed to init SSH agent handle")?;
    agent.connect().context("failed to connect to SSH agent")?;

    agent
        .list_identities()
        .context("failed to fetch identities from SSH agent")?;
    let identities = agent
        .identities()
        .context("failed to get identities from SSH agent")?;
    ensure!(!identities.is_empty(), "public keys is empty");

    for identity in identities {
        if let Err(..) = agent.userauth(username, &identity) {
            continue;
        }
    }

    Ok(())
}
