use anyhow::{Context as _, Result};
use std::{
    net::{IpAddr, SocketAddr},
    process::Stdio,
};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tracing::Instrument as _;

#[tokio::main]
async fn main() -> Result<()> {
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

    let (mut child, r, w) = establish_connection(&addr, &username)?;

    tracing::debug!("start SFTP");

    let (sftp, send, recv) = sftp::init(r, w)
        .await
        .context("failed to init SFTP session")?;
    tokio::spawn(send.instrument(tracing::debug_span!("send_request")));
    tokio::spawn(recv.instrument(tracing::debug_span!("recv_response")));

    tracing::debug!(r#"stat(".")"#);
    match sftp.stat(".").await {
        Ok(attrs) => {
            tracing::debug!("--> {:?}", attrs);
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    }

    tracing::debug!(r#"realpath(".")"#);
    match sftp.realpath(".").await {
        Ok(path) => {
            tracing::debug!("--> ok(path = {:?})", path);
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    }

    tracing::debug!(r#"stat("./foo.txt")"#);
    match sftp.stat("./foo.txt").await {
        Ok(attrs) => {
            tracing::debug!("--> {:?}", attrs);
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
        }
        Err(err) => return Err(err.into()),
    }

    tracing::debug!(r#"opendir(".")"#);
    let dir = match sftp.opendir(".").await {
        Ok(dir) => {
            tracing::debug!("--> ok(handle = {:?})", dir);
            dir
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    tracing::debug!(r#"readdir({:?})"#, dir);
    match sftp.readdir(&dir).await {
        Ok(entries) => {
            tracing::debug!("--> ok(entries = {:?})", entries);
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    }

    tracing::debug!(r#"close({:?})"#, dir);
    match sftp.close(&dir).await {
        Ok(()) => {
            tracing::debug!("--> ok");
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    match sftp
        .extended("statvfs@openssh.com", &[0, 0, 0, 1, b'.'] /* = "." */)
        .await
    {
        Ok(data) => {
            tracing::debug!("--> ok(data = {:?})", data);
        }
        Err(sftp::Error::Remote(err)) => {
            tracing::debug!(
                "--> error(code = {}, message = {:?})",
                err.code(),
                err.message()
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    }

    child.kill().await.context("failed to send KILL")?;
    child.wait().await?;

    Ok(())
}

fn establish_connection(
    addr: &SocketAddr,
    username: &str,
) -> Result<(Child, ChildStdout, ChildStdin)> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-p")
        .arg(addr.port().to_string())
        .arg(format!("{}@{}", username, addr.ip().to_string()))
        .args(&["-s", "sftp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    tracing::debug!("spawn {:?}", cmd);
    let mut child = cmd.spawn().context("failed to spawn ssh")?;

    let reader = child.stdout.take().expect("missing stdout pipe");
    let writer = child.stdin.take().expect("missing stdin pipe");

    Ok((child, reader, writer))
}
