use anyhow::{Context as _, Result};
use std::{
    net::{IpAddr, SocketAddr},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

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

    let (mut child, r, w) = establish_connection(&addr, &username)?;

    tracing::debug!("start SFTP");

    let (sftp, send, recv) = sftp::init(r, w, vec![]).context("failed to init SFTP session")?;
    std::thread::spawn(move || tracing::debug_span!("send_request").in_scope(|| send.run()));
    std::thread::spawn(move || tracing::debug_span!("recv_response").in_scope(|| recv.run()));

    tracing::debug!(r#"stat(".")"#);
    match sftp.stat(".") {
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
    match sftp.realpath(".") {
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
    match sftp.stat("./foo.txt") {
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
    let dir = match sftp.opendir(".") {
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
    match sftp.readdir(&dir) {
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
    match sftp.close(&dir) {
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

    match sftp.extended("statvfs@openssh.com", &[0, 0, 0, 1, b'.'] /* = "." */) {
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

    child.kill().context("failed to send KILL")?;
    child.wait()?;

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
