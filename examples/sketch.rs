use anyhow::{Context as _, Result};
use std::{
    io::{self, IoSlice, IoSliceMut},
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

    let conn = establish_connection(&addr, &username)?;

    tracing::debug!("start SFTP");

    // TODO: communicate SFTP
    let mut sftp = sftp::Session::init(conn).context("failed to init SFTP")?;
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

    tracing::debug!("realpath(\".\")");
    match sftp.realpath(".")? {
        Ok(path) => {
            tracing::debug!("--> ok(path = {:?})", path);
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

struct Connection {
    _child: Child,
    reader: ChildStdout,
    writer: ChildStdin,
}

impl io::Read for Connection {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.reader.read_vectored(bufs)
    }
}

impl io::Write for Connection {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.writer.write_vectored(bufs)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn establish_connection(addr: &SocketAddr, username: &str) -> Result<Connection> {
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

    Ok(Connection {
        _child: child,
        reader,
        writer,
    })
}
