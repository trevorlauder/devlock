use crate::agent::Agent;
use crate::path_safety;
use crate::sandbox::error::DevlockError;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

fn wait_for_port(port: u16) -> bool {
    let addr = format!("127.0.0.1:{port}");
    (0..20).any(|_| {
        if TcpStream::connect(&addr).is_ok() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(50));
            false
        }
    })
}

pub fn verify_policy(
    agent: &dyn Agent,
    tunnel_port: u16,
    api_port: u16,
    session_token: &str,
) -> Result<(), DevlockError> {
    let (tunnel_up, api_up) = std::thread::scope(|s| {
        let t = s.spawn(|| wait_for_port(tunnel_port));
        let a = s.spawn(|| wait_for_port(api_port));
        (t.join().unwrap_or(false), a.join().unwrap_or(false))
    });
    if !tunnel_up {
        return Err(DevlockError::Verification(format!(
            "tunnel proxy not reachable on port {tunnel_port}"
        )));
    }
    if !api_up {
        return Err(DevlockError::Verification(format!(
            "api proxy not reachable on port {api_port}"
        )));
    }

    if let Some(path) = agent.inaccessible_path() {
        let path = sanitize_inaccessible(&path)?;
        match fs::File::open(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Ok(_) => {
                return Err(DevlockError::Verification(format!(
                    "{} is unexpectedly readable",
                    path.display()
                )));
            }
            Err(e) => {
                return Err(DevlockError::Verification(format!(
                    "{} open error: {e}",
                    path.display()
                )));
            }
        }
        // Also confirm the credentials file cannot be truncated or rewritten.
        // Without this, a sandboxed agent sitting in a dir_create directory
        // could overwrite the host's real OAuth tokens.
        match fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
        {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Ok(_) => {
                return Err(DevlockError::Verification(format!(
                    "{} is unexpectedly writable",
                    path.display()
                )));
            }
            Err(e) => {
                return Err(DevlockError::Verification(format!(
                    "{} write open error: {e}",
                    path.display()
                )));
            }
        }
    }

    let blocked = "blocked-test.invalid";
    let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
    let result = (|| -> std::io::Result<bool> {
        let mut s = TcpStream::connect(&tunnel_addr)?;
        write!(
            s,
            "CONNECT {blocked}:443 HTTP/1.1\r\nHost: {blocked}:443\r\nProxy-Authorization: Bearer {session_token}\r\n\r\n"
        )?;
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf)?;
        Ok(std::str::from_utf8(&buf[..n]).unwrap_or("").contains("403"))
    })();

    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(DevlockError::Verification(format!(
            "disallowed domain {blocked} was not blocked"
        ))),
        Err(e) => Err(DevlockError::Verification(format!(
            "blocked domain check error: {e}"
        ))),
    }
}

fn sanitize_inaccessible(p: &Path) -> Result<PathBuf, DevlockError> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home"));
    let roots: Vec<&Path> = vec![
        home.as_path(),
        Path::new("/home"),
        Path::new("/root"),
        Path::new("/etc"),
        Path::new("/var"),
    ];
    path_safety::safe_canonical_under(p, &roots).map_err(|e| {
        DevlockError::Verification(format!(
            "inaccessible path {} failed sanitization: {e}",
            p.display()
        ))
    })
}
