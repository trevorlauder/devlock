//! Bundled copy of `policy/` baked into the binary. Materialized to disk
//! at startup so the existing loader can read it; users never edit these
//! files directly, they override by dropping same-named files into
//! `~/.config/devlock/policy/`.

use std::io;
use std::path::Path;

use include_dir::{Dir, include_dir};

pub static BUNDLED: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/policy");

/// Write every embedded file under `dest`, preserving relative paths.
/// Parent directories are created as needed. Existing files are overwritten.
pub fn materialize_to(dest: &Path) -> io::Result<()> {
    write_dir(&BUNDLED, dest)
}

fn write_dir(dir: &Dir<'_>, dest: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(sub) => {
                let rel = sub.path().file_name().ok_or_else(|| {
                    io::Error::other(format!("bundled dir has no name: {}", sub.path().display()))
                })?;
                write_dir(sub, &dest.join(rel))?;
            }
            include_dir::DirEntry::File(f) => {
                let rel = f.path().file_name().ok_or_else(|| {
                    io::Error::other(format!("bundled file has no name: {}", f.path().display()))
                })?;
                std::fs::write(dest.join(rel), f.contents())?;
            }
        }
    }
    Ok(())
}
