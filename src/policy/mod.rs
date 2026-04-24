//! Policy loaders. YAML lives under `policy/`.

pub mod agent;
mod bundled;
pub mod filesystem;
pub mod install;
pub mod seccomp;
mod yaml_merge;
