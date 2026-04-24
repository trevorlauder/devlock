//! Loads `policy/seccomp.yaml`. Default action is hardcoded, not in YAML.

use std::io;

use serde::Deserialize;

const POLICY_YAML: &str = include_str!("seccomp.yaml");

#[derive(Debug)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub supervisor: SupervisorPolicy,
}

#[derive(Debug, Default)]
pub struct SupervisorPolicy {
    /// Mask of clone3 flag bits the supervisor permits. Any bit set
    /// in the syscall's flags argument that falls outside this mask
    /// causes the call to be rejected.
    pub clone3_allowed_flags: u64,
}

#[derive(Debug)]
pub struct Rule {
    pub syscall: String,
    pub action: Action,
    pub when: Vec<Cond>,
    pub handler: Option<Handler>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    OpenRequest,
    StatRequest,
    StructuralWrite,
    PathWrite,
    FdWrite,
    DirfdWrite,
    ExecRequest,
    BindRequest,
    ConnectRequest,
    Clone3Request,
    SignalRequest,
}

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Allow,
    Notify,
    Deny { errno: u32 },
}

#[derive(Debug)]
pub struct Cond {
    pub arg: u32,
    pub op: Op,
    pub value: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    MaskedEq(u64),
}

pub fn load() -> io::Result<Policy> {
    let raw: RawPolicy = serde_norway::from_str(POLICY_YAML)
        .map_err(|e| io::Error::other(format!("policy/seccomp.yaml: {e}")))?;
    RawPolicy::resolve(raw)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    supervisor: RawSupervisor,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSupervisor {
    #[serde(default)]
    clone3_allowed_flags: Option<StringOrInt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    syscall: String,
    action: String,
    #[serde(default)]
    errno: Option<StringOrInt>,
    #[serde(default)]
    when: Vec<RawCond>,
    #[serde(default)]
    handler: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCond {
    arg: u32,
    op: String,
    #[serde(default)]
    mask: Option<StringOrInt>,
    value: StringOrInt,
}

#[derive(Debug)]
enum StringOrInt {
    String(String),
    Int(u64),
}

impl<'de> Deserialize<'de> for StringOrInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = StringOrInt;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string symbol or an unsigned integer")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StringOrInt::String(v.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StringOrInt::String(v))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StringOrInt::Int(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StringOrInt::Int(v as u64))
            }
        }
        deserializer.deserialize_any(V)
    }
}

impl StringOrInt {
    fn resolve(&self) -> io::Result<u64> {
        match self {
            StringOrInt::Int(n) => Ok(*n),
            StringOrInt::String(s) => resolve_symbol(s),
        }
    }
}

impl RawPolicy {
    fn resolve(raw: Self) -> io::Result<Policy> {
        let mut rules = Vec::with_capacity(raw.rules.len());

        for r in raw.rules {
            let action = match r.action.as_str() {
                "allow" => Action::Allow,
                "notify" => Action::Notify,
                "deny" => {
                    let errno = r
                        .errno
                        .as_ref()
                        .ok_or_else(|| {
                            io::Error::other(format!(
                                "deny rule for {} must specify `errno`",
                                r.syscall
                            ))
                        })?
                        .resolve()? as u32;
                    Action::Deny { errno }
                }
                other => {
                    return Err(io::Error::other(format!(
                        "unknown action `{other}` on syscall {}",
                        r.syscall
                    )));
                }
            };
            if r.errno.is_some() && !matches!(action, Action::Deny { .. }) {
                return Err(io::Error::other(format!(
                    "`errno` only applies to deny rules, not {}",
                    r.syscall
                )));
            }

            let mut when = Vec::with_capacity(r.when.len());
            for w in r.when {
                let op = match w.op.as_str() {
                    "eq" => Op::Eq,
                    "ne" => Op::Ne,
                    "lt" => Op::Lt,
                    "le" => Op::Le,
                    "gt" => Op::Gt,
                    "ge" => Op::Ge,
                    "masked_eq" => {
                        let mask = w
                            .mask
                            .as_ref()
                            .ok_or_else(|| {
                                io::Error::other(format!("masked_eq needs `mask` in {}", r.syscall))
                            })?
                            .resolve()?;
                        Op::MaskedEq(mask)
                    }
                    other => {
                        return Err(io::Error::other(format!(
                            "unknown compare op `{other}` in {}",
                            r.syscall
                        )));
                    }
                };
                when.push(Cond {
                    arg: w.arg,
                    op,
                    value: w.value.resolve()?,
                });
            }

            let handler = match (&action, r.handler.as_deref()) {
                (Action::Notify, Some(name)) => Some(parse_handler(name, &r.syscall)?),
                (Action::Notify, None) => {
                    return Err(io::Error::other(format!(
                        "notify rule for {} must name a handler",
                        r.syscall
                    )));
                }
                (_, Some(_)) => {
                    return Err(io::Error::other(format!(
                        "handler only applies to notify rules, not {}",
                        r.syscall
                    )));
                }
                (_, None) => None,
            };

            rules.push(Rule {
                syscall: r.syscall,
                action,
                when,
                handler,
            });
        }

        let supervisor = SupervisorPolicy {
            clone3_allowed_flags: raw
                .supervisor
                .clone3_allowed_flags
                .as_ref()
                .map(StringOrInt::resolve)
                .transpose()?
                .unwrap_or(0),
        };
        let out = Policy { rules, supervisor };
        validate_shape(&out)?;
        Ok(out)
    }
}

fn parse_handler(name: &str, syscall: &str) -> io::Result<Handler> {
    Ok(match name {
        "open_request" => Handler::OpenRequest,
        "stat_request" => Handler::StatRequest,
        "structural_write" => Handler::StructuralWrite,
        "path_write" => Handler::PathWrite,
        "fd_write" => Handler::FdWrite,
        "dirfd_write" => Handler::DirfdWrite,
        "exec_request" => Handler::ExecRequest,
        "bind_request" => Handler::BindRequest,
        "connect_request" => Handler::ConnectRequest,
        "clone3_request" => Handler::Clone3Request,
        "signal_request" => Handler::SignalRequest,
        other => {
            return Err(io::Error::other(format!(
                "unknown handler `{other}` on syscall {syscall}"
            )));
        }
    })
}

fn validate_shape(p: &Policy) -> io::Result<()> {
    // An unconditional allow rule for a syscall that also appears as
    // notify is contradictory, and vice versa. Catch at load time.
    use std::collections::BTreeMap;
    let mut seen: BTreeMap<&str, &Action> = BTreeMap::new();
    for r in &p.rules {
        if r.when.is_empty()
            && let Some(existing) = seen.insert(r.syscall.as_str(), &r.action)
        {
            let compatible = matches!(
                (existing, &r.action),
                (Action::Allow, Action::Allow)
                    | (Action::Notify, Action::Notify)
                    | (Action::Deny { .. }, Action::Deny { .. })
            );
            if !compatible {
                return Err(io::Error::other(format!(
                    "conflicting unconditional rules for syscall {}",
                    r.syscall
                )));
            }
        }
    }
    Ok(())
}

/// Resolve a symbol name to its numeric value. The table is hand built
/// from libc so typos in the YAML fail at load with a readable error.
fn resolve_symbol(name: &str) -> io::Result<u64> {
    // Parse hex or decimal literal strings to support mixing numeric
    // and symbolic values without two YAML fields.
    if let Some(n) = parse_numeric_literal(name) {
        return Ok(n);
    }

    let value = match name {
        // Address families.
        "AF_UNSPEC" => libc::AF_UNSPEC as u64,
        "AF_UNIX" => libc::AF_UNIX as u64,
        "AF_INET" => libc::AF_INET as u64,
        "AF_INET6" => libc::AF_INET6 as u64,
        "AF_NETLINK" => libc::AF_NETLINK as u64,
        "AF_PACKET" => libc::AF_PACKET as u64,

        // Socket types.
        "SOCK_STREAM" => libc::SOCK_STREAM as u64,
        "SOCK_DGRAM" => libc::SOCK_DGRAM as u64,
        "SOCK_RAW" => libc::SOCK_RAW as u64,

        // Socket type mask excluding SOCK_NONBLOCK and SOCK_CLOEXEC.
        "SOCK_TYPE_MASK" => 0xf,

        // clone namespace flags.
        "CLONE_NEWUSER" => libc::CLONE_NEWUSER as u64,
        "CLONE_NEWNS" => libc::CLONE_NEWNS as u64,
        "CLONE_NEWPID" => libc::CLONE_NEWPID as u64,
        "CLONE_NEWNET" => libc::CLONE_NEWNET as u64,
        "CLONE_NEWUTS" => libc::CLONE_NEWUTS as u64,
        "CLONE_NEWIPC" => libc::CLONE_NEWIPC as u64,
        "CLONE_NEWCGROUP" => libc::CLONE_NEWCGROUP as u64,
        "CLONE_NS_MASK" => {
            (libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWCGROUP) as u64
        }
        // Minimum bits needed for pthread_create, fork, and vfork.
        // The low byte is the exit_signal. Anything outside this mask
        // is rejected so new kernel flags default to deny.
        "CLONE_SAFE_MASK" => {
            0xff | (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD
                | libc::CLONE_SYSVSEM
                | libc::CLONE_SETTLS
                | libc::CLONE_PARENT_SETTID
                | libc::CLONE_CHILD_CLEARTID
                | libc::CLONE_VFORK) as u64
        }

        // ioctl request codes.
        "TIOCSTI" => libc::TIOCSTI,
        "FIONREAD" => libc::FIONREAD,
        "FIONBIO" => libc::FIONBIO,
        "FIOCLEX" => libc::FIOCLEX,
        "FIONCLEX" => libc::FIONCLEX,
        "TCGETS" => libc::TCGETS,
        "TCSETS" => libc::TCSETS,
        "TCSETSW" => libc::TCSETSW,
        "TCSETSF" => libc::TCSETSF,
        "TIOCGWINSZ" => libc::TIOCGWINSZ,
        "TIOCSWINSZ" => libc::TIOCSWINSZ,
        "TIOCGPGRP" => libc::TIOCGPGRP,
        "TIOCSPGRP" => libc::TIOCSPGRP,
        "TIOCGSID" => libc::TIOCGSID,
        "TIOCGPTN" => libc::TIOCGPTN,
        "FICLONE" => libc::FICLONE,
        "FICLONERANGE" => libc::FICLONERANGE,
        // _IOWR(0x94, 54, sizeof(file_dedupe_range)=24). libc does not export it.
        "FIDEDUPERANGE" => 0xC018_9436u64,

        // prctl options.
        "PR_SET_NAME" => libc::PR_SET_NAME as u64,
        "PR_GET_NAME" => libc::PR_GET_NAME as u64,
        "PR_SET_NO_NEW_PRIVS" => libc::PR_SET_NO_NEW_PRIVS as u64,
        "PR_GET_DUMPABLE" => libc::PR_GET_DUMPABLE as u64,
        "PR_SET_DUMPABLE" => libc::PR_SET_DUMPABLE as u64,
        "PR_SET_PDEATHSIG" => libc::PR_SET_PDEATHSIG as u64,
        "PR_GET_PDEATHSIG" => libc::PR_GET_PDEATHSIG as u64,
        "PR_CAPBSET_READ" => libc::PR_CAPBSET_READ as u64,

        // Errno values. Kept in sync with the names we actually use.
        "EPERM" => libc::EPERM as u64,
        "EACCES" => libc::EACCES as u64,
        "EAFNOSUPPORT" => libc::EAFNOSUPPORT as u64,
        "ENOSYS" => libc::ENOSYS as u64,

        other => {
            return Err(io::Error::other(format!(
                "unknown symbol {other} in policy"
            )));
        }
    };
    Ok(value)
}

fn parse_numeric_literal(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
        s.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_symbol_in_the_shipped_policy_resolves() {
        let p = load().expect("policy/seccomp.yaml must load");
        assert!(!p.rules.is_empty());
    }

    #[test]
    fn numeric_literals_parse_as_decimal_and_hex() {
        assert_eq!(parse_numeric_literal("15"), Some(15));
        assert_eq!(parse_numeric_literal("0x0f"), Some(15));
        assert_eq!(parse_numeric_literal("0xFF"), Some(255));
        assert_eq!(parse_numeric_literal(""), None);
        assert_eq!(parse_numeric_literal("AF_INET"), None);
    }

    #[test]
    fn unknown_symbol_is_rejected() {
        let err = resolve_symbol("NOT_A_REAL_CONSTANT").unwrap_err();
        assert!(err.to_string().contains("unknown symbol"));
    }

    #[test]
    fn masked_eq_without_mask_is_rejected() {
        let yaml = r#"
rules:
  - syscall: ioctl
    action: allow
    when:
      - { arg: 1, op: masked_eq, value: TIOCSTI }
"#;
        let raw: RawPolicy = serde_norway::from_str(yaml).unwrap();
        let err = RawPolicy::resolve(raw).unwrap_err();
        assert!(err.to_string().contains("masked_eq"));
    }

    #[test]
    fn unknown_op_is_rejected() {
        let yaml = r#"
rules:
  - syscall: ioctl
    action: allow
    when:
      - { arg: 1, op: between, value: 0 }
"#;
        let raw: RawPolicy = serde_norway::from_str(yaml).unwrap();
        let err = RawPolicy::resolve(raw).unwrap_err();
        assert!(err.to_string().contains("unknown compare op"));
    }

    #[test]
    fn unknown_action_is_rejected() {
        let yaml = r#"
rules:
  - { syscall: ioctl, action: maybe }
"#;
        let raw: RawPolicy = serde_norway::from_str(yaml).unwrap();
        let err = RawPolicy::resolve(raw).unwrap_err();
        assert!(err.to_string().contains("unknown action"));
    }

    #[test]
    fn conflicting_unconditional_rules_rejected() {
        let yaml = r#"
rules:
  - { syscall: openat, action: allow }
  - { syscall: openat, action: notify, handler: open_request }
"#;
        let raw: RawPolicy = serde_norway::from_str(yaml).unwrap();
        let err = RawPolicy::resolve(raw).unwrap_err();
        assert!(err.to_string().contains("conflicting"));
    }

    #[test]
    fn notify_rule_without_handler_rejected() {
        let yaml = r#"
rules:
  - { syscall: openat, action: notify }
"#;
        let raw: RawPolicy = serde_norway::from_str(yaml).unwrap();
        let err = RawPolicy::resolve(raw).unwrap_err();
        assert!(err.to_string().contains("handler"));
    }
}
