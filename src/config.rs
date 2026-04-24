//! Flat view of the agent overlay used by the devlock runtime.

use crate::policy::agent::{AgentPolicy, TunnelConfig};
use anyhow::ensure;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Default)]
pub struct Config {
    pub tunnel: TunnelConfig,
    pub allowed_domains: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub read_exec_paths: Vec<String>,
    pub env: HashMap<String, String>,
}

impl Config {
    pub fn from_policy(agent: &AgentPolicy) -> Self {
        Self {
            tunnel: agent.tunnel.clone(),
            allowed_domains: agent.network_allowlist.clone(),
            read_only_paths: agent.paths.read_only.clone(),
            read_exec_paths: agent.paths.read_exec.clone(),
            env: agent
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        for domain in &self.allowed_domains {
            ensure!(!domain.trim().is_empty(), "allowed domain cannot be empty");
            ensure!(
                !domain.contains(' ') && !domain.contains('/'),
                "invalid allowed domain pattern: {domain}"
            );
            ensure!(
                !(domain.starts_with("*.") && domain.len() <= 2),
                "invalid wildcard allowed domain pattern: {domain}"
            );
        }
        ensure!(
            self.tunnel.max_connections > 0,
            "tunnel.max_connections must be greater than 0"
        );
        ensure!(
            self.tunnel.max_per_host > 0,
            "tunnel.max_per_host must be greater than 0"
        );
        ensure!(
            self.tunnel.idle_timeout_secs > 0,
            "tunnel.idle_timeout_secs must be greater than 0"
        );
        Ok(())
    }

    pub fn normalized_allowlist(&self, agent_allowlist: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        agent_allowlist
            .into_iter()
            .chain(self.allowed_domains.iter().cloned())
            .map(|d| normalize_domain(&d))
            .filter(|d| !d.is_empty() && seen.insert(d.clone()))
            .collect()
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_allowlist_dedupes_and_lowercases() {
        let cfg = Config {
            allowed_domains: vec!["API.GITHUB.COM.".into(), "example.com".into()],
            ..Default::default()
        };
        let list = cfg.normalized_allowlist(vec!["example.com".into()]);
        assert!(list.contains(&"api.github.com".to_string()));
        assert!(list.contains(&"example.com".to_string()));
        assert_eq!(list.iter().filter(|d| *d == "example.com").count(), 1);
    }

    #[test]
    fn validate_rejects_blank_and_invalid_domains() {
        for bad in ["", "   ", "foo bar", "a/b", "*."] {
            let cfg = Config {
                allowed_domains: vec![bad.into()],
                ..Default::default()
            };
            assert!(cfg.validate().is_err(), "{bad} should fail");
        }
    }
}
