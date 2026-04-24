use crate::agent::Agent;
use crate::yaml_agent::YamlAgent;
use clap::Parser;
use std::path::Path;

#[derive(Parser)]
#[command(name = "devlock", about = "Run agents in a sandboxed environment")]
pub struct Args {
    /// Agent to run. Resolved against policy/agents/<name>.yaml.
    #[arg(long = "agent")]
    pub agent_name: String,

    /// Profile to apply. Resolved against policy/profiles/<name>.yaml.
    #[arg(long = "profile", default_value = "default")]
    pub profile: String,

    /// Print the resolved devlock configuration and exit without running.
    #[arg(long)]
    pub inspect: bool,

    /// Open an interactive shell (zsh or bash) using the agent's devlock settings.
    #[arg(long)]
    pub shell: bool,

    /// Arguments passed through to the agent
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub passthrough: Vec<String>,
}

pub fn parse_args() -> Args {
    Args::parse()
}

pub fn make_agent(name: &str, home: &Path) -> anyhow::Result<Box<dyn Agent>> {
    Ok(Box::new(YamlAgent::new(name, home)?))
}

/// Build the YamlAgent and keep the concrete type so callers that
/// care about the raw AgentPolicy can reach into it.
pub fn make_yaml_agent(name: &str, home: &Path) -> anyhow::Result<YamlAgent> {
    YamlAgent::new(name, home)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_with_passthrough() {
        let args = Args::try_parse_from(["devlock", "--agent", "claude", "--inspect", "--", "foo"])
            .expect("args should parse");
        assert_eq!(args.agent_name, "claude");
        assert!(args.inspect);
        assert_eq!(args.passthrough, vec!["foo".to_string()]);
    }
}
