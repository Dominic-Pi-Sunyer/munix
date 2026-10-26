//! The agent's sandbox: Docker commands for an internal network, a relay to the model gateway, and the agent
//! container itself.
//!
//! Tested on Colima (Docker 29, arm64): `--network none` works with stdio, but a host Unix socket mounted into the
//! container does not, so the gateway is reached over TCP through a relay. On Colima the host is `192.168.5.2` and
//! bind mounts only work under `$HOME`; on Docker Desktop the host is `host.docker.internal`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The placeholder the agent gets as its API key. The gateway ignores it.
pub const PLACEHOLDER_KEY: &str = "munix-gateway";

/// Env names containing any of these are refused, so no credential is passed in by mistake.
const FORBIDDEN_ENV_PARTS: [&str; 4] = ["KEY", "TOKEN", "SECRET", "PASSWORD"];
/// Env names the sandbox sets itself.
const RESERVED_ENV: [&str; 1] = ["OPENAI_BASE_URL"];

/// A host path that is bind-mounted: absolute, and free of characters that would change the `-v` syntax.
fn check_mount_path(p: &Path, what: &'static str) -> Result<(), SandboxError> {
    let s = p
        .to_str()
        .ok_or(SandboxError::Invalid("paths must be UTF-8"))?;
    if !p.is_absolute() || s.contains([':', ',', '\0', '\n']) {
        return Err(SandboxError::Invalid(match what {
            "agent_dir" => "agent_dir must be an absolute path without ':' or ','",
            _ => "relay_script must be an absolute path without ':' or ','",
        }));
    }
    Ok(())
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_string()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Names the network and containers: `munix-<name>` and `munix-<name>-relay`. 1-40 of `[a-z0-9-]`.
    pub name: String,
    /// The agent's image, such as `python:3.12-slim`. The relay uses the same image.
    pub image: String,
    /// The agent's code on the host, mounted read-only at `/agent`. Must be absolute.
    pub agent_dir: PathBuf,
    /// The command run inside the container, such as `["python", "/agent/agent.py", ...]`.
    pub command: Vec<String>,
    /// Extra environment for the agent. Names are `[A-Z0-9_]`; names containing `KEY`, `TOKEN`, `SECRET` or
    /// `PASSWORD` are refused, so no credential is passed in by mistake.
    pub env: BTreeMap<String, String>,
    /// How the relay reaches the host: `192.168.5.2` on Colima, `host.docker.internal` on Docker Desktop.
    pub host_gateway: String,
    /// The gateway's port on the host loopback.
    pub gateway_port: u16,
    /// This crate's `relay/relay.py` on the host, mounted read-only into the relay container.
    pub relay_script: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("invalid sandbox spec: {0}")]
    Invalid(&'static str),
    #[error("docker failed: {0}")]
    Docker(String),
}

impl SandboxSpec {
    /// Checks every rule above.
    pub fn validate(&self) -> Result<(), SandboxError> {
        let bad = |why: &'static str| Err(SandboxError::Invalid(why));
        if self.name.is_empty()
            || self.name.len() > 40
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return bad("name must be 1-40 of [a-z0-9-]");
        }
        if self.image.is_empty()
            || self.image.starts_with('-')
            || !self
                .image
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/:@".contains(&b))
        {
            return bad("image is empty or has unexpected characters");
        }
        check_mount_path(&self.agent_dir, "agent_dir")?;
        check_mount_path(&self.relay_script, "relay_script")?;
        if self.command.is_empty() || self.command.iter().any(|c| c.contains('\0')) {
            return bad("command must be non-empty without NUL");
        }
        for (k, v) in &self.env {
            if k.is_empty()
                || k.starts_with(|c: char| c.is_ascii_digit())
                || !k
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                return bad("env names must be [A-Z0-9_] and not start with a digit");
            }
            if FORBIDDEN_ENV_PARTS.iter().any(|p| k.contains(p)) {
                return bad("env name looks like a credential");
            }
            if RESERVED_ENV.contains(&k.as_str()) {
                return bad("env name is set by the sandbox");
            }
            if v.contains('\0') || v.contains('\n') || v.contains('\r') {
                return bad("env values must be single-line without NUL");
            }
        }
        if self.host_gateway.is_empty()
            || !self
                .host_gateway
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return bad("host_gateway must be a host name or IPv4 address");
        }
        if self.gateway_port == 0 {
            return bad("gateway_port must be non-zero");
        }
        Ok(())
    }

    pub fn network(&self) -> String {
        format!("munix-{}", self.name)
    }

    pub fn relay(&self) -> String {
        format!("munix-{}-relay", self.name)
    }

    /// `docker network create --internal munix-<name>`, as argv after `docker`.
    pub fn network_create_args(&self) -> Vec<String> {
        strings(&["network", "create", "--internal", &self.network()])
    }

    /// Runs the relay detached on the default bridge (so it can reach the host), with
    /// `--add-host host.docker.internal:host-gateway`, read-only root, all capabilities dropped and
    /// `no-new-privileges`. It runs `python /relay/relay.py <port> <host_gateway> <port>`.
    pub fn relay_run_args(&self) -> Vec<String> {
        let port = self.gateway_port.to_string();
        strings(&[
            "run",
            "-d",
            "--name",
            &self.relay(),
            "--add-host",
            "host.docker.internal:host-gateway",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "-v",
            &format!("{}:/relay/relay.py:ro", self.relay_script.display()),
            &self.image,
            "python",
            "/relay/relay.py",
            &port,
            &self.host_gateway,
            &port,
        ])
    }

    /// `docker network connect munix-<name> munix-<name>-relay`.
    pub fn relay_connect_args(&self) -> Vec<String> {
        strings(&["network", "connect", &self.network(), &self.relay()])
    }

    /// Runs the agent with `-i --rm` on the internal network only, read-only root with a small `/tmp` tmpfs, all
    /// capabilities dropped, `no-new-privileges`, `--pids-limit 256`, `--memory 1g`, `-v <agent_dir>:/agent:ro`,
    /// `OPENAI_BASE_URL=http://munix-<name>-relay:<port>/v1`, `OPENAI_API_KEY=<PLACEHOLDER_KEY>` and `env`, then
    /// the image and command.
    pub fn agent_run_args(&self) -> Vec<String> {
        let mut args = strings(&[
            "run",
            "-i",
            "--rm",
            "--name",
            &self.network(),
            "--network",
            &self.network(),
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=64m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "-v",
            &format!("{}:/agent:ro", self.agent_dir.display()),
            "-e",
            &format!(
                "OPENAI_BASE_URL=http://{}:{}/v1",
                self.relay(),
                self.gateway_port
            ),
            "-e",
            &format!("OPENAI_API_KEY={PLACEHOLDER_KEY}"),
        ]);
        for (k, v) in &self.env {
            args.push("-e".to_string());
            args.push(format!("{k}={v}"));
        }
        args.push(self.image.clone());
        args.extend(self.command.iter().cloned());
        args
    }

    /// Removes the agent container, the relay and the network, ignoring ones that are already gone.
    pub fn cleanup_args(&self) -> Vec<Vec<String>> {
        vec![
            strings(&["rm", "-f", &self.network()]),
            strings(&["rm", "-f", &self.relay()]),
            strings(&["network", "rm", &self.network()]),
        ]
    }
}

/// A running sandbox. Its stdin and stdout are the agent's MCP channel.
pub struct Sandbox {
    pub spec: SandboxSpec,
    pub child: Child,
}

impl Sandbox {
    /// Validates the spec, cleans up leftovers with the same name, creates the network, starts and connects the
    /// relay, then spawns the agent with piped stdin and stdout (stderr inherited).
    pub fn launch(spec: SandboxSpec) -> Result<Sandbox, SandboxError> {
        spec.validate()?;
        // Leftovers from an earlier run with the same name. Failures here are not interesting.
        let _ = cleanup(&spec);

        let setup = || -> Result<Child, SandboxError> {
            docker_ok(&spec.network_create_args())?;
            docker_ok(&spec.relay_run_args())?;
            docker_ok(&spec.relay_connect_args())?;
            Command::new("docker")
                .args(spec.agent_run_args())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| SandboxError::Docker(format!("could not start docker: {e}")))
        };
        match setup() {
            Ok(child) => Ok(Sandbox { spec, child }),
            Err(e) => {
                let _ = cleanup(&spec);
                Err(e)
            }
        }
    }

    /// Kills the agent and removes everything `launch` created.
    pub fn kill(mut self) -> Result<(), SandboxError> {
        // Removing the container first stops the agent itself; then reap the local docker client process.
        let result = cleanup(&self.spec);
        let _ = self.child.kill();
        let _ = self.child.wait();
        result
    }
}

/// Runs `docker <args>` and returns its stderr text on failure.
fn docker_ok(args: &[String]) -> Result<(), SandboxError> {
    let out = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| SandboxError::Docker(format!("could not run docker: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(SandboxError::Docker(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

/// Runs every cleanup command. "Already gone" is fine; any other failure is reported after all have run.
fn cleanup(spec: &SandboxSpec) -> Result<(), SandboxError> {
    let mut first_error = None;
    for args in spec.cleanup_args() {
        if let Err(SandboxError::Docker(msg)) = docker_ok(&args) {
            let lower = msg.to_lowercase();
            let gone = lower.contains("no such") || lower.contains("not found");
            if !gone && first_error.is_none() {
                first_error = Some(SandboxError::Docker(msg));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SandboxSpec {
        SandboxSpec {
            name: "demo-1".to_string(),
            image: "python:3.12-slim".to_string(),
            agent_dir: PathBuf::from("/home/u/agent"),
            command: vec!["python".into(), "/agent/agent.py".into(), "--x".into()],
            env: BTreeMap::from([("MODEL".to_string(), "muse".to_string())]),
            host_gateway: "192.168.5.2".to_string(),
            gateway_port: 4040,
            relay_script: PathBuf::from("/home/u/munix/relay/relay.py"),
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn invalid(f: impl FnOnce(&mut SandboxSpec)) {
        let mut sp = spec();
        f(&mut sp);
        assert!(
            matches!(sp.validate(), Err(SandboxError::Invalid(_))),
            "{sp:?}"
        );
    }

    #[test]
    fn a_good_spec_validates() {
        assert!(spec().validate().is_ok());
    }

    #[test]
    fn names_are_checked() {
        invalid(|sp| sp.name = String::new());
        invalid(|sp| sp.name = "a".repeat(41));
        invalid(|sp| sp.name = "Upper".into());
        invalid(|sp| sp.name = "has space".into());
        invalid(|sp| sp.name = "a/b".into());
        invalid(|sp| sp.name = "under_score".into());
        let mut sp = spec();
        sp.name = "a".repeat(40);
        assert!(sp.validate().is_ok());
        sp.name = "0-9".into();
        assert!(sp.validate().is_ok());
    }

    #[test]
    fn image_command_and_paths_are_checked() {
        invalid(|sp| sp.image = String::new());
        invalid(|sp| sp.image = "--privileged".into());
        invalid(|sp| sp.image = "img name".into());
        invalid(|sp| sp.command = vec![]);
        invalid(|sp| sp.agent_dir = PathBuf::from("relative/dir"));
        invalid(|sp| sp.agent_dir = PathBuf::from("/a:b"));
        invalid(|sp| sp.agent_dir = PathBuf::from("/a,b"));
        invalid(|sp| sp.relay_script = PathBuf::from("relay.py"));
        invalid(|sp| sp.relay_script = PathBuf::from("/a:rw/relay.py"));
        invalid(|sp| sp.host_gateway = String::new());
        invalid(|sp| sp.host_gateway = "1.2.3.4 --x".into());
        invalid(|sp| sp.gateway_port = 0);
    }

    #[test]
    fn env_names_and_values_are_checked() {
        for bad in [
            "API_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "MY_SECRET",
            "DB_PASSWORD",
            "KEYRING",
            "lower",
            "HAS-DASH",
            "",
            "1ABC",
            "OPENAI_BASE_URL",
        ] {
            invalid(|sp| {
                sp.env.insert(bad.to_string(), "v".to_string());
            });
        }
        invalid(|sp| {
            sp.env.insert("OK".into(), "a\nb".into());
        });
        invalid(|sp| {
            sp.env.insert("OK".into(), "a\0b".into());
        });
        let mut sp = spec();
        sp.env.insert("A_1".into(), "x=y z".into());
        assert!(sp.validate().is_ok());
    }

    #[test]
    fn names_derive() {
        assert_eq!(spec().network(), "munix-demo-1");
        assert_eq!(spec().relay(), "munix-demo-1-relay");
    }

    #[test]
    fn network_create_is_internal() {
        assert_eq!(
            spec().network_create_args(),
            s(&["network", "create", "--internal", "munix-demo-1"])
        );
    }

    #[test]
    fn relay_run_args_are_exact() {
        assert_eq!(
            spec().relay_run_args(),
            s(&[
                "run",
                "-d",
                "--name",
                "munix-demo-1-relay",
                "--add-host",
                "host.docker.internal:host-gateway",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "-v",
                "/home/u/munix/relay/relay.py:/relay/relay.py:ro",
                "python:3.12-slim",
                "python",
                "/relay/relay.py",
                "4040",
                "192.168.5.2",
                "4040",
            ])
        );
    }

    #[test]
    fn relay_connect_args_are_exact() {
        assert_eq!(
            spec().relay_connect_args(),
            s(&["network", "connect", "munix-demo-1", "munix-demo-1-relay"])
        );
    }

    #[test]
    fn agent_run_args_are_exact() {
        assert_eq!(
            spec().agent_run_args(),
            s(&[
                "run",
                "-i",
                "--rm",
                "--name",
                "munix-demo-1",
                "--network",
                "munix-demo-1",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=64m",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "256",
                "--memory",
                "1g",
                "-v",
                "/home/u/agent:/agent:ro",
                "-e",
                "OPENAI_BASE_URL=http://munix-demo-1-relay:4040/v1",
                "-e",
                "OPENAI_API_KEY=munix-gateway",
                "-e",
                "MODEL=muse",
                "python:3.12-slim",
                "python",
                "/agent/agent.py",
                "--x",
            ])
        );
    }

    #[test]
    fn the_agent_gets_no_credentials_and_only_the_internal_network() {
        let mut sp = spec();
        sp.env.insert("TOPIC".into(), "shoes".into());
        let args = sp.agent_run_args();
        let env_names: Vec<&str> = args
            .windows(2)
            .filter(|w| w[0] == "-e")
            .filter_map(|w| w[1].split('=').next())
            .collect();
        for name in &env_names {
            if *name != "OPENAI_API_KEY" {
                assert!(
                    !FORBIDDEN_ENV_PARTS.iter().any(|p| name.contains(p)),
                    "{name}"
                );
            }
        }
        // The placeholder is the only credential-looking value.
        assert!(args.contains(&format!("OPENAI_API_KEY={PLACEHOLDER_KEY}")));
        assert_eq!(args.iter().filter(|a| *a == "--network").count(), 1);
        assert!(
            !args
                .iter()
                .any(|a| a == "host" || a == "bridge" || a.contains("--privileged"))
        );
        assert!(args.contains(&"--read-only".to_string()));
    }

    #[test]
    fn relay_script_and_agent_dir_are_read_only_mounts() {
        let sp = spec();
        for args in [sp.relay_run_args(), sp.agent_run_args()] {
            for w in args.windows(2).filter(|w| w[0] == "-v") {
                assert!(w[1].ends_with(":ro"), "{}", w[1]);
            }
        }
    }

    #[test]
    fn cleanup_removes_agent_relay_then_network() {
        assert_eq!(
            spec().cleanup_args(),
            vec![
                s(&["rm", "-f", "munix-demo-1"]),
                s(&["rm", "-f", "munix-demo-1-relay"]),
                s(&["network", "rm", "munix-demo-1"]),
            ]
        );
    }

    #[test]
    fn launch_refuses_an_invalid_spec_before_touching_docker() {
        let mut sp = spec();
        sp.name = "BAD".into();
        assert!(matches!(Sandbox::launch(sp), Err(SandboxError::Invalid(_))));
    }
}
