//! Qoder (`qodercli --acp`) shares the ACP transport. Its four session modes are
//! its permission modes, and models that support it report their own reasoning
//! efforts. Credentials stay with the installed Qoder CLI.
use super::*;

/// Qoder Desktop and the Agent SDK export SDK variables into the shells they spawn.
/// Inheriting them would hand the CLI the host's SDK identity and auth payload
/// instead of its own sign-in.
const SDK_ENVIRONMENT: [&str; 4] = [
    "QODER_AGENT_SDK_ENTRYPOINT",
    "QODER_SDK_ACCESS_TOKEN",
    "QODER_SDK_AUTH_PAYLOAD_FILE",
    "QODER_AUTH_STDIN",
];

pub(crate) fn configure(command: &mut Command) {
    command.arg("--acp");
    for name in SDK_ENVIRONMENT {
        command.env_remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configure_starts_the_acp_server() {
        let mut cmd = Command::new("test");
        configure(&mut cmd);
        assert_eq!(cmd.as_std().get_args().collect::<Vec<_>>(), ["--acp"]);
    }

    #[test]
    fn configure_removes_the_inherited_sdk_environment() {
        let inherited = [
            ("QODER_AGENT_SDK_ENTRYPOINT", "sdk"),
            ("QODER_SDK_ACCESS_TOKEN", "secret"),
            ("QODER_SDK_AUTH_PAYLOAD_FILE", "/tmp/payload.json"),
            ("QODER_AUTH_STDIN", "1"),
        ];
        let mut cmd = Command::new("test");
        for (name, value) in inherited {
            cmd.env(name, value);
        }
        cmd.env("QODER_CONFIG_DIR", "/home/user/.qoder");
        configure(&mut cmd);
        let envs: Vec<_> = cmd.as_std().get_envs().collect();
        for (name, _) in inherited {
            assert!(envs.iter().any(|(key, value)| *key == name && value.is_none()), "{name}");
        }
        // A user's own config folder is not an SDK variable and must survive.
        assert!(envs.iter().any(|(key, value)| *key == "QODER_CONFIG_DIR" && value.is_some()));
    }
}
