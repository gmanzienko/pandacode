//! Qoder (`qodercli --acp`) shares the ACP transport. Its four session modes are
//! its permission modes, and models that support it report their own reasoning
//! efforts. Credentials stay with the installed Qoder CLI.
use super::*;

/// Shown when Qoder has no stored sign-in.
pub(super) const SIGN_IN: &str =
    "Qoder is not signed in. Run `qodercli login` in a terminal, then send again.";

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

    /// Recorded from `qodercli --acp` 1.1.13.
    fn initialize() -> Value {
        json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,
            "authMethods":[{"id":"qodercli-login","name":"Use qodercli login","description":"Use your existing qodercli login for this agent. If needed, sign in from qodercli first."}],
            "agentInfo":{"name":"qoder-cli","title":"Qoder CLI","version":"1.1.13"},
            "agentCapabilities":{"_meta":{"qoder":{"promptQueueing":true}},"loadSession":true,
                "sessionCapabilities":{"additionalDirectories":{},"close":{},"delete":{},"fork":{},"list":{},"resume":{}},
                "promptCapabilities":{"image":true,"embeddedContext":true},
                "mcpCapabilities":{"http":true,"sse":true}}}})
    }

    /// The recording was signed in, so the error frame is the documented
    /// JSON-RPC shape rather than a captured one.
    #[test]
    fn a_session_without_sign_in_names_the_login_command() {
        let mut p = Protocol::new(super::super::tests::config("qoder"));
        let step = p.acp(initialize()).unwrap();
        assert_eq!(step.write[0]["method"], "session/new");
        let error = p.acp(json!({"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Authentication required"}})).err().unwrap();
        assert_eq!(error, SIGN_IN);
    }
}
