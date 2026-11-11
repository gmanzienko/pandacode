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

pub(super) fn mode_id(mode: &str) -> &'static str {
    match mode {
        "auto" => "acceptEdits",
        "full" => "bypassPermissions",
        "plan" => "plan",
        _ => "default",
    }
}

pub(super) fn permission(mode: &str, kind: &str) -> Option<&'static str> {
    match kind {
        "read" | "search" | "fetch" | "think" => Some("allow_once"),
        _ if mode == "plan" => Some("reject_once"),
        _ if mode == "full" => Some("allow_once"),
        _ => None,
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

    #[test]
    fn every_pandacode_mode_has_exactly_one_qoder_mode() {
        assert_eq!(mode_id("ask"), "default");
        assert_eq!(mode_id("auto"), "acceptEdits");
        assert_eq!(mode_id("plan"), "plan");
        assert_eq!(mode_id("full"), "bypassPermissions");
    }

    #[test]
    fn plan_allows_research_and_declines_everything_else() {
        for kind in ["read", "search", "fetch", "think"] {
            assert_eq!(permission("plan", kind), Some("allow_once"));
        }
        for kind in ["edit", "delete", "move", "execute", "other"] {
            assert_eq!(permission("plan", kind), Some("reject_once"));
        }
        assert_eq!(permission("ask", "edit"), None);
        assert_eq!(permission("full", "execute"), Some("allow_once"));
    }

    /// Recorded from `qodercli --acp` 1.1.13; session ID anonymized, model catalog omitted.
    fn session() -> Value {
        json!({"jsonrpc":"2.0","id":2,"result":{"sessionId":"ses_qoder_test",
            "modes":{"availableModes":[
                {"id":"default","name":"Default","description":"Prompts for approval"},
                {"id":"acceptEdits","name":"Accept Edits","description":"Auto-approves edit tools"},
                {"id":"bypassPermissions","name":"Bypass Permissions","description":"Auto-approves all tools"},
                {"id":"plan","name":"Plan","description":"Read-only mode"}],"currentModeId":"default"},
            "configOptions":[{"type":"select","id":"mode","name":"Mode","category":"mode","currentValue":"default","options":[
                {"value":"default","name":"Default","description":"Prompts for approval"},
                {"value":"acceptEdits","name":"Accept Edits","description":"Auto-approves edit tools"},
                {"value":"bypassPermissions","name":"Bypass Permissions","description":"Auto-approves all tools"},
                {"value":"plan","name":"Plan","description":"Read-only mode"}]}]}})
    }

    /// Recorded Plan-mode Write request; session ID and recorder paths
    /// anonymized. Option ids, kinds and ordering are verbatim: no
    /// `reject_always` is ever offered.
    fn permission_request(kind: &str) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"session/request_permission","params":{
            "sessionId":"ses_qoder_test",
            "options":[
                {"optionId":"proceed_always","name":"Allow for this session","kind":"allow_always"},
                {"optionId":"proceed_once","name":"Allow","kind":"allow_once"},
                {"optionId":"cancel","name":"Reject","kind":"reject_once"}],
            "toolCall":{"toolCallId":"call_5f44dc5181244712b01e386f","status":"pending","title":"Edit panda.txt",
                "content":[{"type":"diff","path":"panda.txt","oldText":null,"newText":"PANDA\n","_meta":{"kind":"add"}}],
                "kind":kind,
                "rawInput":{"content":"PANDA\n","file_path":"panda.txt"},
                "_meta":{"qoder":{"toolName":"Write"}}}}})
    }

    fn ready(mode: &str) -> Protocol {
        let mut cfg = super::super::tests::config("qoder");
        cfg.mode = mode.into();
        let mut p = Protocol::new(cfg);
        assert_eq!(p.acp(initialize()).unwrap().write[0]["method"], "session/new");
        let step = p.acp(session()).unwrap();
        assert_eq!(step.write[0]["method"], "session/set_config_option");
        assert_eq!(step.write[0]["params"]["configId"], "mode");
        assert_eq!(step.write[0]["params"]["value"], mode_id(mode));
        let prompt = p.acp(json!({"jsonrpc":"2.0","id":4,"result":{}})).unwrap();
        assert_eq!(prompt.write[0]["method"], "session/prompt");
        p
    }

    #[test]
    fn recorded_plan_edit_selects_the_offered_cancel_option() {
        let mut p = ready("plan");
        let step = p.acp(permission_request("edit")).unwrap();
        assert_eq!(step.write[0]["id"], 1);
        assert_eq!(step.write[0]["result"]["outcome"], json!({"outcome":"selected","optionId":"cancel"}));
        assert!(step.events.iter().any(|event| event.kind == "status" && event.text == "Plan mode declined: Edit panda.txt"));
        assert!(!step.events.iter().any(|event| event.kind == "approval"));
    }

    #[test]
    fn recorded_research_kinds_select_the_offered_proceed_once_option() {
        for kind in ["read", "search", "fetch", "think"] {
            let mut p = ready("plan");
            let step = p.acp(permission_request(kind)).unwrap();
            assert_eq!(step.write[0]["result"]["outcome"]["optionId"], "proceed_once", "{kind}");
        }
    }

    #[test]
    fn full_access_execute_selects_the_offered_proceed_once_option() {
        let mut p = ready("full");
        let step = p.acp(permission_request("execute")).unwrap();
        assert_eq!(step.write[0]["result"]["outcome"]["optionId"], "proceed_once");
    }

    /// Auto edits are allowed by the shared ACP path rather than Qoder's own
    /// policy; commands still ask the user.
    #[test]
    fn auto_mode_allows_research_and_edits_but_keeps_command_approvals() {
        for (kind, expected) in [
            ("read", Some("proceed_once")),
            ("edit", Some("proceed_once")),
            ("execute", None),
        ] {
            let mut p = ready("auto");
            let step = p.acp(permission_request(kind)).unwrap();
            if let Some(expected) = expected {
                assert_eq!(step.write[0]["result"]["outcome"]["optionId"], expected, "{kind}");
            } else {
                assert!(step.events.iter().any(|event| event.kind == "approval"), "{kind}");
                assert!(step.write.is_empty(), "{kind}");
            }
        }
    }

    #[test]
    fn standard_mode_keeps_the_edit_approval_for_the_user() {
        let mut p = ready("ask");
        let step = p.acp(permission_request("edit")).unwrap();
        assert!(step.events.iter().any(|event| event.kind == "approval"));
        assert!(step.write.is_empty());
    }

    #[test]
    fn a_plan_edit_without_a_reject_option_cancels_the_turn() {
        let mut p = ready("plan");
        let mut request = permission_request("edit");
        request["params"]["options"] = json!([
            {"optionId":"proceed_always","name":"Allow for this session","kind":"allow_always"},
            {"optionId":"proceed_once","name":"Allow","kind":"allow_once"}]);
        let step = p.acp(request).unwrap();
        assert_eq!(step.write[0]["result"]["outcome"]["outcome"], "cancelled");
        assert!(!step.events.iter().any(|event| event.kind == "approval"));
    }

    #[test]
    fn a_mode_the_cli_does_not_advertise_fails_the_run() {
        let mut cfg = super::super::tests::config("qoder");
        cfg.mode = "plan".into();
        let mut p = Protocol::new(cfg);
        p.acp(initialize()).unwrap();
        let mut unsupported = session();
        unsupported["result"]["configOptions"][0]["options"] = json!([
            {"value":"default","name":"Default","description":"Prompts for approval"}]);
        unsupported["result"]["modes"]["availableModes"] = json!([{"id":"default","name":"Default"}]);
        let error = p.acp(unsupported).err().unwrap();
        assert_eq!(error, "This harness does not advertise the selected task mode.");
    }

    /// The recordings carry `availableModes` without `configOptions`, so the
    /// mode rides on `session/set_mode`.
    #[test]
    fn recorded_modes_without_config_options_use_session_set_mode() {
        let mut cfg = super::super::tests::config("qoder");
        cfg.mode = "plan".into();
        let mut p = Protocol::new(cfg);
        p.acp(initialize()).unwrap();
        let mut modes_only = session();
        modes_only["result"].as_object_mut().unwrap().remove("configOptions");
        let step = p.acp(modes_only).unwrap();
        assert_eq!(step.write[0]["method"], "session/set_mode");
        assert_eq!(step.write[0]["params"]["modeId"], "plan");
        assert_eq!(step.write[0]["params"]["sessionId"], "ses_qoder_test");
    }

    #[test]
    fn an_unadvertised_mode_without_config_options_fails_the_run() {
        let mut cfg = super::super::tests::config("qoder");
        cfg.mode = "plan".into();
        let mut p = Protocol::new(cfg);
        p.acp(initialize()).unwrap();
        let mut unsupported = session();
        unsupported["result"].as_object_mut().unwrap().remove("configOptions");
        unsupported["result"]["modes"]["availableModes"] = json!([{"id":"default","name":"Default"}]);
        let error = p.acp(unsupported).err().unwrap();
        assert_eq!(error, "This harness does not advertise the selected task mode.");
    }

    #[test]
    fn a_session_without_mode_information_fails_the_run() {
        for mode in ["ask", "auto", "plan", "full"] {
            let mut cfg = super::super::tests::config("qoder");
            cfg.mode = mode.into();
            let mut p = Protocol::new(cfg);
            p.acp(initialize()).unwrap();
            let error = p.acp(json!({"jsonrpc":"2.0","id":2,"result":{"sessionId":"ses_qoder_test"}})).err().unwrap();
            assert_eq!(error, "This harness does not advertise the selected task mode.", "{mode}");
        }
    }
}
