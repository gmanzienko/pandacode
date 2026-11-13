//! Qoder (`qodercli --acp`) shares the ACP transport. Its advertised session modes are
//! its permission modes, and models that support it report their own reasoning
//! efforts. Credentials stay with the installed Qoder CLI.
use super::*;
use crate::slash_commands::claude::Pipe;

const STARTUP: Duration = Duration::from_secs(60);
// Qoder deletion includes a network round trip; valid replies can exceed two seconds.
const CLEANUP: Duration = Duration::from_secs(10);

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

pub(crate) fn scrub_sdk_environment(command: &mut impl crate::child_env::EnvTarget) {
    for name in SDK_ENVIRONMENT {
        command.remove_var(std::ffi::OsStr::new(name));
    }
}

pub(crate) fn configure(command: &mut Command) {
    command.arg("--acp");
    scrub_sdk_environment(command);
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

fn command(path: &Path) -> Result<Command, String> {
    let mut command = super::provider_command("qoder", path)?;
    configure(&mut command);
    Ok(command)
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"pandacode","version":"0.1.0"}}})
}

fn session_error(frame: &Value) -> String {
    if frame["error"]["code"] == -32000 {
        SIGN_IN.into()
    } else {
        acp::rpc_error(frame, "session creation")
    }
}

fn transport(pipe: &Pipe) -> String {
    if pipe.timed_out() {
        acp::ACP_STARTUP_TIMEOUT.into()
    } else {
        "Qoder's ACP server ended before it answered. Check the Qoder installation and sign-in, then refresh.".into()
    }
}

/// `config_option_update` notifications arrive before the reply and are
/// skipped; the reply is the source of truth.
async fn request(pipe: &mut Pipe, frame: &Value) -> Result<Value, String> {
    pipe.send(frame).await.map_err(|_| transport(pipe))?;
    loop {
        let reply = pipe.read().await.map_err(|_| transport(pipe))?;
        if reply.get("method").is_some() {
            if reply.get("id").is_some() {
                let _ = pipe.send(&json!({"jsonrpc":"2.0","id":reply["id"],"error":{"code":-32601,"message":"Metadata discovery does not execute requests"}})).await;
            }
            continue;
        }
        if reply["id"] == frame["id"] {
            return Ok(reply);
        }
    }
}

/// Attempt remote deletion on a fresh deadline; an ACK does not prove disk residue is gone.
pub(super) async fn delete_session(pipe: &mut Pipe, id: &str) -> Result<(), String> {
    const FAILED: &str = "Qoder session cleanup failed: session/delete did not return a matching success result.";
    pipe.set_deadline_after(CLEANUP);
    let reply = request(pipe, &json!({"jsonrpc":"2.0","id":9000,"method":"session/delete","params":{"sessionId":id}}))
        .await.map_err(|_| if pipe.timed_out() {
            "Qoder session cleanup timed out after 10 seconds.".to_owned()
        } else {
            "Qoder session cleanup failed: transport ended before acknowledgement.".to_owned()
        })?;
    if let Some(error) = reply.get("error") {
        return Err(match error["code"].as_i64() {
            Some(code) => format!("Qoder session cleanup failed: RPC error {code}."),
            None => "Qoder session cleanup failed: RPC error.".to_owned(),
        });
    }
    if !reply.get("result").is_some_and(Value::is_object) {
        return Err(FAILED.into());
    }
    Ok(())
}

async fn probe(path: &Path) -> Result<(Value, HashMap<String, Value>), String> {
    let cwd = std::env::temp_dir();
    let mut pipe = Pipe::spawn(command(path)?, &cwd, STARTUP)
        .map_err(|_| "Could not start Qoder's ACP server. Check the selected executable.".to_owned())?;
    let result = probe_frames(&mut pipe, &cwd).await;
    pipe.finish().await;
    result.map_err(|error| super::diagnostics::failure(&error, pipe.diagnostic()))
}

/// One empty session switches through every model, then attempts checked cleanup.
async fn probe_frames(pipe: &mut Pipe, cwd: &Path) -> Result<(Value, HashMap<String, Value>), String> {
    let init = request(pipe, &initialize()).await?;
    if init.get("error").is_some() {
        return Err(acp::rpc_error(&init, "initialize"));
    }
    if init["result"]["protocolVersion"] != 1 {
        return Err("This Qoder version does not support ACP protocol v1. Update Qoder.".into());
    }
    let created = request(pipe, &json!({"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":launch::external_path(cwd),"mcpServers":[]}})).await?;
    if created.get("error").is_some() {
        return Err(session_error(&created));
    }
    let session = created["result"].clone();
    let id = field(&session, "sessionId");
    if id.is_empty() || id.len() > 256 {
        return Err("Qoder did not return a session ID.".into());
    }
    let ids: Vec<String> = acp::options(&session, "model")
        .map(acp::choices)
        .unwrap_or_default()
        .into_iter()
        .map(|choice| field(choice, "value").to_owned())
        .filter(|id| valid_model_id(id))
        .collect();
    let mut efforts = HashMap::new();
    let walk = async {
        for (index, model) in ids.iter().enumerate() {
            let reply = request(pipe, &json!({"jsonrpc":"2.0","id":100 + index as u64,"method":"session/set_config_option","params":{"sessionId":id,"configId":"model","value":model}})).await?;
            if reply.get("error").is_some() {
                return Err(acp::rpc_error(&reply, "model switch"));
            }
            efforts.insert(model.clone(), reply["result"].clone());
        }
        Ok(())
    }
    .await;
    let cleanup = delete_session(pipe, id).await;
    walk?;
    cleanup?;
    Ok((session, efforts))
}

/// Models with their own efforts. No prompt is sent and no inference runs.
pub(super) async fn models(path: &Path) -> Result<Vec<ModelInfo>, String> {
    if let Some(models) = acp_catalog::get("qoder", path) { return Ok(models); }
    let _refresh = acp_catalog::refresh_lock("qoder", path).await;
    if let Some(models) = acp_catalog::get("qoder", path) { return Ok(models); }
    let discovery = acp_catalog::begin("qoder", path);
    let (session, efforts) = probe(path).await?;
    let models = catalog(&session, &efforts);
    acp_catalog::store_models(discovery, models.clone());
    Ok(models)
}

/// Builds the picker catalog from a `session/new` result and each model's
/// `set_config_option` reply result. The `reasoning_effort` option shares the
/// `model` category, so it is looked up by its exact id; a reply without one
/// means the model has no efforts.
pub(super) fn catalog(session: &Value, efforts: &HashMap<String, Value>) -> Vec<ModelInfo> {
    let mut models = vec![ModelInfo::default_choice()];
    let Some(option) = acp::options(session, "model") else { return models };
    for choice in acp::choices(option) {
        let id = field(choice, "value");
        if !valid_model_id(id) {
            continue;
        }
        let reply = efforts.get(id).unwrap_or(&Value::Null);
        let effort = acp::options(reply, "reasoning_effort").unwrap_or(&Value::Null);
        let reasoning_efforts: Vec<ReasoningEffortInfo> = acp::choices(effort)
            .into_iter()
            .filter_map(|choice| {
                let id = field(choice, "value");
                validate_reasoning_effort("qoder", Some(id)).ok()?;
                Some(effort_info(id, None))
            })
            .collect();
        let default_reasoning_effort = effort["currentValue"]
            .as_str()
            .filter(|value| reasoning_efforts.iter().any(|effort| effort.id == *value))
            .map(str::to_owned);
        models.push(ModelInfo {
            speed_tiers: Vec::new(),
            id: id.into(),
            name: model_text(choice["name"].as_str(), id, 160),
            description: model_text(choice["description"].as_str(), "", 500),
            reasoning_efforts,
            default_reasoning_effort,
            context_window: None,
        });
    }
    models
}

#[cfg(test)]
pub(super) mod tests {
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

    #[test]
    fn scrub_sdk_environment_removes_the_inherited_sdk_environment_from_a_console() {
        let inherited = [
            ("QODER_AGENT_SDK_ENTRYPOINT", "sdk"),
            ("QODER_SDK_ACCESS_TOKEN", "secret"),
            ("QODER_SDK_AUTH_PAYLOAD_FILE", "/tmp/payload.json"),
            ("QODER_AUTH_STDIN", "1"),
        ];
        let mut cmd = portable_pty::CommandBuilder::new("test");
        for (name, value) in inherited {
            cmd.env(name, value);
        }
        cmd.env("QODER_CONFIG_DIR", "/home/user/.qoder");
        scrub_sdk_environment(&mut cmd);
        for (name, _) in inherited {
            assert!(cmd.get_env(name).is_none(), "{name}");
        }
        // A user's own config folder is not an SDK variable and must survive.
        assert!(cmd.get_env("QODER_CONFIG_DIR").is_some());
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
        let step = p.receive(initialize()).unwrap();
        assert_eq!(step.write[0]["method"], "session/new");
        let error = p.receive(json!({"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Authentication required"}})).err().unwrap();
        assert_eq!(error, SIGN_IN);
    }

    #[test]
    fn pandacode_modes_keep_the_historical_qoder_mode_ids() {
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
    fn the_shared_acp_dispatch_drives_qoders_handshake_approvals_and_stop() {
        let mut p = ready("ask");
        assert_eq!(p.initial()["method"], "initialize");
        assert_eq!(p.initial()["params"]["protocolVersion"], 1);
        for (approved, option) in [(true, "proceed_once"), (false, "cancel")] {
            let step = p.receive(permission_request("execute")).unwrap();
            let id = step.events.iter().find(|event| event.kind == "approval").unwrap().request_id.clone().unwrap();
            assert_eq!(p.approve(&id, approved).unwrap()["result"]["outcome"]["optionId"], option, "{approved}");
        }
        assert_eq!(p.cancel()["method"], "session/cancel");
        assert_eq!(p.cancel()["params"]["sessionId"], "ses_qoder_test");
    }

    #[test]
    fn a_plan_edit_without_a_reject_option_cancels_the_request() {
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
        let error = p.acp(unsupported).unwrap().failure.unwrap();
        assert_eq!(error, "This harness does not advertise the selected task mode.");
    }

    /// Synthetic fixtures use the mode IDs defined in the installed 1.1.88 bundle,
    /// not a new live recording. Exercise both ACP configuration shapes.
    #[test]
    fn full_uses_only_an_advertised_equivalent_permission_mode() {
        for config_options in [true, false] {
            for (offered, expected) in [
                (vec!["yolo"], Some("yolo")),
                (vec!["bypassPermissions"], Some("bypassPermissions")),
                (vec!["yolo", "bypassPermissions"], Some("bypassPermissions")),
                (vec!["default", "acceptEdits", "auto", "dontAsk"], None),
                (vec!["unexpected"], None),
                (vec![], None),
            ] {
                let mut cfg = super::super::tests::config("qoder");
                cfg.mode = "full".into();
                let mut p = Protocol::new(cfg);
                p.receive(initialize()).unwrap();
                let mut frame = session();
                frame["result"]["modes"]["availableModes"] = json!(offered.iter().map(|id| json!({"id":id})).collect::<Vec<_>>());
                frame["result"]["modes"]["currentModeId"] = json!("unexpected");
                frame["result"]["configOptions"][0]["options"] = json!(offered.iter().map(|id| json!({"value":id})).collect::<Vec<_>>());
                frame["result"]["configOptions"][0]["currentValue"] = json!("unexpected");
                if !config_options { frame["result"].as_object_mut().unwrap().remove("configOptions"); }
                match (expected, p.receive(frame)) {
                    (Some(expected), Ok(step)) => {
                        assert!(step.failure.is_none());
                        assert_eq!(step.write.len(), 1);
                        let request = &step.write[0];
                        assert_eq!(request["method"], if config_options { "session/set_config_option" } else { "session/set_mode" });
                        assert_eq!(request["params"][if config_options { "value" } else { "modeId" }], expected);
                        let permission = p.receive(permission_request("execute")).unwrap();
                        assert_eq!(permission.write[0]["result"]["outcome"]["optionId"], "proceed_once");
                    }
                    (None, Ok(step)) => {
                        assert_eq!(step.failure.as_deref(), Some("This harness does not advertise the selected task mode."));
                        assert!(step.write.is_empty());
                    }
                    (expected, result) => panic!("offered {offered:?}, config options {config_options}: expected {expected:?}, success {}", result.is_ok()),
                }
            }
        }
    }

    #[tokio::test]
    async fn missing_plan_stops_before_model_selection_or_prompt() {
        for config_options in [true, false] {
            let mut frame = session();
            let offered = ["default", "acceptEdits", "auto", "dontAsk", "yolo"];
            frame["result"]["modes"]["availableModes"] = json!(offered.iter().map(|id| json!({"id":id})).collect::<Vec<_>>());
            frame["result"]["configOptions"][0]["options"] = json!(offered.iter().map(|id| json!({"value":id})).collect::<Vec<_>>());
            if !config_options { frame["result"].as_object_mut().unwrap().remove("configOptions"); }
            let script = format!(r#"
if(r.method==='initialize') send({{id:r.id,result:{{protocolVersion:1}}}});
else if(r.method==='session/new') send({frame});
else send({{id:r.id,result:{{}}}});
"#);
            let (child, dir) = fake_child(&script);
            let mut cfg = super::super::tests::config("qoder");
            cfg.cwd = dir.0.clone();
            cfg.mode = "plan".into();
            cfg.model = "efficient".into();
            let events = Arc::new(Mutex::new(Vec::<AgentEvent>::new()));
            let seen = events.clone();
            let (_input, receiver) = tokio::sync::mpsc::unbounded_channel();
            let result = run_process_with_tools(cfg, Arc::new(move |e| seen.lock().unwrap().push(e)), receiver, child, vec![], None).await;
            assert_eq!(result.unwrap_err(), "This harness does not advertise the selected task mode.");
            assert_eq!(requests(&dir.0).iter().map(|r| r["method"].as_str().unwrap()).collect::<Vec<_>>(), ["initialize", "session/new"]);
            assert!(!events.lock().unwrap().iter().any(|e| e.kind == "approval" || e.tool.is_some()));
            assert!(events.lock().unwrap().iter().any(|e| e.kind == "session" && e.text == "ses_qoder_test"), "setup failure must retain the owned session ID for checked cleanup");
        }
    }

    /// Synthetic shape: every recording advertises a `mode` configOption, but a
    /// future Qoder build could expose only `availableModes`. Cover the
    /// `session/set_mode` fallback so the selected mode is still applied.
    #[test]
    fn modes_without_config_options_use_session_set_mode() {
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
        let error = p.acp(unsupported).unwrap().failure.unwrap();
        assert_eq!(error, "This harness does not advertise the selected task mode.");
    }

    #[test]
    fn a_session_without_mode_information_fails_the_run() {
        for mode in ["ask", "auto", "plan", "full"] {
            let mut cfg = super::super::tests::config("qoder");
            cfg.mode = mode.into();
            let mut p = Protocol::new(cfg);
            p.acp(initialize()).unwrap();
            let error = p.acp(json!({"jsonrpc":"2.0","id":2,"result":{"sessionId":"ses_qoder_test"}})).unwrap().failure.unwrap();
            assert_eq!(error, "This harness does not advertise the selected task mode.", "{mode}");
        }
    }

    /// Recorded `session/new` result from `qodercli --acp` 1.1.13; session ID
    /// anonymized. The CLI's current model is `auto`, which has no effort option.
    pub(in crate::providers) fn session_new() -> Value {
        json!({"sessionId":"ses_qoder_test",
            "modes":{"availableModes":[
                {"id":"default","name":"Default","description":"Prompts for approval"},
                {"id":"acceptEdits","name":"Accept Edits","description":"Auto-approves edit tools"},
                {"id":"bypassPermissions","name":"Bypass Permissions","description":"Auto-approves all tools"},
                {"id":"plan","name":"Plan","description":"Read-only mode"}],"currentModeId":"default"},
            "models":{"availableModels":[
                {"modelId":"auto","name":"Auto (default)","description":"Vision · 0.50x Credit"},
                {"modelId":"ultimate","name":"Ultimate","description":"Reasoning · Vision · 0.40x Credit"},
                {"modelId":"efficient","name":"Efficient","description":"Vision · 0.30x Credit"},
                {"modelId":"smodel","name":"Sonus","description":"Reasoning · Vision · New · 8.00x Credit"},
                {"modelId":"cmodel","name":"Cantus","description":"Reasoning · Vision · New · 4.00x Credit"},
                {"modelId":"qmodel_latest","name":"Qwen4-Max-Preview","description":"Reasoning · Vision · New · 0.10x Credit"},
                {"modelId":"qmodel_38max","name":"Qwen3.8-Max","description":"Reasoning · Vision · New · 0.20x Credit"},
                {"modelId":"qfmodel","name":"Qwen3.8-Flash","description":"Reasoning · Vision · New · 0.04x Credit"},
                {"modelId":"kmodel_latest","name":"Kimi-K3.1-Pro","description":"Vision · New · 1.00x Credit"},
                {"modelId":"kmodel","name":"Kimi-K2.8-Preview","description":"Vision · New · 0.80x Credit"},
                {"modelId":"gmodel","name":"GLM-5.3","description":"Reasoning · Vision · New · 0.80x Credit"},
                {"modelId":"gfmodel","name":"GLM-5.3-Flash","description":"Reasoning · Vision · New · 0.10x Credit"},
                {"modelId":"dmodel","name":"DeepSeek-V4-Pro","description":"Reasoning · Vision · New · 0.50x Credit"},
                {"modelId":"dfmodel","name":"DeepSeek-Flash","description":"Reasoning · Vision · New · 0.10x Credit"},
                {"modelId":"mmodel","name":"MiniMax-M3.1-Flash","description":"Reasoning · Vision · New · 0.10x Credit"}],
                "currentModelId":"auto"},
            "configOptions":[
                {"type":"select","id":"mode","name":"Mode","category":"mode","currentValue":"default","options":[
                    {"value":"default","name":"Default","description":"Prompts for approval"},
                    {"value":"acceptEdits","name":"Accept Edits","description":"Auto-approves edit tools"},
                    {"value":"bypassPermissions","name":"Bypass Permissions","description":"Auto-approves all tools"},
                    {"value":"plan","name":"Plan","description":"Read-only mode"}]},
                {"type":"select","id":"model","name":"Model","category":"model","currentValue":"auto","options":[
                    {"value":"auto","name":"Auto (default)","description":"Vision · 0.50x Credit"},
                    {"value":"ultimate","name":"Ultimate","description":"Reasoning · Vision · 0.40x Credit"},
                    {"value":"efficient","name":"Efficient","description":"Vision · 0.30x Credit"},
                    {"value":"smodel","name":"Sonus","description":"Reasoning · Vision · New · 8.00x Credit"},
                    {"value":"cmodel","name":"Cantus","description":"Reasoning · Vision · New · 4.00x Credit"},
                    {"value":"qmodel_latest","name":"Qwen4-Max-Preview","description":"Reasoning · Vision · New · 0.10x Credit"},
                    {"value":"qmodel_38max","name":"Qwen3.8-Max","description":"Reasoning · Vision · New · 0.20x Credit"},
                    {"value":"qfmodel","name":"Qwen3.8-Flash","description":"Reasoning · Vision · New · 0.04x Credit"},
                    {"value":"kmodel_latest","name":"Kimi-K3.1-Pro","description":"Vision · New · 1.00x Credit"},
                    {"value":"kmodel","name":"Kimi-K2.8-Preview","description":"Vision · New · 0.80x Credit"},
                    {"value":"gmodel","name":"GLM-5.3","description":"Reasoning · Vision · New · 0.80x Credit"},
                    {"value":"gfmodel","name":"GLM-5.3-Flash","description":"Reasoning · Vision · New · 0.10x Credit"},
                    {"value":"dmodel","name":"DeepSeek-V4-Pro","description":"Reasoning · Vision · New · 0.50x Credit"},
                    {"value":"dfmodel","name":"DeepSeek-Flash","description":"Reasoning · Vision · New · 0.10x Credit"},
                    {"value":"mmodel","name":"MiniMax-M3.1-Flash","description":"Reasoning · Vision · New · 0.10x Credit"}]}]})
    }

    /// Each model's recorded `session/set_config_option` reply result (CLI
    /// 1.1.13). Every reply repeats `session_new`'s `mode` and `model` options
    /// byte-for-byte with `model.currentValue` set to the switched model, then
    /// appends the recorded `reasoning_effort` option pasted below; `auto` and
    /// `efficient` replied without one.
    pub(in crate::providers) fn efforts() -> HashMap<String, Value> {
        let base = session_new()["configOptions"].as_array().unwrap().clone();
        let mut efforts = HashMap::new();
        for (model, option) in [
            ("auto", Value::Null),
            ("ultimate", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"},{"value":"medium","name":"Medium"}]})),
            ("efficient", Value::Null),
            ("smodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"},{"value":"medium","name":"Medium"}]})),
            ("cmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"},{"value":"medium","name":"Medium"}]})),
            ("qmodel_latest", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"none","name":"None"}]})),
            ("qmodel_38max", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"low","name":"Low"},{"value":"medium","name":"Medium"},{"value":"none","name":"None"}]})),
            ("qfmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"low","name":"Low"},{"value":"medium","name":"Medium"},{"value":"none","name":"None"}]})),
            ("kmodel_latest", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"high","options":[{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"}]})),
            ("kmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"high","options":[{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"}]})),
            ("gmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"high","options":[{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"}]})),
            ("gfmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"high","options":[{"value":"high","name":"High"},{"value":"max","name":"Max"}]})),
            ("dmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"high","options":[{"value":"high","name":"High"},{"value":"max","name":"Max"},{"value":"none","name":"None"}]})),
            ("dfmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"high","options":[{"value":"high","name":"High"},{"value":"max","name":"Max"},{"value":"low","name":"Low"},{"value":"none","name":"None"}]})),
            ("mmodel", json!({"type":"select","id":"reasoning_effort","name":"Reasoning Effort","category":"model","currentValue":"xhigh","options":[{"value":"xhigh","name":"Extra High"},{"value":"high","name":"High"},{"value":"low","name":"Low"},{"value":"max","name":"Max"},{"value":"medium","name":"Medium"}]})),
        ] {
            let mut options = base.clone();
            options.iter_mut().find(|option| option["id"] == "model").unwrap()["currentValue"] = json!(model);
            if !option.is_null() {
                options.push(option);
            }
            efforts.insert(model.to_owned(), json!({"configOptions": options}));
        }
        efforts
    }

    #[test]
    fn catalog_keeps_default_and_every_advertised_model() {
        let models = catalog(&session_new(), &efforts());
        assert_eq!(models.len(), 16); // default + 15
        assert_eq!(models[0].id, "default");
        let sonus = models.iter().find(|m| m.id == "smodel").unwrap();
        assert_eq!(sonus.name, "Sonus");
        assert_eq!(sonus.reasoning_efforts.len(), 5);
        let kimi = models.iter().find(|m| m.id == "kmodel_latest").unwrap();
        assert_eq!(kimi.reasoning_efforts.len(), 3);
        let auto = models.iter().find(|m| m.id == "auto").unwrap();
        assert!(auto.reasoning_efforts.is_empty());
        // Recorded: `efficient` advertises no reasoning_effort option either.
        let efficient = models.iter().find(|m| m.id == "efficient").unwrap();
        assert!(efficient.reasoning_efforts.is_empty());
        assert!(models.iter().all(|m| m.speed_tiers.is_empty()));
    }

    #[test]
    fn catalog_reads_each_models_own_effort_option_in_wire_order() {
        let models = catalog(&session_new(), &efforts());
        let effort_ids = |id: &str| {
            models.iter().find(|m| m.id == id).unwrap()
                .reasoning_efforts.iter().map(|effort| effort.id.as_str()).collect::<Vec<_>>()
        };
        assert_eq!(effort_ids("gfmodel"), ["high", "max"]);
        assert_eq!(effort_ids("dmodel"), ["high", "max", "none"]);
        assert_eq!(effort_ids("qmodel_latest"), ["xhigh", "high", "low", "none"]);
        // Kimi's descriptions carry no `Reasoning` marker, yet the wire option
        // offers three efforts: the description text must never gate them.
        let kimi = models.iter().find(|m| m.id == "kmodel_latest").unwrap();
        assert!(!kimi.description.contains("Reasoning"));
        assert_eq!(effort_ids("kmodel_latest"), ["high", "low", "max"]);
        assert_eq!(effort_ids("kmodel"), ["high", "low", "max"]);
        assert_eq!(models.iter().filter(|m| !m.reasoning_efforts.is_empty()).count(), 13);
        let ultimate = models.iter().find(|m| m.id == "ultimate").unwrap();
        assert_eq!(ultimate.reasoning_efforts[0].name, "Extra high");
        assert_eq!(ultimate.default_reasoning_effort.as_deref(), Some("xhigh"));
        let dmodel = models.iter().find(|m| m.id == "dmodel").unwrap();
        assert_eq!(dmodel.default_reasoning_effort.as_deref(), Some("high"));
        assert!(models.iter().all(|m| m.context_window.is_none()));
        // Credit prices drift between probes, so only the stable markers are pinned.
        let sonus = models.iter().find(|m| m.id == "smodel").unwrap();
        assert!(sonus.description.contains("Reasoning"));
        assert!(sonus.description.contains("Vision"));
    }

    /// Synthetic `smodel` override: an unoffered `currentValue` must not be the default.
    #[test]
    fn a_current_value_outside_the_offered_efforts_is_not_the_default() {
        let baseline = catalog(&session_new(), &efforts());
        let sonus = baseline.iter().find(|m| m.id == "smodel").unwrap();
        assert_eq!(sonus.default_reasoning_effort.as_deref(), Some("xhigh"));

        let mut replies = efforts();
        let options = replies.get_mut("smodel").unwrap()["configOptions"].as_array_mut().unwrap();
        let effort = options.iter_mut().find(|option| option["id"] == "reasoning_effort").unwrap();
        effort["currentValue"] = json!("turbo");
        let models = catalog(&session_new(), &replies);
        let sonus = models.iter().find(|m| m.id == "smodel").unwrap();
        assert_eq!(sonus.default_reasoning_effort.as_deref(), None);
        assert_eq!(
            sonus.reasoning_efforts.iter().map(|effort| effort.id.as_str()).collect::<Vec<_>>(),
            ["xhigh", "high", "low", "max", "medium"]
        );
    }

    /// Like `ready`, but with a model and effort chosen: stops after the model
    /// switch (request id 5) so the caller feeds that model's recorded reply
    /// from `efforts()`.
    fn ready_model_effort(mode: &str, model: &str, effort: &str) -> Protocol {
        let mut cfg = super::super::tests::config("qoder");
        cfg.mode = mode.into();
        cfg.model = model.into();
        cfg.reasoning_effort = Some(effort.into());
        let mut p = Protocol::new(cfg);
        assert_eq!(p.acp(initialize()).unwrap().write[0]["method"], "session/new");
        let step = p.acp(json!({"jsonrpc":"2.0","id":2,"result":session_new()})).unwrap();
        assert_eq!(step.write[0]["method"], "session/set_config_option");
        assert_eq!(step.write[0]["params"]["configId"], "mode");
        assert_eq!(step.write[0]["params"]["value"], mode_id(mode));
        let step = p.acp(json!({"jsonrpc":"2.0","id":4,"result":{}})).unwrap();
        assert_eq!(step.write[0]["id"], 5);
        assert_eq!(step.write[0]["method"], "session/set_config_option");
        assert_eq!(step.write[0]["params"]["configId"], "model");
        assert_eq!(step.write[0]["params"]["value"], model);
        p
    }

    #[test]
    fn a_chosen_effort_is_set_after_the_model_switch_before_the_prompt() {
        let mut p = ready_model_effort("ask", "smodel", "max");
        let step = p.acp(json!({"jsonrpc":"2.0","id":5,"result":efforts()["smodel"]})).unwrap();
        assert_eq!(step.write[0]["id"], 6);
        assert_eq!(step.write[0]["method"], "session/set_config_option");
        assert_eq!(step.write[0]["params"]["sessionId"], "ses_qoder_test");
        assert_eq!(step.write[0]["params"]["configId"], "reasoning_effort");
        assert_eq!(step.write[0]["params"]["value"], "max");
        let prompt = p.acp(json!({"jsonrpc":"2.0","id":6,"result":{}})).unwrap();
        assert_eq!(prompt.write[0]["method"], "session/prompt");
    }

    #[test]
    fn an_effort_on_a_model_that_advertises_none_fails_the_run() {
        let mut p = ready_model_effort("ask", "efficient", "max");
        let error = p.acp(json!({"jsonrpc":"2.0","id":5,"result":efforts()["efficient"]})).err().unwrap();
        assert_eq!(error, "This model does not advertise an adjustable reasoning effort. Choose harness settings.");
    }

    // Node is an offline JSON-lines ACP child, also on Windows; it never invokes Qoder.
    fn fake_child(script: &str) -> (Command, Cleanup) {
        let dir = std::env::temp_dir().join(format!("pandacode-qoder-fixture-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut command = Command::new("node");
        let prefix = r#"const fs=require('node:fs');
const send=x=>{if(x.id===9000 && x.result && !x.error) fs.writeFileSync('delete-ack.json',JSON.stringify(x));console.log(JSON.stringify(x));};
require('node:readline').createInterface({input:process.stdin}).on('line',line=>{
 const r=JSON.parse(line); fs.appendFileSync('requests.jsonl',line+'\n');
"#;
        command.args(["-e", &format!("{prefix}{script}\n}});"), "--"]);
        (command, Cleanup(dir))
    }

    fn requests(dir: &Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join("requests.jsonl")).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    #[tokio::test]
    async fn qoder_cold_spawn_scrubs_sdk_values_after_named_launch() {
        for provider in ["kimi", "qoder"] {
            let script = format!(r#"
if(r.method==='initialize') send({{id:r.id,result:{{protocolVersion:1}}}});
else if(r.method==='session/new') send({{id:r.id,result:{session}}});
else if(r.method==='session/set_config_option'||r.method==='session/set_mode') send({{id:r.id,result:{{}}}});
else if(r.method==='session/prompt') {{
 fs.writeFileSync('environment.json',JSON.stringify({{
  QODER_AGENT_SDK_ENTRYPOINT:process.env.QODER_AGENT_SDK_ENTRYPOINT,
  QODER_SDK_ACCESS_TOKEN:process.env.QODER_SDK_ACCESS_TOKEN,
  QODER_SDK_AUTH_PAYLOAD_FILE:process.env.QODER_SDK_AUTH_PAYLOAD_FILE,
  QODER_AUTH_STDIN:process.env.QODER_AUTH_STDIN,
  QODER_CONFIG_DIR:process.env.QODER_CONFIG_DIR,
  PANDA_FIXTURE_ORDINARY:process.env.PANDA_FIXTURE_ORDINARY
 }}));
 send({{id:r.id,result:{{stopReason:'end_turn'}}}});
}}
"#, session=session()["result"]);
            let (mut child, dir) = fake_child(&script);
            let mut config = super::super::tests::config(provider);
            config.cwd = dir.0.clone();
            super::super::configure_command_with_agents(&mut child, &config, &Default::default(), &Default::default());
            let mut env: Vec<_> = SDK_ENVIRONMENT.iter().map(|name| (name.to_string(), "fixture-sdk".into())).collect();
            env.extend([("QODER_CONFIG_DIR".into(), "fixture-config".into()), ("PANDA_FIXTURE_ORDINARY".into(), "ordinary".into())]);
            crate::connections::Launch { executable: None, args: vec![], env, secrets: vec![] }.apply(&mut child);
            let (_input, receiver) = tokio::sync::mpsc::unbounded_channel();
            let result = tokio::time::timeout(Duration::from_secs(5), run_process_with_tools(config, Arc::new(|_| {}), receiver, child, vec![], None)).await;
            assert!(matches!(result, Ok(Ok(()))), "{provider}: {result:?}");
            let env: Value = serde_json::from_str(&std::fs::read_to_string(dir.0.join("environment.json")).unwrap()).unwrap();
            assert_eq!(env.as_object().unwrap().len(), if provider == "qoder" { 2 } else { 6 });
            for name in SDK_ENVIRONMENT {
                if provider == "qoder" { assert!(env.get(name).is_none(), "{name} survived named launch"); }
                else { assert_eq!(env[name], "fixture-sdk", "{name} control"); }
            }
            assert_eq!(env["QODER_CONFIG_DIR"], "fixture-config");
            assert_eq!(env["PANDA_FIXTURE_ORDINARY"], "ordinary");
        }
    }

    #[tokio::test]
    async fn qoder_probe_requires_delete_ack_and_preserves_walk_failure() {
        let mut failures = vec![];
        for (case, delete, walk, expected) in [
            ("delayed-valid-ack", "setTimeout(()=>send({id:r.id,result:{}}),2400)", "send({id:r.id,result:{}})", None),
            ("success", "send({id:r.id,result:{}})", "send({id:r.id,result:{}})", None),
            ("delete-error", "send({id:r.id,error:{code:-1,message:'private fixture secret'}})", "send({id:r.id,result:{}})", Some("RPC error -1")),
            ("eof", "process.exit(0)", "send({id:r.id,result:{}})", Some("transport ended")),
            ("missing-result", "send({id:r.id})", "send({id:r.id,result:{}})", Some("cleanup")),
            ("timeout", "setTimeout(()=>{},20000)", "send({id:r.id,result:{}})", Some("cleanup timed out")),
            ("non-object-result", "send({id:r.id,result:[]})", "send({id:r.id,result:{}})", Some("cleanup")),
            ("error-with-result", "send({id:r.id,result:{},error:{message:'private fixture secret'}})", "send({id:r.id,result:{}})", Some("RPC error")),
            ("wrong-id-then-ack", "send({id:8999,error:{code:-1}});send({id:r.id,result:{}})", "send({id:r.id,result:{}})", None),
            ("walk-error-delete-error", "send({id:r.id,error:{code:-1,message:'private fixture secret'}})", "send({id:r.id,error:{code:-1,message:'walk failed'}})", Some("model switch")),
            ("walk-timeout-fresh-delete", "setTimeout(()=>send({id:r.id,result:{}}),100)", "setTimeout(()=>{},5000)", Some("timed out")),
        ] {
            let script = format!(r#"
if(r.method==='initialize') send({{id:r.id,result:{{protocolVersion:1}}}});
else if(r.method==='session/new') send({{id:r.id,result:{{sessionId:'owned',configOptions:[{{type:'select',id:'model',options:[{{value:'efficient'}}]}}]}}}});
else if(r.method==='session/set_config_option') {{ {walk}; }}
else if(r.method==='session/delete') {{ if(r.params.sessionId!=='owned') process.exit(3); {delete}; }}
"#);
            let (child, dir) = fake_child(&script);
            let mut pipe = Pipe::spawn(child, &dir.0, Duration::from_millis(600)).unwrap();
            let started = std::time::Instant::now();
            let result = probe_frames(&mut pipe, &dir.0).await;
            let elapsed = started.elapsed();
            if elapsed > Duration::from_secs(13) { failures.push(format!("{case}: exceeded bounded cleanup")); }
            if case == "timeout" && elapsed < Duration::from_secs(10) { failures.push("timeout: cleanup ended before ten seconds".into()); }
            pipe.finish().await;
            let deleted = requests(&dir.0).iter().any(|r| r["method"] == "session/delete" && r["params"]["sessionId"] == "owned");
            if !deleted { failures.push(format!("{case}: no delete attempted")); }
            if matches!(case, "delayed-valid-ack" | "success" | "wrong-id-then-ack" | "walk-timeout-fresh-delete") && !dir.0.join("delete-ack.json").is_file() {
                failures.push(format!("{case}: cleanup ended before the success acknowledgement"));
            }
            match (expected, result) {
                (None, Ok(_)) => {},
                (Some(expected), Err(error)) if error.contains(expected) && !error.contains("private fixture secret") => {},
                (expected, result) => failures.push(format!("{case}: expected {expected:?}, got {result:?}")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[tokio::test]
    async fn qoder_command_inspection_checks_cleanup_and_keeps_optional_commands() {
        let mut failures = vec![];
        for (case, notifications, created, delete, expected) in [
            ("before", "before", true, "ack", "commands"),
            ("after", "after", true, "ack", "commands"),
            ("none", "none", true, "ack", "empty"),
            ("wrong-session", "wrong", true, "ack", "empty"),
            ("delete-error", "after", true, "error", "error"),
            ("failure-after-create", "bad", true, "ack", "error"),
            ("no-id", "none", false, "ack", "error"),
        ] {
            let script = format!(r#"
if(r.method==='initialize') send({{id:r.id,result:{{protocolVersion:1}}}});
else if(r.method==='session/new') {{
 const update={{method:'session/update',params:{{sessionId:'owned',update:{{sessionUpdate:'available_commands_update',availableCommands:[{{name:'fixture'}}]}}}}}};
 if('{notifications}'==='before') send(update);
 send({{id:r.id,result:{{sessionId:{id}}}}});
 if('{notifications}'==='after') send(update);
 if('{notifications}'==='wrong') {{update.params.sessionId='other';send(update);}}
 if('{notifications}'==='bad') send({{id:2,error:{{code:-1,message:'later session failure'}}}});
}}
else if(r.method==='session/delete') {{
 if(r.params.sessionId!=='owned') process.exit(3);
 send('{delete}'==='ack'?{{id:r.id,result:{{}}}}:{{id:r.id,error:{{code:-1,message:'private fixture secret'}}}});
}}
"#, id=if created { "'owned'" } else { "null" });
            let (child, dir) = fake_child(&script);
            let result = acp::inspect_with(child, &dir.0, true, false, true).await;
            let deletes: Vec<_> = requests(&dir.0).into_iter().filter(|r| r["method"] == "session/delete").collect();
            if deletes.len() != usize::from(created) { failures.push(format!("{case}: {} deletes", deletes.len())); }
            match (expected, result) {
                ("commands", Ok((_, Some(_)))) | ("empty", Ok((_, None))) => {},
                ("error", Err(error)) if !error.contains("private fixture secret") => {},
                (_, result) => failures.push(format!("{case}: {result:?}")),
            }
        }
        // Public generic inspector must continue without deleting non-Qoder sessions.
        let (child, dir) = fake_child("if(r.method==='initialize') send({id:r.id,result:{protocolVersion:1}}); else if(r.method==='session/new') send({id:r.id,result:{sessionId:'other'}}); else process.exit(9);");
        assert!(acp::inspect(child, &dir.0, false).await.is_ok());
        assert!(!requests(&dir.0).iter().any(|r| r["method"] == "session/delete"));
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn plan_declines_missing_null_and_unrecognized_permission_kinds() {
        for kind in [None, Some(Value::Null), Some(json!("Read")), Some(json!("unexpected")), Some(json!(17))] {
            for reject in [true, false] {
                let mut p = ready("plan");
                let mut request = permission_request("edit");
                let tool = request["params"]["toolCall"].as_object_mut().unwrap();
                if let Some(kind) = &kind { tool.insert("kind".into(), kind.clone()); } else { tool.remove("kind"); }
                if !reject { request["params"]["options"].as_array_mut().unwrap().retain(|o| o["kind"] != "reject_once"); }
                let step = p.acp(request).unwrap();
                assert_eq!(step.write[0]["result"]["outcome"], if reject { json!({"outcome":"selected","optionId":"cancel"}) } else { json!({"outcome":"cancelled"}) });
                assert!(step.events.iter().any(|e| e.kind == "status" && e.text.starts_with("Plan mode declined:")));
                assert!(!step.events.iter().any(|e| e.kind == "approval"));
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires an installed, signed-in Qoder CLI; reads the catalog only"]
    async fn installed_qoder_lists_models_with_efforts() {
        let path = executable("qoder").expect("Install Qoder CLI first");
        let models = models(&path).await.expect("Qoder ACP discovery should succeed");
        assert!(models.iter().any(|m| m.id == "default"));
        assert!(models.iter().any(|m| !m.reasoning_efforts.is_empty()));
    }

    /// Needs a signed-in Qoder CLI. Two small turns on `efficient` in a throwaway
    /// git repo: the first writes a file, the second resumes the same session and
    /// reads it back. A resumed turn that kept the id and still reached a tool is
    /// the proof `session/resume` works; the advertised capability alone is not.
    #[tokio::test]
    #[ignore = "requires an installed, signed-in Qoder CLI; sends two short prompts"]
    async fn installed_qoder_runs_and_resumes_a_task() {
        super::super::widen_process_path();
        let dir = std::env::temp_dir().join(format!("pandacode-qoder-live-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cwd = dir.canonicalize().unwrap();
        // The repo is removed even when an assertion below fails.
        let _cleanup = Cleanup(cwd.clone());
        crate::secret_store::setup(&cwd);
        let init = std::process::Command::new("git").args(["init", "-q"]).current_dir(&cwd).stdin(std::process::Stdio::null()).output().expect("git init");
        assert!(init.status.success(), "git init failed in the throwaway repo");
        let path = executable("qoder").expect("Install Qoder CLI first");
        // Unique per run, so the resumed turn can only get it from the file or the session.
        let word = format!("PANDA-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() % 100_000);
        let text = |events: &[AgentEvent]| events.iter().filter(|e| e.kind == "text" || e.kind == "delta").map(|e| e.text.as_str()).collect::<String>();
        let (first, first_outcome) = live_turn(&path, &cwd, "auto", format!("Create a file named panda.txt in the current directory containing exactly this word: {word}. Use your file-writing tool, then reply with the word."), None).await;
        let session = first.iter().find(|event| event.kind == "session").map(|event| event.text.clone());
        let (second, outcome) = if let Some(session) = session.as_ref().filter(|_| first_outcome.is_ok()) {
            live_turn(&path, &cwd, "auto", "Read panda.txt with your file-reading tool and reply with exactly the word it contains.".into(), Some(session.clone())).await
        } else {
            (Vec::new(), Err("Resume skipped because the first turn failed or returned no session ID.".into()))
        };
        let cleanup = cleanup_live_sessions(&path, &cwd, first.iter().chain(second.iter())).await;
        // Assert only after attempting checked cleanup for every captured ID.
        assert!(first_outcome.is_ok(), "the first turn should finish");
        assert!(outcome.is_ok(), "the resumed turn should finish");
        cleanup.expect("all test-owned sessions should acknowledge deletion");
        let session = session.expect("a session id");
        let written = std::fs::read_to_string(cwd.join("panda.txt")).expect("the first turn should have written panda.txt");
        assert!(written.contains(&word), "the file should contain the expected word");
        assert!(first.iter().any(|event| event.tool.is_some()), "the first turn should have called a tool");
        assert!(text(&first).contains(&word), "the first response should contain the expected word");
        assert_eq!(second.iter().find(|event| event.kind == "session").expect("a session id").text, session, "resume must reuse the saved session");
        assert!(second.iter().any(|event| event.tool.is_some()), "the resumed turn should have called a tool");
        assert!(text(&second).contains(&word), "the resumed response should contain the expected word");
        for event in first.iter().chain(second.iter()) {
            assert!(!event.text.contains("Bearer "), "a run must never surface the host token");
        }
    }

    async fn live_turn(path: &Path, cwd: &Path, mode: &str, prompt: String, resume: Option<String>) -> (Vec<AgentEvent>, Result<(), String>) {
        let mut config = super::super::tests::config("qoder");
        config.session_id = "qoder-live-smoke".into();
        config.cwd = cwd.to_owned();
        config.mode = mode.into();
        config.model = "efficient".into();
        config.prompt = prompt;
        config.resume_id = resume;
        let events = Arc::new(Mutex::new(Vec::<AgentEvent>::new()));
        let seen = events.clone();
        // Hold input open; unexpected approvals receive no manual auto-approval.
        let (_input, receiver) = tokio::sync::mpsc::unbounded_channel::<RunInput>();
        let sink: Sink = Arc::new(move |event| seen.lock().unwrap().push(event));
        let mut command = super::super::provider_command("qoder", path).unwrap();
        super::super::configure_command(&mut command, &config);
        command.env("TMPDIR", cwd).env("TEMP", cwd).env("TMP", cwd);
        let result = tokio::time::timeout(Duration::from_secs(180), run_process_with_tools(config, sink, receiver, command, Vec::new(), None))
            .await.map_err(|_| "the turn timed out".to_string()).and_then(|r| r);
        let captured = events.lock().unwrap().clone();
        (captured, result)
    }

    async fn cleanup_live_sessions<'a>(path: &Path, cwd: &Path, events: impl Iterator<Item = &'a AgentEvent>) -> Result<(), String> {
        let ids: HashSet<_> = events.filter(|e| e.kind == "session" && !e.text.is_empty() && e.text.len() <= 256)
            .map(|e| e.text.clone()).collect();
        if ids.is_empty() { return Err("No test-owned session ID was captured; cleanup could not be attempted.".into()); }
        let mut errors = Vec::new();
        for id in ids {
            let result = async {
                let mut child = command(path)?;
                child.env("TMPDIR", cwd).env("TEMP", cwd).env("TMP", cwd);
                let mut pipe = Pipe::spawn(child, cwd, STARTUP).map_err(|_| "Could not start session cleanup.".to_owned())?;
                let result = async {
                    let init = request(&mut pipe, &super::initialize()).await?;
                    if init.get("error").is_some() || init["result"]["protocolVersion"] != 1 {
                        return Err("Could not initialize session cleanup.".into());
                    }
                    delete_session(&mut pipe, &id).await
                }.await;
                pipe.finish().await;
                result
            }.await;
            if let Err(error) = result { errors.push(error); }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
    }

    #[tokio::test]
    #[ignore = "requires an installed, signed-in Qoder CLI; sends one short Plan write request"]
    async fn installed_qoder_plan_refuses_write() {
        super::super::widen_process_path();
        let dir = std::env::temp_dir().join(format!("pandacode-qoder-plan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cwd = dir.canonicalize().unwrap();
        let _cleanup = Cleanup(cwd.clone());
        crate::secret_store::setup(&cwd);
        let init = std::process::Command::new("git").args(["init", "-q"]).current_dir(&cwd).stdin(Stdio::null()).output().expect("git init");
        assert!(init.status.success(), "git init failed in the throwaway repo");
        std::fs::write(cwd.join("sentinel.txt"), "KEEP\n").unwrap();
        assert!(!cwd.join("plan-target.txt").exists());
        let path = executable("qoder").expect("Install Qoder CLI first");
        let (events, outcome) = live_turn(&path, &cwd, "plan", "Use your file-writing tool to overwrite sentinel.txt with CHANGED and create plan-target.txt containing CHANGED.".into(), None).await;
        let cleanup = cleanup_live_sessions(&path, &cwd, events.iter()).await;
        cleanup.expect("all test-owned sessions should acknowledge deletion");
        assert_eq!(std::fs::read_to_string(cwd.join("sentinel.txt")).unwrap(), "KEEP\n");
        assert!(!cwd.join("plan-target.txt").exists());
        assert!(!events.iter().any(|e| e.kind == "approval"), "Plan must not need manual approval");
        match outcome {
            Ok(()) => assert!(events.iter().any(|e| e.kind == "status" && e.text.starts_with("Plan mode declined:")),
                "inconclusive: no actual Plan decline event; a text-only refusal does not prove enforcement"),
            Err(error) if error == "This harness does not advertise the selected task mode." => {
                assert!(!events.iter().any(|e| e.tool.is_some()), "unsupported Plan must not execute tools");
                panic!("unsupported Plan: the installed CLI did not advertise the task mode during session setup, before model selection or prompting; files unchanged, no approvals or tools, cleanup acknowledged; write enforcement was not tested");
            }
            Err(_) => panic!("Plan turn failed with an unexpected setup or execution error; cleanup acknowledged; write enforcement was not established"),
        }
    }

    /// Removes the throwaway repo when the test ends, pass or fail.
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
