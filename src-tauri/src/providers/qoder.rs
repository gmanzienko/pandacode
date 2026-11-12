//! Qoder (`qodercli --acp`) shares the ACP transport. Its four session modes are
//! its permission modes, and models that support it report their own reasoning
//! efforts. Credentials stay with the installed Qoder CLI.
use super::*;
use crate::slash_commands::claude::Pipe;

const STARTUP: Duration = Duration::from_secs(60);
const CLEANUP: Duration = Duration::from_secs(2);

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

async fn probe(path: &Path) -> Result<(Value, HashMap<String, Value>), String> {
    let cwd = std::env::temp_dir();
    let mut pipe = Pipe::spawn(command(path)?, &cwd, STARTUP)
        .map_err(|_| "Could not start Qoder's ACP server. Check the selected executable.".to_owned())?;
    let result = probe_frames(&mut pipe, &cwd).await;
    pipe.finish().await;
    result.map_err(|error| super::diagnostics::failure(&error, pipe.diagnostic()))
}

/// One session switches through every model in order (each switch answers in
/// about a millisecond), then is deleted so it never appears in Qoder's history.
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
    // Delete even when the walk failed, so an early error leaves no session behind.
    pipe.set_deadline_after(CLEANUP);
    let _ = request(pipe, &json!({"jsonrpc":"2.0","id":9000,"method":"session/delete","params":{"sessionId":id}})).await;
    walk?;
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

    /// Recorded `session/new` result from `qodercli --acp` 1.1.13; session ID
    /// anonymized. The CLI's current model is `auto`, which has no effort option.
    fn session_new() -> Value {
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
    fn efforts() -> HashMap<String, Value> {
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
        let turn = |prompt: String, resume: Option<String>| {
            let mut config = super::super::tests::config("qoder");
            config.session_id = "qoder-live-resume".into();
            config.cwd = cwd.clone();
            config.model = "efficient".into();
            config.prompt = prompt;
            config.resume_id = resume;
            let events = Arc::new(Mutex::new(Vec::<AgentEvent>::new()));
            let seen = events.clone();
            let (input, receiver) = tokio::sync::mpsc::unbounded_channel::<RunInput>();
            let approvals = input.clone();
            let sink: Sink = Arc::new(move |event| {
                if event.kind == "approval" {
                    if let Some(request_id) = event.request_id.clone() {
                        let _ = approvals.send(RunInput::Approval { request_id, approved: true });
                    }
                }
                seen.lock().unwrap().push(event);
            });
            let mut command = super::super::provider_command("qoder", &path).unwrap();
            super::super::configure_command(&mut command, &config);
            async move {
                // A closed input channel means Stop; hold it open for the turn.
                let _input = input;
                let run = run_process_with_tools(config, sink, receiver, command, Vec::new(), None);
                let limit = tokio::time::Duration::from_secs(180);
                let result = tokio::time::timeout(limit, run).await.map_err(|_| "the turn timed out".to_string()).and_then(|r| r);
                (events.lock().unwrap().clone(), result)
            }
        };
        let text = |events: &[AgentEvent]| events.iter().filter(|e| e.kind == "text" || e.kind == "delta").map(|e| e.text.as_str()).collect::<String>();
        let (first, outcome) = turn(format!("Create a file named panda.txt in the current directory containing exactly this word: {word}. Use your file-writing tool, then reply with the word."), None).await;
        outcome.expect("the first turn should finish");
        let session = first.iter().find(|event| event.kind == "session").expect("a session id").text.clone();
        let (second, outcome) = turn("Read panda.txt with your file-reading tool and reply with exactly the word it contains.".into(), Some(session.clone())).await;
        // Delete before asserting, so a failed assertion still leaves no Qoder history.
        let mut pipe = Pipe::spawn(command(&path).unwrap(), &cwd, STARTUP).unwrap();
        pipe.send(&initialize()).await.unwrap();
        pipe.send(&json!({"jsonrpc":"2.0","id":2,"method":"session/delete","params":{"sessionId":session.clone()}})).await.unwrap();
        while let Ok(frame) = pipe.read().await {
            if frame["id"] == 2 {
                assert!(frame.get("error").is_none(), "{frame}");
                break;
            }
        }
        pipe.finish().await;
        outcome.expect("the resumed turn should finish");
        let written = std::fs::read_to_string(cwd.join("panda.txt")).expect("the first turn should have written panda.txt");
        assert!(written.contains(&word), "{written:?}");
        assert!(first.iter().any(|event| event.tool.is_some()), "the first turn should have called a tool");
        assert!(text(&first).contains(&word), "{:?}", first.iter().map(|e| (&e.kind, &e.text)).collect::<Vec<_>>());
        assert_eq!(second.iter().find(|event| event.kind == "session").expect("a session id").text, session, "resume must reuse the saved session");
        assert!(second.iter().any(|event| event.tool.is_some()), "the resumed turn should have called a tool");
        assert!(text(&second).contains(&word), "{:?}", second.iter().map(|e| (&e.kind, &e.text)).collect::<Vec<_>>());
        for event in first.iter().chain(second.iter()) {
            assert!(!event.text.contains("Bearer "), "a run must never surface the host token");
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
