//! ZCode (z.ai's CLI) over its `app-server` protocol: newline-delimited JSON on
//! stdio, no handshake and no transport auth — whoever holds the pipe drives the
//! session. Frames recorded from the CLI bundled with ZCode.app (user-agent
//! `ZCode/3.16.3`); see `.agents/state/zcode-harness/protocol.md`. The wire
//! surface (`session/*` v1) predates the in-flight v4 migration, so every frame
//! is parsed defensively: unknown events and reverse requests are ignored or
//! answered `-32601` (the server tolerates that), and nothing outside the
//! session's turn is allowed to fail a run.
use super::*;
use tokio::io::AsyncBufReadExt;

/// Own request ids on the shared connection. Prompts continue the sequence so
/// `turn.completed` echoes them back as `inputId` ("pandacode-<n>").
const ID_CREATE: u64 = 1;
const ID_MODEL: u64 = 2;
const ID_THOUGHT: u64 = 3;
const ID_SUBSCRIBE: u64 = 4;
const ID_MODE: u64 = 5;
const ID_STOP: u64 = 1 << 40;
const FIRST_PROMPT_ID: u64 = 6;

pub(super) const SIGN_IN: &str =
    "ZCode requires sign-in. Sign in via the ZCode desktop app (or run `zcode` in a terminal if using the standalone CLI), then send again.";

const NO_MODELS: &str = "ZCode reported no models over app-server. On ZCode 3.19+, Z.ai/BigModel account plans stay inside the ZCode desktop app — make sure you are signed in (in ZCode Desktop, or via `zcode` for the standalone CLI) and configure an API-key provider in ZCode Desktop's Provider Settings or directly in ~/.zcode/v2/provider_config.json (for the standalone CLI), or use GLM Coding Plan in PandaCode.";

/// A JSON-RPC error as user text: an account or auth failure becomes the sign-in
/// guidance, anything else keeps the server's (shortened) message. Whole words and
/// phrases only, so `assign`, `signature` or `design` never read as sign-in.
fn auth_words(text: &str) -> String {
    let mut words = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut previous = None;
    while let Some(ch) = chars.next() {
        if ch.is_ascii_uppercase() && previous.is_some_and(|prev: char| prev.is_ascii_lowercase() || prev.is_ascii_digit()
            || (prev.is_ascii_uppercase() && chars.peek().is_some_and(char::is_ascii_lowercase))) { words.push(' '); }
        words.push(ch.to_ascii_lowercase());
        previous = Some(ch);
    }
    words
}

fn rpc_error(error: &Value) -> String {
    let raw_message = field(error, "message");
    let bounded_message = (raw_message.len() > 256 * 1024).then(|| super::diagnostics::clean_bounded(raw_message));
    let lower = auth_words(bounded_message.as_deref().unwrap_or(raw_message));
    let data_text = |text: &str| if text.len() > 256 * 1024 { super::diagnostics::clean_bounded(text) } else { text.to_owned() };
    let words: Vec<_> = lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).collect();
    let data = auth_words(&error.get("data").map(|data| {
        if let Some(text) = data.as_str() { return data_text(text); }
        let fields = ["code", "kind", "error", "type", "reason", "message"];
        std::iter::once(data).chain(["error", "details", "cause"].iter().filter_map(|key| data.get(key).filter(|value| value.is_object())))
            .flat_map(|object| fields.iter().filter_map(move |key| object.get(key).and_then(Value::as_str)))
            .map(&data_text).collect::<Vec<_>>().join(" ")
    }).unwrap_or_default());
    let data_words: Vec<_> = data.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).collect();
    let combined: Vec<_> = words.iter().chain(data_words.iter()).copied().collect();
    let billing_or_quota = combined.iter().any(|word| matches!(*word, "billing" | "quota" | "balance" | "credit" | "credits" | "rate" | "limit" | "limits" | "budget" | "plan" | "subscription" | "payment" | "insufficient" | "exceeded" | "exhausted"));
    let provider_api_key = combined.windows(2).any(|pair| matches!(pair, ["api", "key"]))
        || combined.iter().any(|word| matches!(*word, "apikey" | "provider" | "providers"));
    let transport = combined.iter().any(|word| matches!(*word,
        "econnrefused" | "econnreset" | "etimedout" | "enotfound" | "ehostunreach" | "enetunreach" | "epipe" | "econnaborted"
        | "network" | "dns" | "socket" | "timeout" | "timedout" | "unreachable" | "tls" | "ssl" | "certificate" | "cert" | "proxy"
    )) || combined.windows(2).any(|pair| matches!(pair, ["timed", "out"] | ["connection", "refused"] | ["connection", "reset"] | ["hang", "up"]));
    let config_only = words.iter().any(|word| matches!(*word, "provider" | "providers" | "model" | "models" | "configured" | "config"));
    let account_auth = words.contains(&"account") && !billing_or_quota && !config_only && !provider_api_key
        && words.iter().any(|word| matches!(*word, "missing" | "required" | "needed" | "none" | "no" | "auth" | "authenticate" | "authenticated" | "authentication" | "expired" | "invalid" | "unverified"));
    let message_auth = words.iter().any(|word| matches!(*word, "auth" | "authentication" | "authorization" | "oauth"))
        && words.iter().any(|word| matches!(*word, "missing" | "required" | "failed" | "expired" | "invalid" | "needed" | "denied" | "rejected" | "revoked"));
    let explicit_auth = words.iter().any(|word| matches!(*word, "signin" | "login" | "unauthenticated" | "unauthorized"))
        || words.windows(2).any(|pair| matches!(pair, ["sign", "in"] | ["signed", "in"] | ["log", "in"] | ["logged", "in"] | ["not", "authenticated"] | ["signed", "out"] | ["logged", "out"] | ["token", "expired"] | ["session", "expired"] | ["status", "401"] | ["http", "401"]))
        || words.windows(3).any(|tri| matches!(tri, ["status", "code", "401"]))
        || (words.contains(&"token") && words.contains(&"expired"))
        || (words.contains(&"session") && words.contains(&"expired"));
    let data_auth = data_words.iter().any(|word| matches!(*word, "auth" | "authentication" | "authorization" | "unauthenticated" | "unauthorized" | "oauth" | "signin" | "login"));
    let auth = !transport && (account_auth || (!billing_or_quota && !provider_api_key && (message_auth || explicit_auth || data_auth)));
    if auth { SIGN_IN.into() } else { short(&bounded_message.unwrap_or_else(|| super::diagnostics::clean_bounded(raw_message))) }
}

/// The create snapshot names a session model, which serves the `default` choice
/// even when the catalog lists nothing.
fn has_session_model(snapshot: &Value) -> bool {
    !model_text(snapshot["session"]["model"]["modelId"].as_str(), "", 160).is_empty()
}

/// The CLI bundled with ZCode Desktop (`…/resources/glm/zcode.cjs`), for installs
/// without `zcode` on PATH. The launch layer runs it on the app's own Electron
/// runtime, so no system node is needed.
pub(super) fn bundled() -> Option<PathBuf> {
    bundled_candidates().into_iter().find(|path| runnable(path))
}

/// The launch layer can run the script: it carries an exec bit (direct shebang
/// exec) or a desktop app runtime sits beside it to launch it, so a bundled copy
/// that lost its mode still counts when its app can run it.
#[cfg(unix)]
fn runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().is_ok_and(|metadata| {
        metadata.is_file()
            && (metadata.permissions().mode() & 0o111 != 0
                || super::launch::electron_runtime(path).is_some())
    })
}

#[cfg(not(unix))]
fn runnable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(target_os = "macos")]
fn bundled_candidates() -> Vec<PathBuf> {
    let home = crate::agent_usage_providers::home();
    [Some(PathBuf::from("/Applications")), home.map(|home| home.join("Applications"))]
        .into_iter()
        .flatten()
        .map(|root| root.join("ZCode.app/Contents/Resources/glm/zcode.cjs"))
        .collect()
}

#[cfg(target_os = "windows")]
fn bundled_candidates() -> Vec<PathBuf> {
    bundled_candidates_for_windows(
        std::env::var_os("LOCALAPPDATA").as_deref(),
        std::env::var_os("ProgramFiles").as_deref(),
    )
}

/// electron-builder's NSIS defaults: per-user under %LOCALAPPDATA%\Programs,
/// per-machine under %ProgramFiles%; the inner layout matches every platform.
/// A relative value would resolve against the working directory, and a `..` one
/// could leave the install root, so either is ignored.
#[cfg(any(target_os = "windows", test))]
fn bundled_candidates_for_windows(
    local_appdata: Option<&std::ffi::OsStr>,
    program_files: Option<&std::ffi::OsStr>,
) -> Vec<PathBuf> {
    let absolute = |value: Option<&std::ffi::OsStr>| {
        value
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .filter(|path| super::launch::is_clean_absolute(path))
    };
    absolute(local_appdata)
        .map(|local| local.join("Programs"))
        .into_iter()
        .chain(absolute(program_files))
        .flat_map(|root| ["ZCode", "zcode"].map(|name| root.join(name)))
        .map(|root| root.join("resources").join("glm").join("zcode.cjs"))
        .collect()
}

#[cfg(target_os = "linux")]
fn bundled_candidates() -> Vec<PathBuf> {
    // electron-builder's deb/rpm default installs under /opt/<product name>.
    ["/opt/ZCode", "/opt/zcode"]
        .iter()
        .map(|root| PathBuf::from(root).join("resources/glm/zcode.cjs"))
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn bundled_candidates() -> Vec<PathBuf> {
    Vec::new()
}

/// PandaCode mode → ZCode session mode. `auto` is Accept edits (edits run
/// free, the rest ask); Standard (`ask`) and the reviewer mode run `build`.
pub(super) fn mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "plan",
        "auto" => "edit",
        "full" => "yolo",
        _ => "build",
    }
}

pub(super) fn configure(command: &mut Command) {
    command.arg("app-server");
}

#[derive(Default)]
pub(super) struct State {
    /// Context window of the session's model, captured from the create snapshot.
    context_window: Option<u64>,
    /// Model reference requested via `session/setModel`, verified on the reply.
    requested_model: Option<(String, String)>,
    /// Thought level requested via `session/setThoughtLevel`.
    requested_thought: Option<String>,
    /// Session mode requested via `session/setMode` (create and every resume).
    requested_mode: Option<&'static str>,
    /// Sequence number of the prompt in flight; 0 until the first `session/send`.
    next_input: u64,
    /// The current assistant message streamed reasoning deltas.
    reasoning: bool,
    /// Latest turn failure, held until the turn's completed frame decides the run.
    error: Option<String>,
}

fn same_ref(a: &Value, b: &Value) -> bool {
    a["providerId"] == b["providerId"] && a["modelId"] == b["modelId"]
}

/// The catalog entry matching a session model reference carries the live
/// context window; recorded snapshots restated it per build, so re-read it
/// from whichever snapshot just answered instead of caching the first value.
fn context_window_of(settings: &Value, reference: &Value) -> Option<u64> {
    settings["model"]["available"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| same_ref(&entry["ref"], reference))
        .and_then(|entry| entry["contextWindow"].as_u64())
        .filter(|n| *n > 0 && *n <= 1_000_000_000)
}

/// The catalog entry offers this reasoning level.
fn lists_level(entry: &Value, level: &str) -> bool {
    entry["reasoning"]["levels"]
        .as_array()
        .is_some_and(|levels| levels.iter().any(|item| field(item, "value") == level))
}

fn workspace_of(cwd: &std::path::Path) -> Value {
    let path = cwd.to_string_lossy().to_string();
    json!({"workspacePath": path, "workspaceKey": path})
}

/// `payload.type` carries the discriminator on recorded frames; `type` is the
/// fallback for builds that flattened the envelope.
fn event_kind(params: &Value) -> &str {
    let nested = field(&params["payload"], "type");
    if nested.is_empty() {
        field(params, "type")
    } else {
        nested
    }
}

/// Whether a stopped run's output has reached its end.
pub(super) fn stop_settled(value: &Value) -> bool {
    value["method"] == "session/event" && event_kind(&value["params"]) == "turn.completed"
}

/// The stop request. The run then settles through `turn.completed`.
pub(super) fn stop(remote_id: &str) -> Value {
    json!({"id": ID_STOP, "method": "session/stop", "params": {"sessionId": remote_id}})
}

/// Discovery stdout cap, mirroring the Pi discovery limit.
const DISCOVERY_OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;

type DefaultKey = (PathBuf, Option<std::time::SystemTime>, u64);
type DefaultModels = HashMap<DefaultKey, (std::time::Instant, Vec<ModelInfo>)>;
fn default_key(path: &Path) -> DefaultKey {
    let metadata = std::fs::metadata(path).ok();
    (path.to_owned(), metadata.as_ref().and_then(|m| m.modified().ok()), metadata.map_or(0, |m| m.len()))
}
fn default_cache() -> &'static Mutex<DefaultModels> {
    static CACHE: OnceLock<Mutex<DefaultModels>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}
fn default_epoch() -> &'static std::sync::atomic::AtomicU64 {
    static EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    &EPOCH
}
pub(super) fn clear_default_cache() {
    let mut cache = default_cache().lock().unwrap_or_else(|p| p.into_inner());
    default_epoch().fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    cache.clear();
}
fn default_models(path: &Path, now: std::time::Instant) -> Option<Vec<ModelInfo>> {
    let mut cache = default_cache().lock().unwrap_or_else(|p| p.into_inner());
    cache.retain(|_, (time, _)| now.saturating_duration_since(*time) < Duration::from_secs(60));
    cache.get(&default_key(path)).map(|(_, models)| models.clone())
}
fn store_default(path: &Path, epoch: u64, models: &[ModelInfo]) {
    let mut cache = default_cache().lock().unwrap_or_else(|p| p.into_inner());
    let now = std::time::Instant::now();
    cache.retain(|_, (time, _)| now.saturating_duration_since(*time) < Duration::from_secs(60));
    if default_epoch().load(std::sync::atomic::Ordering::Relaxed) != epoch { return; }
    cache.retain(|key, _| key.0 != path);
    if models.len() <= 1 {
        while cache.len() >= 16 {
            let oldest = cache.iter().min_by_key(|(_, (time, _))| *time).map(|(key, _)| key.clone()).unwrap();
            cache.remove(&oldest);
        }
        cache.insert(default_key(path), (now, models.to_vec()));
    }
}

/// The catalog is session metadata only: never send a prompt during discovery.
pub(super) async fn models(path: &Path) -> Result<Vec<ModelInfo>, String> {
    if let Some(models) = acp_catalog::get("zcode", path).or_else(|| default_models(path, std::time::Instant::now())) {
        return Ok(models);
    }
    let _refresh = acp_catalog::refresh_lock("zcode", path).await;
    if let Some(models) = acp_catalog::get("zcode", path).or_else(|| default_models(path, std::time::Instant::now())) {
        return Ok(models);
    }
    let epoch = default_epoch().load(std::sync::atomic::Ordering::Relaxed);
    let discovery = acp_catalog::begin("zcode", path);
    let models = discover(path).await?;
    acp_catalog::store_models(discovery, models.clone());
    store_default(path, epoch, &models);
    Ok(models)
}

fn parse_models(snapshot: &Value) -> Result<Vec<ModelInfo>, String> {
    let entries = snapshot["settings"]["model"]["available"]
        .as_array()
        .filter(|v| v.len() <= MODEL_CATALOG_LIMIT)
        .ok_or("Invalid ZCode model catalog")?;
    let mut models = vec![ModelInfo::default_choice()];
    // 3.19+ leaves the catalog empty when only desktop-managed account plans exist;
    // a session model still serves the default choice, and the row names it.
    if entries.is_empty() {
        if !has_session_model(snapshot) {
            return Err(NO_MODELS.into());
        }
        let session_model = model_text(snapshot["session"]["model"]["modelId"].as_str(), "", 160);
        if !session_model.is_empty() {
            models[0].description = format!("Uses ZCode's active session model ({session_model}).");
        }
        return Ok(models);
    }
    let mut seen = HashSet::new();
    for entry in entries {
        let label = field(entry, "label").to_owned();
        if !valid_model_id(&label) || !seen.insert(label.clone()) {
            continue;
        }
        let reasoning = &entry["reasoning"];
        let efforts: Vec<_> = reasoning["levels"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|level| (field(level, "value"), level["description"].as_str()))
            .filter(|(value, _)| validate_reasoning_effort("zcode", Some(value)).is_ok())
            .map(|(value, description)| effort_info(value, description))
            .collect();
        let default_reasoning_effort = reasoning["defaultLevel"]
            .as_str()
            .filter(|level| efforts.iter().any(|effort| effort.id.as_str() == *level))
            .map(str::to_owned);
        models.push(ModelInfo {
            speed_tiers: Vec::new(),
            name: model_text(entry["label"].as_str(), &label, 160),
            description: model_text(entry["providerLabel"].as_str(), "", 200),
            id: label,
            reasoning_efforts: efforts,
            default_reasoning_effort,
            context_window: entry["contextWindow"]
                .as_u64()
                .filter(|n| *n > 0 && *n <= 1_000_000_000),
        });
    }
    // Entries were listed, yet none was usable.
    if models.len() <= 1 {
        return Err("Invalid ZCode model catalog".into());
    }
    Ok(models)
}

/// The throwaway discovery session's private, empty workspace under app data.
/// No fallback: a shared temp folder can hold a planted project config that the
/// CLI would load, so discovery fails instead.
fn discovery_workspace(app_data: Option<&Path>) -> Result<AgentTemp, String> {
    let dir = app_data.ok_or("Could not locate PandaCode's app data folder for ZCode discovery. Check your user profile permissions and try again.")?;
    let root = dir.join(AGENT_TEMP_DIR);
    AgentTemp::sweep_once(&root);
    AgentTemp::create_in(&root).ok_or_else(|| format!("Could not create a private folder for ZCode discovery under {}. Check folder permissions and free disk space, then try again.", root.display()))
}

fn discovery_error(message: String, diagnostic: &str) -> String {
    if message == SIGN_IN || message == NO_MODELS { message }
    else { super::diagnostics::failure(&message, diagnostic) }
}

async fn discover(path: &Path) -> Result<Vec<ModelInfo>, String> {
    let mut command = super::provider_command("zcode", path)?;
    command.arg("app-server");
    #[cfg(test)]
    let app_data = Some(std::env::temp_dir().join("pandacode-test-app-data"));
    #[cfg(not(test))]
    let app_data = crate::secret_store::dir().map(Path::to_path_buf);
    let folder = discovery_workspace(app_data.as_deref())?;
    command
        .current_dir(&folder.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not start ZCode: {e}"))?;
    let mut stderr_task = child
        .stderr
        .take()
        .map(|stderr| super::StderrReader(tokio::spawn(super::read_stderr(stderr))));
    let group = ProcessGroup::register(child.id());
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        let mut stdin = child.stdin.take().ok_or("ZCode stdin unavailable")?;
        write_json(
            &mut stdin,
            &json!({"id": ID_CREATE, "method": "session/create", "params": {
                "workspace": workspace_of(&folder.0),
                "persistence": "deferred",
                "mode": "plan",
                "titleGenerationEnabled": false,
            }}),
        )
        .await?;
        let mut stdout = tokio::io::BufReader::new(
            child.stdout.take().ok_or("ZCode stdout unavailable")?,
        )
        .take(DISCOVERY_OUTPUT_LIMIT + 1);
        let mut total = 0u64;
        loop {
            let mut line = Vec::new();
            let count = stdout
                .read_until(b'\n', &mut line)
                .await
                .map_err(|e| e.to_string())?;
            total += count as u64;
            if total > DISCOVERY_OUTPUT_LIMIT {
                return Err("ZCode model catalog exceeded its output limit".into());
            }
            if count == 0 {
                return Err("ZCode exited before returning models".into());
            }
            let value: Value =
                serde_json::from_slice(&line).map_err(|_| "Invalid ZCode discovery JSON")?;
            if value.get("method").is_some() && value.get("id").is_some() {
                // The server blocks on client requests (runtime preferences);
                // declining them like the run path does unblocks the create.
                write_json(
                    &mut stdin,
                    &json!({"id": value["id"], "error": {"code": -32601, "message": "Method not found"}}),
                )
                .await?;
                continue;
            }
            if value["id"] != ID_CREATE {
                continue;
            }
            if let Some(error) = value.get("error") {
                return Err(rpc_error(error));
            }
            let _ = write_json(
                &mut stdin,
                &json!({"id": 2, "method": "session/close", "params": {
                    "sessionId": value["result"]["session"]["sessionId"],
                }}),
            )
            .await;
            return parse_models(&value["result"]);
        }
    })
    .await
    .unwrap_or_else(|_| Err("ZCode model discovery timed out".into()));
    drop(group);
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    // Removed only once the CLI is gone, so it never runs in a deleted folder.
    drop(folder);
    match result {
        Ok(models) => Ok(models),
        Err(message) if message == SIGN_IN || message == NO_MODELS => Err(discovery_error(message, "")),
        Err(message) => {
            // Surface why the CLI failed (missing provider config, addon load
            // failure), cleaned and with credentials redacted.
            let diagnostic = match stderr_task.take() {
                Some(mut task) => tokio::time::timeout(Duration::from_millis(500), &mut task.0)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default(),
                None => String::new(),
            };
            Err(discovery_error(message, &diagnostic))
        }
    }
}

impl Protocol {
    /// Opens the run's session. Deferred persistence keeps captures and failed
    /// starts out of the user's ZCode history; resume attaches by saved id.
    pub(super) fn zcode_initial(&self) -> Value {
        match &self.config.resume_id {
            Some(id) => json!({"id": ID_CREATE, "method": "session/resume",
                "params": {"sessionId": id, "workspace": workspace_of(&self.config.cwd)}}),
            None => self.zcode_create(),
        }
    }

    fn zcode_create(&self) -> Value {
        json!({"id": ID_CREATE, "method": "session/create", "params": {
            "workspace": workspace_of(&self.config.cwd),
            "mode": mode(&self.config.mode),
            "persistence": "deferred",
            "titleGenerationEnabled": false,
        }})
    }

    pub(super) fn zcode(&mut self, value: Value) -> Result<Step, String> {
        let mut step = Step::default();
        if value.get("method").is_some() {
            self.zcode_frame(value, &mut step)?;
            return Ok(step);
        }
        if let Some(error) = value.get("error") {
            // Deferred persistence promotes a session on its first send, so a
            // start that failed before it left nothing on disk and this
            // per-run server cannot resume it. Start fresh instead of failing
            // the thread for good; a create's own error is never swallowed.
            if value["id"] == ID_CREATE
                && self.config.resume_id.is_some()
                && (error["code"] == -32004
                    || field(error, "message")
                        .to_lowercase()
                        .starts_with("session not found"))
            {
                self.config.resume_id = None;
                self.remote_id.clear();
                step.events.push(self.event(
                    "status",
                    "The saved ZCode session is gone, so a new session started without its history",
                    None,
                ));
                step.write.push(self.zcode_create());
                return Ok(step);
            }
            return Err(rpc_error(error));
        }
        match value["id"].as_u64() {
            Some(ID_CREATE) => self.zcode_created(&value, &mut step)?,
            Some(ID_MODEL) => {
                let session = &value["result"]["session"];
                let applied = self
                    .zcode
                    .requested_model
                    .as_ref()
                    .is_some_and(|(provider, model)| {
                        session["model"]["providerId"] == *provider
                            && session["model"]["modelId"] == *model
                    });
                if !applied {
                    return Err("ZCode did not apply the selected model".into());
                }
                self.zcode.context_window =
                    context_window_of(&value["result"]["settings"], &session["model"]);
            }
            Some(ID_MODE) => {
                let applied = self.zcode.requested_mode.is_some_and(|wanted| {
                    value["result"]["settings"]["mode"]["current"] == wanted
                });
                if !applied {
                    return Err("ZCode did not apply the selected access mode".into());
                }
            }
            Some(ID_THOUGHT) => {
                let applied = self.zcode.requested_thought.as_deref().is_some_and(|effort| {
                    value["result"]["settings"]["thoughtLevel"]["current"] == *effort
                });
                if !applied {
                    return Err("ZCode did not apply the selected thinking level".into());
                }
            }
            Some(ID_SUBSCRIBE) => self.zcode_prompt(self.config.prompt.clone(), &mut step),
            _ => {}
        }
        Ok(step)
    }

    /// Notifications and the server's reverse requests. Unknown reverse requests
    /// get `-32601`, which recorded servers answer and carry on from.
    fn zcode_frame(&mut self, value: Value, step: &mut Step) -> Result<(), String> {
        match (field(&value, "method"), value.get("id").is_some()) {
            ("interaction/requestPermission", true)
                if self.config.mode == "full" && !super::lasting_only(&value) =>
            {
                // yolo should not ask; a policy request that still arrives takes
                // the offered one-time allow, never a standing grant.
                step.write.push(permission_decision(&value, true));
            }
            ("interaction/requestPermission", true) => {
                // Offering only a lasting allow (e.g. `allow_project` adding rules) is
                // never answered automatically, even in Full: it asks, marked `LASTING_ONLY`.
                let params = &value["params"];
                let text = format!(
                    "{}\n{}\n{}",
                    field(params, "toolName"),
                    field(params, "reason"),
                    preview_json(&params["input"], TOOL_INPUT_LIMIT),
                );
                self.approval(value, text, step);
                // A denial needs no offered option (`permission_decision` falls back to a
                // plain deny), so a team worker's automatic answer can always decline it.
                if let Some(data) = step.events.last_mut().and_then(|event| event.data.as_mut()) {
                    if data[super::LASTING_ONLY] == true {
                        data[super::LASTING_DECLINABLE] = json!(true);
                    }
                }
            }
            ("interaction/requestUserInput", true) => step.write.push(
                json!({"id": value["id"], "result": {"action": "decline",
                       "reason": "PandaCode cannot answer interactive questions yet"}}),
            ),
            ("session/event", false) => self.zcode_event(&value, step)?,
            (_, true) => step.write.push(
                json!({"id": value["id"], "error": {"code": -32601, "message": "Method not found"}}),
            ),
            _ => {}
        }
        Ok(())
    }

    fn zcode_event(&mut self, value: &Value, step: &mut Step) -> Result<(), String> {
        let params = &value["params"];
        let payload = &params["payload"];
        match event_kind(params) {
            "turn.started" => self.zcode.reasoning = false,
            "model.streaming" => match field(payload, "kind") {
                "text_delta" => {
                    let id = field(payload, "assistantMessageId");
                    if self.claude_message_id != id {
                        self.claude_message_id = id.to_owned();
                        self.zcode.reasoning = false;
                    }
                    self.text_delta(id, None, field(payload, "delta"), step);
                }
                "reasoning_delta" if !self.zcode.reasoning => {
                    self.zcode.reasoning = true;
                    step.events.push(self.event("status", "Reasoning", None));
                }
                _ => {}
            },
            "tool.updated" => {
                let id = field(payload, "toolCallId");
                match field(payload, "kind") {
                    "scheduled" | "started" => {
                        self.tool_update(
                            id,
                            Some(field(payload, "toolName")),
                            Some("running"),
                            payload["input"]
                                .as_object()
                                .map(|_| preview_json(&payload["input"], TOOL_INPUT_LIMIT)),
                            None,
                            step,
                        );
                    }
                    "result" => {
                        let result = &payload["result"];
                        let status = if result["success"] == true {
                            "completed"
                        } else {
                            "failed"
                        };
                        self.tool_update(
                            id,
                            Some(field(payload, "toolName")),
                            Some(status),
                            None,
                            Some(content_preview(&result["content"], TOOL_OUTPUT_LIMIT)),
                            step,
                        );
                    }
                    "error" => self.tool_update(
                        id,
                        Some(field(payload, "toolName")),
                        Some("failed"),
                        None,
                        Some(content_preview(&payload["error"], TOOL_OUTPUT_LIMIT)),
                        step,
                    ),
                    _ => {}
                }
            }
            "turn.failed" => {
                self.zcode.error = Some(short(&super::diagnostics::clean_bounded(field(payload, "error"))));
            }
            "turn.completed" => {
                // A late completed frame from an earlier input never ends this run.
                let input = field(payload, "inputId");
                if !input.is_empty() && input != format!("pandacode-{}", self.zcode.next_input) {
                    return Ok(());
                }
                let usage = &payload["usage"];
                let used = usage["inputTokens"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_add(usage["cacheReadTokens"].as_u64().unwrap_or(0));
                let used = if used > 0 {
                    used
                } else {
                    payload["tokenCount"].as_u64().unwrap_or(0)
                };
                self.usage(used, self.zcode.context_window, step);
                match field(payload, "resultType") {
                    "success" => step.done = true,
                    "cancelled" => return Err("ZCode run was stopped".into()),
                    other => {
                        let held = self.zcode.error.take();
                        return Err(held.unwrap_or_else(|| match other {
                            "error_max_turns" => "ZCode reached its turn limit".into(),
                            "error_max_budget" => "ZCode reached its budget limit".into(),
                            "error_max_tool_calls" => "ZCode reached its tool-call limit".into(),
                            _ => "ZCode could not finish the response".into(),
                        }));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// First frame of the session chain: create (or resume) answers, then the
    /// model/effort/subscribe writes queue up in order.
    fn zcode_created(&mut self, value: &Value, step: &mut Step) -> Result<(), String> {
        let result = &value["result"];
        self.remote_id = string(&result["session"], "sessionId");
        if self.remote_id.is_empty() {
            return Err("ZCode did not return a session ID".into());
        }
        step.events
            .push(self.event("session", self.remote_id.clone(), None));
        let settings = &result["settings"];
        let current = &result["session"]["model"];
        self.zcode.context_window = context_window_of(settings, current);
        let wanted = mode(&self.config.mode);
        if settings["mode"]["current"].as_str() != Some(wanted) {
            self.zcode.requested_mode = Some(wanted);
            step.write.push(json!({
                "id": ID_MODE, "method": "session/setMode",
                "params": {"sessionId": self.remote_id, "mode": wanted},
            }));
        }
        let catalog = &settings["model"]["available"];
        let wanted = &self.config.model;
        // An empty 3.19+ catalog with no session model cannot answer a send,
        // whether the selection is `default` or a saved model id.
        let catalog_empty = if self.config.resume_id.is_some() {
            catalog.as_array().is_some_and(Vec::is_empty)
        } else { catalog.as_array().map_or(true, Vec::is_empty) };
        if !has_session_model(result) && catalog_empty {
            return Err(NO_MODELS.into());
        }
        let mut thought = self.config.reasoning_effort.clone();
        if !wanted.is_empty() && wanted != "default" {
            let entry = catalog
                .as_array()
                .into_iter()
                .flatten()
                .find(|entry| field(entry, "label") == *wanted);
            let mut reference = match entry {
                Some(entry) => entry["ref"].clone(),
                // A custom model id rides the session's current provider.
                None => json!({"providerId": current["providerId"], "modelId": wanted}),
            };
            // The selection itself must carry the reasoning level: the server
            // validates `options.reasoningLevel` inside setModel and rejects the
            // frame without it, so the later setThoughtLevel cannot repair it.
            // An effort this model does not list falls to its default, and is
            // not sent to setThoughtLevel either, which would fail the run.
            if let Some(entry) = entry {
                thought = thought.filter(|effort| lists_level(entry, effort));
                let default = entry["reasoning"]["defaultLevel"]
                    .as_str()
                    .filter(|level| lists_level(entry, level));
                if let Some(level) = thought.as_deref().or(default) {
                    reference["options"] = json!({"reasoningLevel": level});
                }
            }
            self.zcode.requested_model = Some((
                string(&reference, "providerId"),
                string(&reference, "modelId"),
            ));
            step.write.push(json!({
                "id": ID_MODEL, "method": "session/setModel",
                "params": {"sessionId": self.remote_id, "model": reference},
            }));
        }
        if let Some(effort) = thought {
            step.write.push(json!({
                "id": ID_THOUGHT, "method": "session/setThoughtLevel",
                "params": {"sessionId": self.remote_id, "thoughtLevel": effort},
            }));
            self.zcode.requested_thought = Some(effort);
        }
        step.write.push(json!({
            "id": ID_SUBSCRIBE, "method": "session/subscribe",
            "params": {"sessionId": self.remote_id, "deliveryKind": "desktop-continuous"},
        }));
        Ok(())
    }

    /// Writes the prompt (or a steered next turn) as `session/send`.
    pub(super) fn zcode_prompt(&mut self, text: String, step: &mut Step) {
        self.zcode.next_input += 1;
        step.write.push(json!({
            "id": FIRST_PROMPT_ID - 1 + self.zcode.next_input,
            "method": "session/send",
            "params": {
                "sessionId": self.remote_id,
                "content": text,
                "inputId": format!("pandacode-{}", self.zcode.next_input),
            },
        }));
        self.phase = 1;
    }
}

/// Permission answers reuse the option's own `response` object, which carries
/// the exact decision (and any rule updates) the server offered for that button.
pub(super) fn permission_decision(request: &Value, approved: bool) -> Value {
    let options = request["params"]["options"].as_array();
    let kinds: &[&str] = if approved {
        &["allow_once", "allow_always"]
    } else {
        &["deny_once", "deny_always", "reject_once", "reject_always"]
    };
    let selected = kinds.iter().find_map(|kind| {
        options.and_then(|options| {
            options
                .iter()
                .find(|option| option["kind"].as_str() == Some(*kind))
        })
    });
    let decision = selected
        .map(|option| option["response"].clone())
        .unwrap_or_else(|| {
            json!({
                "decision": if approved { "allow" } else { "deny" },
                "reason": if approved { "Approved" } else { "Declined by the user" },
            })
        });
    json!({"id": request["id"], "result": decision})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r23_nested_auth_codes_and_digit_boundaries_are_classified() {
        assert_eq!(rpc_error(&json!({"message":"Request failed","data":{"error":{"type":"AuthenticationError"}}})), SIGN_IN);
        assert_eq!(rpc_error(&json!({"message":"401Unauthorized"})), SIGN_IN);
        assert_eq!(rpc_error(&json!({"message":"Request failed","data":{"error":{"type":"QuotaExceededError"}}})), "Request failed");
        for key in ["details", "cause"] {
            assert_eq!(rpc_error(&json!({"message":"Request failed","data":{key:{"code":"AUTH_REQUIRED"}}})), SIGN_IN);
        }
    }

    #[test]
    fn r21_guidance_excludes_stderr_noise_and_default_cache_expires() {
        for message in [SIGN_IN, NO_MODELS] {
            assert_eq!(discovery_error(message.to_owned(), "Node warning\nError: irrelevant"), message);
        }
        assert!(discovery_error("Discovery failed".to_owned(), "Error: real cause").contains("real cause"));
        let path = PathBuf::from("r21-default-cache-test");
        clear_default_cache();
        let epoch = default_epoch().load(std::sync::atomic::Ordering::Relaxed);
        store_default(&path, epoch, &[ModelInfo::default_choice()]);
        let now = std::time::Instant::now();
        assert_eq!(default_models(&path, now).unwrap().len(), 1);
        assert!(default_models(&path, now + Duration::from_secs(61)).is_none());
        store_default(&path, epoch, &[ModelInfo::default_choice()]);
        super::super::invalidate_catalog("zcode");
        assert!(default_models(&path, now).is_none());
        store_default(&path, epoch, &[ModelInfo::default_choice()]);
        assert!(default_models(&path, now).is_none(), "in-flight invalidated discovery repopulated cache");
        let epoch = default_epoch().load(std::sync::atomic::Ordering::Relaxed);
        store_default(&path, epoch, &[ModelInfo::default_choice()]);
        store_default(&path, epoch, &[ModelInfo::default_choice(), ModelInfo::default_choice()]);
        assert!(default_models(&path, now).is_none());
        let folder = AgentTemp::create_in(&std::env::temp_dir()).unwrap();
        let executable = folder.0.join("zcode-cache-test");
        std::fs::write(&executable, b"first").unwrap();
        store_default(&executable, epoch, &[ModelInfo::default_choice()]);
        assert!(default_models(&executable, std::time::Instant::now()).is_some());
        std::fs::write(&executable, b"changed executable").unwrap();
        assert!(default_models(&executable, std::time::Instant::now()).is_none());
        store_default(&executable, epoch, &[ModelInfo::default_choice()]);
        assert_eq!(default_cache().lock().unwrap().keys().filter(|key| key.0 == executable).count(), 1);
        let expired = folder.0.join("expired");
        let expire_entry = || {
            default_cache().lock().unwrap().insert(default_key(&expired), (std::time::Instant::now() - Duration::from_secs(61), vec![ModelInfo::default_choice()]));
        };
        expire_entry();
        default_models(&executable, std::time::Instant::now());
        assert!(!default_cache().lock().unwrap().keys().any(|key| key.0 == expired));
        expire_entry();
        store_default(&executable, epoch, &[ModelInfo::default_choice()]);
        assert!(!default_cache().lock().unwrap().keys().any(|key| key.0 == expired));
        for index in 0..20 { store_default(&folder.0.join(index.to_string()), epoch, &[ModelInfo::default_choice()]); }
        assert_eq!(default_cache().lock().unwrap().len(), 16);
        clear_default_cache();
    }

    #[test]
    fn r21_camel_auth_codes_preserve_transport_and_quota_errors() {
        for data in [json!({"type":"AuthenticationError"}), json!({"code":"UnauthorizedError"})] {
            assert_eq!(rpc_error(&json!({"message":"Request failed","data":data})), SIGN_IN);
        }
        assert_eq!(rpc_error(&json!({"message":"Request failed","data":{"type":"QuotaExceededError"}})), "Request failed");
        assert_eq!(rpc_error(&json!({"message":"AuthError: connect ECONNREFUSED"})), "AuthError: connect ECONNREFUSED");
    }

    #[test]
    fn r20_rpc_error_caps_oversized_frames_before_rendering() {
        let message = format!("Error: {}SECRET999", "x".repeat(300000));
        assert_eq!(rpc_error(&json!({"message":message})), "[Line over 64 KB omitted]");
        assert_eq!(rpc_error(&json!({"message":"Request failed","data":{"message":"x".repeat(300000)}})), "Request failed");
        let (mut protocol, _) = created();
        subscribe_acked(&mut protocol);
        protocol.receive(event("turn.failed", json!({"error":format!("{}SECRET999", "x".repeat(70000))}))).unwrap();
        assert_eq!(protocol.zcode.error.as_deref(), Some("[Line over 64 KB omitted]"));
    }

    #[test]
    fn r19_auth_transport_errors_keep_their_network_cause() {
        for message in ["Auth error: connect ECONNREFUSED", "Auth failed: connect ECONNREFUSED", "OAuth request failed: ETIMEDOUT"] {
            assert_eq!(rpc_error(&serde_json::json!({"message":message})), message);
        }
        for message in ["Authentication failed", "Auth token expired", "Unauthorized", "Request failed with status code 401"] {
            assert_eq!(rpc_error(&serde_json::json!({"message":message})), SIGN_IN);
        }
        assert_eq!(rpc_error(&serde_json::json!({"message":"Request failed","data":"AUTH_REQUIRED"})), SIGN_IN);
        assert_eq!(rpc_error(&serde_json::json!({"message":"Auth failed","data":{"message":"connection refused"}})), "Auth failed");
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn bundled_candidates_cover_the_desktop_app_bundle() {
        let expected = if cfg!(target_os = "macos") {
            "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"
        } else {
            "/opt/ZCode/resources/glm/zcode.cjs"
        };
        assert!(bundled_candidates()
            .iter()
            .any(|path| path == Path::new(expected)), "missing {expected}");
    }

    /// Recorded from the CLI bundled with ZCode.app (user-agent ZCode/3.16.3);
    /// session IDs, models and paths anonymized, catalog shortened to one entry.
    fn snapshot() -> Value {
        json!({
            "protocol": {"name": "ZCode Protocol", "version": 1},
            "session": {
                "createdAt": 1792931010147_u64, "mode": "build",
                "model": {"providerId": "omnirouter", "modelId": "zcproxy/GLM-5.3"},
                "sessionId": "sess_540e3d16-8f19-449f-8576-7b0133fea47a",
                "sessionKind": "interactive", "status": "idle", "title": "",
            },
            "settings": {
                "mode": {"current": "build"},
                "model": {"available": [
                    {"ref": {"providerId": "omnirouter", "modelId": "zcproxy/GLM-5.3"},
                     "label": "zcproxy/GLM-5.3", "providerLabel": "OmniRouter",
                     "contextWindow": 200000, "maxOutputTokens": 131072,
                     "reasoning": {"levels": [{"value": "low"}, {"value": "high"}, {"value": "max"}],
                                   "defaultLevel": "max"}}
                ]},
                "thoughtLevel": {"enabled": true, "current": "max",
                                 "available": [{"value": "low"}, {"value": "high"}, {"value": "max"}]},
            },
            "messages": [],
        })
    }

    fn event(kind: &str, payload: Value) -> Value {
        json!({"method": "session/event", "params": {
            "type": kind, "payload": payload, "seq": 1,
            "sessionId": "sess_540e3d16-8f19-449f-8576-7b0133fea47a",
            "turnId": "turn_test", "eventId": "evt", "timestamp": 1,
        }})
    }

    fn created() -> (Protocol, Step) {
        let mut p = Protocol::new(super::super::tests::config("zcode"));
        p.config.cwd = PathBuf::from("/tmp");
        let request = p.initial();
        assert_eq!(request["method"], "session/create");
        assert_eq!(request["params"]["workspace"]["workspaceKey"], "/tmp");
        let step = p
            .receive(json!({"id": ID_CREATE, "result": snapshot()}))
            .unwrap();
        (p, step)
    }

    fn subscribe_acked(p: &mut Protocol) -> Step {
        p.receive(json!({"id": ID_SUBSCRIBE, "result": {"eventSeq": 0, "events": []}}))
            .unwrap()
    }

    #[test]
    fn create_chains_model_effort_and_subscribe_before_prompting() {
        let (mut p, _) = created();
        p.config.model = "zcproxy/GLM-5.3".into();
        p.config.reasoning_effort = Some("high".into());
        let step = p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        assert_eq!(step.events[0].kind, "session");
        assert_eq!(step.write.len(), 3);
        assert_eq!(step.write[0]["method"], "session/setModel");
        assert_eq!(step.write[0]["params"]["model"]["modelId"], "zcproxy/GLM-5.3");
        assert_eq!(step.write[0]["params"]["model"]["options"]["reasoningLevel"], "high");
        assert_eq!(step.write[1]["method"], "session/setThoughtLevel");
        assert_eq!(step.write[1]["params"]["thoughtLevel"], "high");
        assert_eq!(step.write[2]["method"], "session/subscribe");

        let step = p.receive(json!({"id": ID_MODEL, "result": snapshot()})).unwrap();
        assert!(step.write.is_empty());
        assert!(p.receive(json!({"id": ID_THOUGHT, "result": snapshot()})).is_err(), "thought not applied yet");
        let mut applied = snapshot();
        applied["settings"]["thoughtLevel"]["current"] = json!("high");
        let step = p.receive(json!({"id": ID_THOUGHT, "result": applied})).unwrap();
        assert!(step.write.is_empty());
        let prompt = subscribe_acked(&mut p);
        assert_eq!(prompt.write[0]["method"], "session/send");
        assert_eq!(prompt.write[0]["params"]["inputId"], "pandacode-1");
        assert_eq!(p.phase, 1);
    }

    #[test]
    fn set_model_without_an_effort_sends_the_catalog_default_level() {
        let (mut p, _) = created();
        p.config.model = "zcproxy/GLM-5.3".into();
        let step = p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        assert_eq!(step.write[0]["params"]["model"]["options"]["reasoningLevel"], "max");

        // A custom id has no catalog entry to default from; the bare
        // reference stands and the server validates it.
        let mut custom = super::super::tests::config("zcode");
        custom.cwd = PathBuf::from("/tmp");
        custom.model = "pandacode/custom-model".into();
        let mut p = Protocol::new(custom);
        assert_eq!(p.initial()["method"], "session/create");
        let step = p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        assert_eq!(step.write[0]["method"], "session/setModel");
        assert!(step.write[0]["params"]["model"].get("options").is_none());
    }

    #[test]
    fn set_model_sends_an_explicit_effort_only_when_the_catalog_lists_it() {
        let chain = |model: &str, effort: &str, snapshot: Value| {
            let mut config = super::super::tests::config("zcode");
            config.cwd = PathBuf::from("/tmp");
            config.model = model.into();
            config.reasoning_effort = Some(effort.into());
            let mut p = Protocol::new(config);
            p.receive(json!({"id": ID_CREATE, "result": snapshot})).unwrap().write
        };
        let glm = "zcproxy/GLM-5.3";

        let write = chain(glm, "low", snapshot());
        assert_eq!(write[0]["params"]["model"]["options"]["reasoningLevel"], "low");
        assert_eq!(write[1]["params"]["thoughtLevel"], "low");

        // An unlisted effort takes the model's default, and setThoughtLevel is
        // skipped: the server would not apply it and the run would fail.
        let write = chain(glm, "medium", snapshot());
        assert_eq!(write[0]["params"]["model"]["options"]["reasoningLevel"], "max");
        assert_eq!(write[1]["method"], "session/subscribe");

        // A model with no levels has no default to fall back to.
        let mut levelless = snapshot();
        levelless["settings"]["model"]["available"][0]["reasoning"] = json!({"levels": []});
        let write = chain(glm, "high", levelless);
        assert!(write[0]["params"]["model"].get("options").is_none());
        assert_eq!(write[1]["method"], "session/subscribe");

        // A default the entry does not list is not sent either.
        let mut stale = snapshot();
        stale["settings"]["model"]["available"][0]["reasoning"]["defaultLevel"] = json!("ultra");
        let write = chain(glm, "medium", stale);
        assert!(write[0]["params"]["model"].get("options").is_none());

        // A custom id has no entry to check: no options, setThoughtLevel still runs.
        let write = chain("pandacode/custom-model", "high", snapshot());
        assert!(write[0]["params"]["model"].get("options").is_none());
        assert_eq!(write[1]["params"]["thoughtLevel"], "high");
    }

    #[test]
    fn default_model_sends_directly_and_custom_ids_ride_the_current_provider() {
        let (mut p, step) = created();
        assert_eq!(step.write.len(), 1, "no model or effort is configured");
        assert_eq!(step.write[0]["method"], "session/subscribe");
        subscribe_acked(&mut p);
        let mut custom = super::super::tests::config("zcode");
        custom.cwd = PathBuf::from("/tmp");
        custom.model = "pandacode/custom-model".into();
        let mut p = Protocol::new(custom);
        assert_eq!(p.initial()["method"], "session/create");
        let step = p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        assert_eq!(step.write[0]["params"]["model"]["providerId"], "omnirouter");
        assert_eq!(step.write[0]["params"]["model"]["modelId"], "pandacode/custom-model");
    }

    #[test]
    fn resume_reuses_the_saved_session() {
        let mut config = super::super::tests::config("zcode");
        config.resume_id = Some("sess_saved".into());
        let p = Protocol::new(config);
        let request = p.initial();
        assert_eq!(request["method"], "session/resume");
        assert_eq!(request["params"]["sessionId"], "sess_saved");
        assert_eq!(p.cancel()["method"], "session/stop");
        // Protocol::new pre-seeds the resume id, so a stop before the snapshot
        // already names the saved session.
        assert_eq!(p.cancel()["params"]["sessionId"], "sess_saved");
    }

    #[test]
    fn a_dead_resume_id_falls_back_to_a_fresh_create() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        config.resume_id = Some("sess_gone".into());
        let mut p = Protocol::new(config);
        assert_eq!(p.initial()["method"], "session/resume");
        let step = p
            .receive(json!({"id": ID_CREATE, "error": {"code": -32004,
                            "message": "Session not found: sess_gone"}}))
            .unwrap();
        assert_eq!(step.write[0]["method"], "session/create");
        assert!(p.config.resume_id.is_none(), "the dead id is dropped");

        // The fresh create answers like any other and runs the chain.
        let step = p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        assert_eq!(step.events[0].kind, "session");
        assert_eq!(step.write[0]["method"], "session/subscribe");

        // A create's own error is never swallowed into another create.
        let Err(message) = p
            .receive(json!({"id": ID_CREATE, "error": {"code": -32004,
                            "message": "Session not found: sess_540e3d16-8f19-449f-8576-7b0133fea47a"}}))
        else {
            panic!("a fresh create's error must fail the run");
        };
        assert_eq!(message, "Session not found: sess_540e3d16-8f19-449f-8576-7b0133fea47a");
    }

    #[test]
    fn a_dead_resume_id_reports_the_lost_history() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        config.resume_id = Some("sess_gone".into());
        let mut p = Protocol::new(config);
        let step = p
            .receive(json!({"id": ID_CREATE, "error": {"code": -32004,
                            "message": "Session not found: sess_gone"}}))
            .unwrap();
        assert_eq!(step.events.len(), 1);
        assert_eq!(step.events[0].kind, "status");
        assert!(step.events[0].text.contains("without its history"), "{}", step.events[0].text);
    }

    #[test]
    fn recorded_stream_and_tool_frames_drive_the_shared_transcript() {
        let (mut p, _) = created();
        subscribe_acked(&mut p);
        let reasoning = p
            .receive(event("model.streaming", json!({"assistantMessageId": "msg_a", "delta": "th", "kind": "reasoning_delta"})))
            .unwrap();
        assert!(reasoning.events.iter().any(|e| e.kind == "status" && e.text == "Reasoning"));
        let text = p
            .receive(event("model.streaming", json!({"assistantMessageId": "msg_a", "delta": "Hello", "kind": "text_delta"})))
            .unwrap();
        assert!(text.events.iter().any(|e| e.kind == "text" && e.text == "Hello"));
        let more = p
            .receive(event("model.streaming", json!({"assistantMessageId": "msg_a", "delta": " world", "kind": "text_delta"})))
            .unwrap();
        assert_eq!(more.events.iter().filter(|e| e.kind == "text").map(|e| e.text.as_str()).collect::<String>(), " world");
        let started = p
            .receive(event("tool.updated", json!({"toolCallId": "call_1", "toolName": "Bash", "kind": "started", "readOnly": false})))
            .unwrap();
        let tool = started.events.iter().find_map(|e| e.tool.as_ref()).unwrap();
        assert_eq!(tool.status, "running");
        let done = p
            .receive(event("tool.updated", json!({"toolCallId": "call_1", "toolName": "Bash", "kind": "result",
                "result": {"success": true, "content": "(Bash completed with no output)"}, "duration": 1275})))
            .unwrap();
        let tool = done.events.iter().find_map(|e| e.tool.as_ref()).unwrap();
        assert_eq!(tool.status, "completed");
        assert!(tool.output.contains("no output"));
    }

    #[test]
    fn recorded_turn_completed_finishes_with_usage_and_reports_failures() {
        let (mut p, _) = created();
        subscribe_acked(&mut p);
        let completed = p
            .receive(event("turn.completed", json!({
                "response": "ok", "tokenCount": 49030,
                "usage": {"inputTokens": 49003, "outputTokens": 27, "totalTokens": 49030, "cacheReadTokens": 64},
                "resultType": "success", "duration": 17944, "inputId": "pandacode-1",
            })))
            .unwrap();
        assert!(completed.done);
        let usage = completed.events.iter().find(|e| e.kind == "usage").unwrap();
        assert_eq!(usage.data.as_ref().unwrap()["usedTokens"], 49067);

        // A stale completed frame from an earlier input never ends the run.
        let (mut p, _) = created();
        subscribe_acked(&mut p);
        let mut stale = event("turn.completed", json!({"resultType": "success", "inputId": "pandacode-9"}));
        stale["params"]["payload"]["tokenCount"] = json!(1);
        let step = p.receive(stale).unwrap();
        assert!(!step.done);

        let (mut p, _) = created();
        subscribe_acked(&mut p);
        p.receive(event("turn.failed", json!({"error": "429 rate limited", "turnPhase": "model"}))).unwrap();
        let Err(failed) = p.receive(event(
            "turn.completed",
            json!({"resultType": "error_during_execution", "inputId": "pandacode-1"}),
        )) else {
            panic!("an errored turn must fail the run");
        };
        assert_eq!(failed, "429 rate limited");
        let Err(stopped) = p.receive(event(
            "turn.completed",
            json!({"resultType": "cancelled", "inputId": "pandacode-1"}),
        )) else {
            panic!("a cancelled turn must fail the run");
        };
        assert_eq!(stopped, "ZCode run was stopped");
    }

    #[test]
    fn permissions_round_trip_through_the_offered_response() {
        let (mut p, _) = created();
        subscribe_acked(&mut p);
        let request = p
            .receive(json!({"id": "perm_1", "method": "interaction/requestPermission", "params": {
                "requestId": "perm_1", "sessionId": "sess_test", "toolCallId": "call_1",
                "toolName": "Bash", "reason": "High risk tools require explicit approval",
                "riskLevel": "high", "input": {"command": "printf 'ok' > out.txt"},
                "options": [
                    {"optionId": "allow_once", "kind": "allow_once", "name": "Allow once",
                     "response": {"decision": "allow", "reason": "Approved once"}},
                    {"optionId": "deny_once", "kind": "deny_once", "name": "Deny",
                     "response": {"decision": "deny", "reason": "Denied"}},
                ],
            }}))
            .unwrap();
        assert!(request.events.iter().any(|e| e.kind == "approval"));
        let id = request.events.iter().find(|e| e.kind == "approval").unwrap().request_id.clone().unwrap();
        assert_eq!(
            p.approve(&id, true).unwrap(),
            json!({"id": "perm_1", "result": {"decision": "allow", "reason": "Approved once"}}),
        );
        let request = p
            .receive(json!({"id": "perm_2", "method": "interaction/requestPermission", "params": {
                "requestId": "perm_2", "sessionId": "sess_test", "toolCallId": "call_2",
                "toolName": "Bash", "reason": "risk", "riskLevel": "high", "input": {},
                "options": [{"optionId": "allow_once", "kind": "allow_once", "name": "Allow once",
                             "response": {"decision": "allow"}}],
            }}))
            .unwrap();
        let id = request.events.iter().find(|e| e.kind == "approval").unwrap().request_id.clone().unwrap();
        let denied = p.approve(&id, false).unwrap();
        assert_eq!(denied["result"]["decision"], "deny", "falls back to a plain denial");
        // Interactive questions decline for now; unknown reverse requests get -32601.
        let question = p
            .receive(json!({"id": "q_1", "method": "interaction/requestUserInput", "params": {"requestId": "q_1"}}))
            .unwrap();
        assert_eq!(question.write[0]["result"]["action"], "decline");
        let unknown = p
            .receive(json!({"id": "r_1", "method": "session/requestRuntimePreferences", "params": {}}))
            .unwrap();
        assert_eq!(unknown.write[0]["error"]["code"], -32601);
    }

    #[test]
    fn steered_messages_wait_for_the_next_turn() {
        let (mut p, _) = created();
        subscribe_acked(&mut p);
        let (tx, mut reply) = tokio::sync::oneshot::channel();
        let step = p.steer("steer-1".into(), "also check tests".into(), tx);
        assert!(step.write.is_empty(), "zcode holds steers for the next turn");
        assert_eq!(reply.try_recv().unwrap().unwrap()["mode"], "next-turn");
        // The completed turn re-opens the run and writes the steered turn itself.
        let turn = p
            .receive(event("turn.completed", json!({"resultType": "success", "inputId": "pandacode-1"})))
            .unwrap();
        assert!(!turn.done);
        assert_eq!(turn.write[0]["method"], "session/send");
        assert_eq!(turn.write[0]["params"]["content"], "also check tests");
        assert_eq!(turn.write[0]["params"]["inputId"], "pandacode-2");
        let ack = p.receive(json!({"id": 7, "result": {"accepted": true}})).unwrap();
        assert!(ack.write.is_empty());
        let done = p
            .receive(event("turn.completed", json!({"resultType": "success", "inputId": "pandacode-2"})))
            .unwrap();
        assert!(done.done);
    }

    #[test]
    fn resumed_sessions_get_the_selected_mode_reapplied() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        config.resume_id = Some("sess_saved".into());
        config.mode = "plan".into();
        let mut p = Protocol::new(config);
        assert_eq!(p.initial()["method"], "session/resume");
        let step = p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        // The saved session ran as build; Plan re-applies before subscribing.
        let set_mode = step.write.iter()
            .find(|frame| frame["method"] == "session/setMode")
            .expect("setMode on resume");
        assert_eq!(set_mode["params"]["mode"], "plan");
        assert!(p.receive(json!({"id": ID_MODE, "result": snapshot()})).is_err(), "mode not applied yet");
        let mut applied = snapshot();
        applied["settings"]["mode"]["current"] = json!("plan");
        let step = p.receive(json!({"id": ID_MODE, "result": applied})).unwrap();
        assert!(step.write.iter().all(|frame| frame["method"] != "session/setMode"));
        // A create whose snapshot already matches sends no setMode.
        let (mut p, _) = created();
        subscribe_acked(&mut p);
    }

    #[test]
    fn full_access_answers_policy_requests_with_the_offered_once_allow() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        config.mode = "full".into();
        let mut p = Protocol::new(config);
        p.initial();
        p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        let step = p
            .receive(json!({"id": "perm_1", "method": "interaction/requestPermission", "params": {
                "requestId": "perm_1", "sessionId": "sess_test", "toolCallId": "call_1",
                "toolName": "Bash", "reason": "Organization policy", "riskLevel": "medium",
                "input": {"command": "ls"},
                "options": [
                    {"optionId": "allow_once", "kind": "allow_once", "name": "Allow once",
                     "response": {"decision": "allow", "reason": "Approved once"}},
                    {"optionId": "allow_project", "kind": "allow_always", "name": "Always",
                     "response": {"decision": "allow", "permissionUpdates": [{"type": "addRules"}]}},
                ],
            }}))
            .unwrap();
        assert!(!step.events.iter().any(|e| e.kind == "approval"), "Full access does not prompt");
        assert_eq!(step.write[0]["result"]["decision"], "allow");
        assert!(
            step.write[0]["result"].get("permissionUpdates").is_none(),
            "never a standing grant",
        );
    }

    #[test]
    fn full_access_asks_when_only_a_lasting_allow_is_offered() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        config.mode = "full".into();
        let mut p = Protocol::new(config);
        p.initial();
        p.receive(json!({"id": ID_CREATE, "result": snapshot()})).unwrap();
        let step = p
            .receive(json!({"id": "perm_1", "method": "interaction/requestPermission", "params": {
                "requestId": "perm_1", "sessionId": "sess_test", "toolCallId": "call_1",
                "toolName": "Bash", "reason": "Organization policy", "riskLevel": "medium",
                "input": {"command": "ls"},
                "options": [
                    {"optionId": "allow_project", "kind": "allow_always", "name": "Always",
                     "response": {"decision": "allow", "permissionUpdates": [{"type": "addRules"}]}},
                ],
            }}))
            .unwrap();
        assert!(step.write.is_empty(), "never granted automatically");
        let approval = step.events.iter().find(|e| e.kind == "approval").expect("asks instead");
        let data = approval.data.as_ref().unwrap();
        assert_eq!(data[super::super::LASTING_ONLY], true);
        assert_eq!(data[super::super::LASTING_DECLINABLE], true);
        // The automatic decline answers with a plain denial, no rule updates.
        let id = approval.request_id.clone().unwrap();
        let denied = p.approve(&id, false).unwrap();
        assert_eq!(denied["result"]["decision"], "deny");
        assert!(denied["result"].get("permissionUpdates").is_none());
    }

    #[test]
    fn catalog_effort_values_are_validated_before_use() {
        let mut mixed = snapshot();
        mixed["settings"]["model"]["available"][0]["reasoning"]["levels"] = json!([
            {"label": "no value"}, {"value": "高"}, {"value": "with space"}, {"value": "max"},
        ]);
        mixed["settings"]["model"]["available"][0]["reasoning"]["defaultLevel"] = json!("高");
        let models = parse_models(&mixed).unwrap();
        assert_eq!(
            models[1]
                .reasoning_efforts
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            ["max"],
        );
        assert_eq!(models[1].default_reasoning_effort.as_deref(), None);
    }

    #[test]
    fn parse_models_reads_labels_efforts_and_context_windows() {
        let models = parse_models(&snapshot()).unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "default");
        assert_eq!(models[1].id, "zcproxy/GLM-5.3");
        assert_eq!(models[1].description, "OmniRouter");
        assert_eq!(models[1].context_window, Some(200000));
        assert_eq!(
            models[1]
                .reasoning_efforts
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            ["low", "high", "max"]
        );
        assert_eq!(models[1].default_reasoning_effort.as_deref(), Some("max"));
        let mut broken = snapshot();
        broken["settings"]["model"] = json!("not-a-catalog");
        assert!(parse_models(&broken).is_err());
    }

    #[test]
    fn an_empty_catalog_reports_the_desktop_managed_plan_guidance() {
        let mut empty = snapshot();
        empty["settings"]["model"]["available"] = json!([]);
        // A session model still serves the default choice.
        let models = parse_models(&empty).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "default");
        let session_model = model_text(empty["session"]["model"]["modelId"].as_str(), "", 160);
        assert!(!session_model.is_empty());
        assert_eq!(models[0].description, format!("Uses ZCode's active session model ({session_model})."));
        empty["session"]["model"] = Value::Null;
        assert_eq!(parse_models(&empty).unwrap_err(), NO_MODELS);
        empty["session"].as_object_mut().unwrap().remove("model");
        assert_eq!(parse_models(&empty).unwrap_err(), NO_MODELS);
        // Listed entries that are all unusable are a broken catalog, not a missing plan.
        let mut invalid = snapshot();
        invalid["settings"]["model"]["available"] = json!([{"label": ""}, {"providerLabel": "x"}]);
        assert_eq!(parse_models(&invalid).unwrap_err(), "Invalid ZCode model catalog");
    }

    #[test]
    fn a_default_send_on_an_empty_catalog_fails_fast() {
        let create = |model: &str, result: Value| {
            let mut config = super::super::tests::config("zcode");
            config.cwd = PathBuf::from("/tmp");
            config.model = model.into();
            let mut p = Protocol::new(config);
            p.initial();
            p.receive(json!({"id": ID_CREATE, "result": result})).err()
        };
        let mut empty = snapshot();
        empty["settings"]["model"]["available"] = json!([]);
        // A session model still serves the default choice.
        assert_eq!(create("default", empty.clone()), None);
        // With no session model, neither the default nor a saved model id can send.
        empty["session"]["model"] = Value::Null;
        assert_eq!(create("default", empty.clone()).as_deref(), Some(NO_MODELS));
        assert_eq!(create("GLM-5.3", empty.clone()).as_deref(), Some(NO_MODELS));
        empty["session"].as_object_mut().unwrap().remove("model");
        assert_eq!(create("default", empty.clone()).as_deref(), Some(NO_MODELS));
        assert_eq!(create("GLM-5.3", empty).as_deref(), Some(NO_MODELS));
    }

    #[test]
    fn discovery_failures_keep_a_clean_redacted_stderr_cause() {
        let result = super::super::diagnostics::failure(
            "ZCode exited before returning models",
            "\u{1b}[31mError: config failed\u{1b}[0m\nAuthorization: Bearer topsecret\napiKey: sk-secret",
        );
        assert!(result.starts_with("ZCode exited before returning models\nError: config failed"), "{result}");
        assert!(!result.contains('\u{1b}'), "{result}");
        assert!(!result.contains("topsecret"), "{result}");
        assert!(!result.contains("sk-secret"), "{result}");
        // The guidance passes through unchanged when stderr has nothing to add.
        assert_eq!(super::super::diagnostics::failure(NO_MODELS, ""), NO_MODELS);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_bundled_candidates_use_native_separators() {
        for path in bundled_candidates() {
            let text = path.to_string_lossy();
            assert!(!text.contains('/'), "{text}");
            assert!(text.ends_with(r"resources\glm\zcode.cjs"), "{text}");
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_bundled_candidates_ignore_relative_roots() {
        use std::ffi::OsStr;
        let found = bundled_candidates_for_windows(
            Some(OsStr::new(r"C:\Users\Person\AppData\Local")),
            Some(OsStr::new(r"C:\Program Files")),
        );
        assert_eq!(
            found,
            [
                r"C:\Users\Person\AppData\Local\Programs\ZCode\resources\glm\zcode.cjs",
                r"C:\Users\Person\AppData\Local\Programs\zcode\resources\glm\zcode.cjs",
                r"C:\Program Files\ZCode\resources\glm\zcode.cjs",
                r"C:\Program Files\zcode\resources\glm\zcode.cjs",
            ]
            .map(PathBuf::from)
        );
        for relative in [
            "AppData",
            r".\Local",
            r"..\Program Files",
            r"\NoDrive",
            "C:relative",
            r"C:\Users\me\AppData\Local\..\evil",
            r"C:\Program Files\..\evil",
        ] {
            let found = bundled_candidates_for_windows(Some(OsStr::new(relative)), Some(OsStr::new(relative)));
            assert!(found.is_empty(), "{relative}: {found:?}");
        }
        // One relative root does not drop the other, absolute one.
        let found = bundled_candidates_for_windows(Some(OsStr::new("relative")), Some(OsStr::new(r"D:\Apps")));
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|path| path.starts_with(r"D:\Apps")), "{found:?}");
        assert!(bundled_candidates_for_windows(None, Some(OsStr::new(""))).is_empty());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn windows_bundled_candidates_ignore_relative_roots() {
        use std::ffi::OsStr;
        // Unix hosts judge absoluteness by `/`, which is enough to see relative values dropped.
        let found = bundled_candidates_for_windows(Some(OsStr::new("relative")), Some(OsStr::new("/apps")));
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|path| path.starts_with("/apps")), "{found:?}");
        assert!(bundled_candidates_for_windows(Some(OsStr::new("a")), Some(OsStr::new("b"))).is_empty());
        // An absolute root that climbs out with `..` is dropped like a relative one.
        let found = bundled_candidates_for_windows(Some(OsStr::new("/apps/../evil")), Some(OsStr::new("/apps")));
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|path| path.starts_with("/apps") && !path.to_string_lossy().contains("..")), "{found:?}");
        assert!(bundled_candidates_for_windows(Some(OsStr::new("/apps/../evil")), Some(OsStr::new("/apps/.."))).is_empty());
    }

    #[test]
    fn discovery_workspace_fails_closed_without_a_private_folder() {
        let root = std::env::temp_dir().join(format!("pandacode-zcode-ws-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(discovery_workspace(None).err().as_deref(), Some("Could not locate PandaCode's app data folder for ZCode discovery. Check your user profile permissions and try again."));
        // A file where the app-data folder should be: nothing can be created under it.
        let blocking_file = root.join("not-a-dir");
        std::fs::write(&blocking_file, b"x").unwrap();
        let error = discovery_workspace(Some(&blocking_file)).err().unwrap();
        assert!(error.contains(&blocking_file.join(AGENT_TEMP_DIR).display().to_string()), "{error}");
        assert!(error.contains("permissions") && error.contains("disk space"), "{error}");
        let app_data = root.join("app-data");
        let folder = discovery_workspace(Some(&app_data)).expect("a private folder under app data");
        assert!(folder.0.is_dir(), "{:?}", folder.0);
        assert!(folder.0.starts_with(app_data.join(AGENT_TEMP_DIR)), "{:?}", folder.0);
        drop(folder);
        let _ = std::fs::remove_dir_all(&root);
    }






    #[test]
    fn r16_auth_exclusions_use_structured_data_and_extended_status_phrases() {
        for data in [json!({"message":"OAuth token quota exceeded"}), json!({"kind":"auth","message":"invalid api key"})] {
            assert_eq!(rpc_error(&json!({"message":"Request failed","data":data})), "Request failed");
        }
        for message in ["Request failed with status code 401", "Access token has expired", "The session has expired"] {
            assert_eq!(rpc_error(&json!({"message":message})), SIGN_IN, "{message}");
        }
    }

    #[test]
    fn r16_resume_without_settings_keeps_the_existing_session() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        config.model = "default".into();
        config.resume_id = Some("sess_saved".into());
        let mut protocol = Protocol::new(config.clone());
        protocol.initial();
        assert!(protocol.receive(json!({"id":ID_CREATE,"result":{"session":{"sessionId":"sess_saved"}}})).is_ok());
        let mut protocol = Protocol::new(config);
        protocol.initial();
        assert_eq!(protocol.receive(json!({"id":ID_CREATE,"result":{"session":{"sessionId":"sess_saved"},"settings":{"model":{"available":[]}}}})).err().as_deref(), Some(NO_MODELS));
    }

    #[test]
    fn r14_structured_auth_data_and_expired_sessions_map_to_sign_in() {
        for data in [json!({"code":"AUTH_REQUIRED"}), json!({"kind":"authorization","reason":"expired"}), json!({"error":"unauthorized"}), json!({"type":"auth","message":"required"})] {
            assert_eq!(rpc_error(&json!({"message":"Request failed","data":data})), SIGN_IN);
        }
        for message in ["Token expired", "Signed out", "Request failed with status 401", "Logged out", "Session expired", "HTTP 401"] {
            assert_eq!(rpc_error(&json!({"message":message})), SIGN_IN, "{message}");
        }
        assert_ne!(rpc_error(&json!({"message":"Invalid API key (status 401)"})), SIGN_IN);
        for message in ["Provider config invalid: apiKey: Required", "Error: apiKey: required", "Error: secret: not found", "Failed: credentials: none configured", "Error: Bearer token missing from request", "Missing Bearer token"] {
            assert_eq!(rpc_error(&json!({"message":message})), message, "{message}");
        }
    }

    #[test]
    fn r12_account_api_key_errors_preserve_the_server_message() {
        for message in ["Invalid API key for account", "Account apikey expired"] {
            assert_eq!(rpc_error(&json!({"message":message})), super::super::diagnostics::clean(message), "{message}");
        }
        for message in ["Account authentication failed", "No account signed in"] {
            assert_eq!(rpc_error(&json!({"message":message})), SIGN_IN, "{message}");
        }
    }

    #[test]
    fn r11_rpc_auth_exclusions_distinguish_provider_keys_from_session_auth() {
        for message in ["Unauthorized: invalid API key for provider", "No provider configured for account", "Sign in failed: quota exhausted", "Login denied: invalid apikey", "Account billing authentication required"] {
            assert_eq!(rpc_error(&json!({"message":message})), message, "{message}");
            assert_eq!(rpc_error(&json!({"message":message,"data":"AUTH_REQUIRED"})), message, "{message}");
        }
        for message in ["Authentication required for this model", "Authentication required", "Authorization header is missing"] {
            assert_eq!(rpc_error(&json!({"message":message})), SIGN_IN, "{message}");
        }
    }

    #[test]
    fn r10_rpc_auth_guidance_preserves_configuration_and_prose_errors() {
        for message in ["No provider configured for account", "No models available for account", "author missing", "Invalid signature", "Design token missing", "Account authorization error: provider config missing"] {
            assert_eq!(rpc_error(&json!({"message":message})), message, "{message}");
        }
        for message in ["Authorization header is missing", "Authentication required", "Authentication failed", "OAuth token expired"] {
            assert_eq!(rpc_error(&json!({"message":message})), SIGN_IN, "{message}");
        }
    }

    #[test]
    fn r9_account_billing_errors_preserve_the_actionable_message() {
        for message in ["Account quota exceeded", "Insufficient account balance", "Account billing payment required", "Account rate limit exceeded", "No account credits", "Account credits required", "Account limits required"] {
            assert_eq!(rpc_error(&json!({"message":message})), message);
        }
        for message in ["account missing", "Account not signed in", "No ZCode account is signed in"] {
            assert_eq!(rpc_error(&json!({"message":message})), SIGN_IN);
        }
    }

    #[test]
    fn r9_whitespace_session_model_is_an_empty_catalog_for_discovery_and_sends() {
        let mut empty = snapshot();
        empty["settings"]["model"]["available"] = json!([]);
        empty["session"]["model"]["modelId"] = json!("   ");
        assert!(!has_session_model(&empty));
        assert_eq!(parse_models(&empty).unwrap_err(), NO_MODELS);
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        let mut protocol = Protocol::new(config);
        protocol.initial();
        assert_eq!(protocol.receive(json!({"id":ID_CREATE,"result":empty})).err().as_deref(), Some(NO_MODELS));
    }

    #[test]
    fn auth_matching_requires_words_or_adjacent_word_pairs() {
        for message in ["Invalid design input", "Failed to assign initial model", "Could not log initialization timing"] {
            assert_eq!(rpc_error(&json!({"message": message})), message);
        }
        assert_eq!(rpc_error(&json!({"message": "Request failed", "data": "author missing"})), "Request failed");
        for message in ["signin required", "login required", "unauthorized", "sign-in first", "signed in required", "log in first", "logged in required", "not authenticated", "account missing"] {
            assert_eq!(rpc_error(&json!({"message": message})), SIGN_IN, "{message}");
        }
        for data in ["AUTH_REQUIRED", "authentication", "authorization", "unauthenticated", "unauthorized", "oauth", "signin", "login"] {
            assert_eq!(rpc_error(&json!({"message": "Request failed", "data": data})), SIGN_IN, "{data}");
        }
    }

    #[test]
    fn windows_bundle_candidates_reject_unc_roots() {
        use std::ffi::OsStr;
        for path in [r"\\server\share", r"\\?\UNC\server\share", "//server/share"] {
            assert!(bundled_candidates_for_windows(Some(OsStr::new(path)), None).is_empty(), "{path}");
            assert!(bundled_candidates_for_windows(None, Some(OsStr::new(path))).is_empty(), "{path}");
        }
    }

    #[test]
    fn round7_rpc_errors_redact_before_shortening_and_match_full_auth_message() {
        let raw = format!("{}http://user:sk-secret{}@proxy", "x".repeat(1000), "y".repeat(4000));
        let error = rpc_error(&json!({"message": raw}));
        assert!(!error.contains("sk-secret"), "{error}");
        assert!(!super::super::diagnostics::failure(&error, "").contains("sk-secret"));
        let late_auth = format!("{} Please sign in", "x".repeat(5000));
        assert_eq!(rpc_error(&json!({"message": late_auth})), SIGN_IN);
    }

    #[test]
    fn round7_turn_failed_redacts_before_shortening() {
        let (mut p, _) = created();
        subscribe_acked(&mut p);
        let raw = format!("{}http://user:sk-secret{}@proxy", "x".repeat(1000), "y".repeat(4000));
        p.receive(event("turn.failed", json!({"error": raw}))).unwrap();
        assert!(!p.zcode.error.as_ref().unwrap().contains("sk-secret"));
        let Err(error) = p.receive(event("turn.completed", json!({"resultType":"error_during_execution","inputId":"pandacode-1"}))) else { panic!("failed turn must return an error"); };
        assert!(!super::super::diagnostics::failure(&error, "").contains("sk-secret"));
    }

    #[test]
    fn rpc_errors_map_account_failures_to_the_sign_in_guidance() {
        for error in [
            json!({"code": -32000, "message": "Request failed", "data": "AUTH_REQUIRED"}),
            json!({"code": -32000, "message": "Request failed", "data": "unauthenticated"}),
            json!({"code": -32000, "message": "No ZCode account is signed in"}),
            json!({"code": -32000, "message": "Please SIGN IN first"}),
            json!({"code": -32000, "message": "Account not signed in"}),
            json!({"code": -32000, "message": "unauthenticated"}),
        ] {
            assert_eq!(rpc_error(&error), SIGN_IN, "{error}");
        }
        for (error, message) in [
            (json!({"code": -32602, "message": "Invalid params: workspace"}), "Invalid params: workspace"),
            (json!({"code": -32603, "message": "Internal error", "data": {"kind": "io"}}), "Internal error"),
            // `sign` and `account` inside other words are not auth failures.
            (json!({"code": -32603, "message": "Failed to assign session model"}), "Failed to assign session model"),
            (json!({"code": -32603, "message": "Invalid signature"}), "Invalid signature"),
            (json!({"code": -32603, "message": "Design token missing"}), "Design token missing"),
        ] {
            assert_eq!(rpc_error(&error), message, "{error}");
        }
    }

    #[test]
    fn run_errors_share_the_discovery_error_mapping() {
        let mut config = super::super::tests::config("zcode");
        config.cwd = PathBuf::from("/tmp");
        let mut p = Protocol::new(config);
        p.initial();
        let Err(auth) = p.receive(json!({"id": ID_CREATE, "error": {"code": -32000, "message": "Account not signed in"}})) else {
            panic!("an auth error must fail the run");
        };
        assert_eq!(auth, SIGN_IN);
        let Err(other) = p.receive(json!({"id": ID_CREATE, "error": {"code": -32602, "message": "Invalid params: mode"}})) else {
            panic!("a create error must fail the run");
        };
        assert_eq!(other, "Invalid params: mode");
    }

    #[tokio::test]
    #[ignore = "needs the ZCode CLI; metadata only, never sends a prompt"]
    async fn installed_zcode_lists_models() {
        // Prefer the desktop bundle: a PATH shim (or a stale install) may not
        // speak the current protocol, and the bundle is what the pin records.
        let path = bundled().unwrap_or_else(|| executable("zcode").expect("Install ZCode first"));
        match models(&path).await {
            Ok(models) => assert!(!models.is_empty() && models[0].id == "default", "{models:?}"),
            Err(err) => assert!(err.starts_with(NO_MODELS), "unexpected discovery error: {err}"),
        }
    }

    /// Metadata re-verification against the current desktop CLI: the create
    /// snapshot carries per-model capability properties and slash commands,
    /// and `session/usage` answers a zero-state session. Never sends a prompt,
    /// so turn event names stay pinned to the recorded frames.
    #[tokio::test]
    #[ignore = "needs the ZCode CLI; metadata only, never sends a prompt"]
    async fn installed_zcode_snapshot_capabilities() {
        // Prefer the desktop bundle: a PATH shim (or a stale install) may not
        // speak the current protocol, and the bundle is what the pin records.
        let path = bundled().unwrap_or_else(|| executable("zcode").expect("Install ZCode first"));
        // The bundled CLI runs on the desktop app's Electron runtime, so the
        // launch layer builds the process (direct exec of zcode.cjs fails).
        let mut command = super::launch::command(&path).unwrap();
        command.arg("app-server");
        let workspace = std::env::temp_dir();
        command
            .current_dir(&workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn().expect("start ZCode");
        let group = ProcessGroup::register(child.id());
        let snapshot = tokio::time::timeout(Duration::from_secs(25), async {
            let mut stdin = child.stdin.take().unwrap();
            write_json(
                &mut stdin,
                &json!({"id": ID_CREATE, "method": "session/create", "params": {
                    "workspace": workspace_of(&workspace),
                    "persistence": "deferred",
                    "mode": "plan",
                    "titleGenerationEnabled": false,
                }}),
            )
            .await
            .unwrap();
            let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
            loop {
                let mut line = String::new();
                let count = stdout.read_line(&mut line).await.unwrap();
                assert!(count > 0, "ZCode exited before the create reply");
                let value: Value = serde_json::from_str(&line).unwrap();
                if value.get("method").is_some() && value.get("id").is_some() {
                    // Decline reverse requests like the run path does; the
                    // create waits on them (runtime preferences).
                    write_json(
                        &mut stdin,
                        &json!({"id": value["id"], "error": {"code": -32601, "message": "Method not found"}}),
                    )
                    .await
                    .unwrap();
                    continue;
                }
                if value["id"] == ID_CREATE {
                    assert!(value.get("error").is_none(), "create failed: {value}");
                    let session_id = value["result"]["session"]["sessionId"].clone();
                    let result = value["result"].clone();
                    // A fresh deferred session may be known to usage only
                    // after its first send; a zero-state reply proves the
                    // method, a session-not-found error proves the same on
                    // builds that defer harder. Anything else has changed.
                    write_json(
                        &mut stdin,
                        &json!({"id": 90, "method": "session/usage", "params": {"sessionId": session_id}}),
                    )
                    .await
                    .unwrap();
                    loop {
                        let mut line = String::new();
                        stdout.read_line(&mut line).await.unwrap();
                        let value: Value = serde_json::from_str(&line).unwrap();
                        if value.get("method").is_some() && value.get("id").is_some() {
                            write_json(
                                &mut stdin,
                                &json!({"id": value["id"], "error": {"code": -32601, "message": "Method not found"}}),
                            )
                            .await
                            .unwrap();
                            continue;
                        }
                        if value["id"] == 90 {
                            if let Some(result) = value.get("result") {
                                assert_eq!(result["totalTokens"], 0, "{result}");
                                assert!(result["inputTokens"].is_number(), "{result}");
                            } else {
                                assert_eq!(value["error"]["code"], -32004, "{value}");
                            }
                            break;
                        }
                    }
                    return result;
                }
            }
        })
        .await
        .expect("ZCode snapshot timed out");
        drop(group);
        let _ = child.start_kill();

        let entries = snapshot["settings"]["model"]["available"].as_array().unwrap();
        assert!(!entries.is_empty());
        for entry in entries {
            let input = &entry["properties"]["inputFormat"];
            assert!(input["supportsText"].is_boolean(), "no inputFormat on {entry}");
            assert!(input["supportsImage"].is_boolean(), "no supportsImage on {entry}");
            assert!(input["supportsPdf"].is_boolean(), "no supportsPdf on {entry}");
            // The catalog schema is strict and carries no speed or tier
            // field; the GLM Coding Plan sells speed per plan, not per model.
            assert!(entry.get("capabilities").is_none(), "{entry}");
            assert!(entry.get("speedTiers").is_none(), "{entry}");
            assert!(entry.get("serviceTiers").is_none(), "{entry}");
        }
        let commands = snapshot["slashCommands"].as_array().unwrap();
        assert!(
            commands.iter().any(|c| c["name"] == "goal" && c["source"] == "builtin"),
            "expected the builtin /goal command in {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c["name"] == "compact"),
            "expected /compact in {commands:?}"
        );
        assert!(snapshot["projection"]["contextWindow"].is_number());
        assert!(snapshot["todos"].is_array());
    }
}
