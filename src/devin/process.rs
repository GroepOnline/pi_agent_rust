//! Session-owned native process supervision for Devin-compatible shell tools.

use super::audit::AuditStatus;
use super::policy::{ToolPolicyEngine, ToolRequest, ToolRequestOrigin};
use crate::agent_cx::AgentCx;
use crate::error::{Error, Result};
use crate::model::{ContentBlock, TextContent};
use crate::tools::{
    Tool, ToolEffects, ToolOutput, ToolUpdate, command_with_default_sigpipe_in_dir,
    isolate_command_process_group, kill_process_group_tree, terminate_process_group_tree,
};
use asupersync::time::{sleep, wall_now};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const PROCESS_OUTPUT_SCHEMA_V1: &str = "pi.devin.process_output.v1";
const PROCESS_CONTROL_SCHEMA_V1: &str = "pi.devin.process_control.v1";
const DEFAULT_OUTPUT_CAPACITY: usize = 1_000_000;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_KILL_GRACE: Duration = Duration::from_millis(250);
const MAX_KILL_GRACE: Duration = Duration::from_secs(5);
const MAX_WAIT_FOR_OUTPUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub struct ProcessSupervisorConfig {
    pub output_capacity: usize,
    pub poll_interval: Duration,
    pub kill_grace: Duration,
}

impl Default for ProcessSupervisorConfig {
    fn default() -> Self {
        Self {
            output_capacity: DEFAULT_OUTPUT_CAPACITY,
            poll_interval: DEFAULT_POLL_INTERVAL,
            kill_grace: DEFAULT_KILL_GRACE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
}

impl ProcessStatus {
    const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }

    const fn audit_status(self) -> AuditStatus {
        match self {
            Self::Running | Self::Succeeded => AuditStatus::Succeeded,
            Self::Failed => AuditStatus::Failed,
            Self::Cancelled => AuditStatus::Cancelled,
            Self::TimedOut => AuditStatus::TimedOut,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSnapshot {
    pub process_id: String,
    pub command: String,
    pub cwd: PathBuf,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: ProcessStatus,
    pub exit_code: Option<i32>,
    pub process_group_id: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdin_open: bool,
    pub artifact_refs: Vec<String>,
    pub redacted_error: Option<String>,
}

impl ProcessSnapshot {
    fn combined_output(&self) -> String {
        match (self.stdout.is_empty(), self.stderr.is_empty()) {
            (false, false) => format!("{}\n[stderr]\n{}", self.stdout, self.stderr),
            (false, true) => self.stdout.clone(),
            (true, false) => format!("[stderr]\n{}", self.stderr),
            (true, true) => String::new(),
        }
    }
}

#[derive(Debug)]
struct BoundedBuffer {
    bytes: VecDeque<u8>,
    capacity: usize,
    total_bytes: u64,
    truncated: bool,
}

impl BoundedBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(capacity.min(64 * 1024)),
            capacity: capacity.max(1),
            total_bytes: 0,
            truncated: false,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.total_bytes = self
            .total_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.bytes.extend(bytes.iter().copied());
        while self.bytes.len() > self.capacity {
            self.bytes.pop_front();
            self.truncated = true;
        }
    }

    fn snapshot(&self, requested_offset: Option<u64>) -> (String, u64, bool) {
        let retained_start = self
            .total_bytes
            .saturating_sub(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX));
        let requested = requested_offset.unwrap_or(retained_start);
        let effective = requested.max(retained_start).min(self.total_bytes);
        let skip = usize::try_from(effective.saturating_sub(retained_start)).unwrap_or(usize::MAX);
        let bytes = self.bytes.iter().skip(skip).copied().collect::<Vec<_>>();
        (
            String::from_utf8_lossy(&bytes).into_owned(),
            effective,
            requested < retained_start,
        )
    }
}

#[derive(Debug)]
struct ProcessState {
    status: ProcessStatus,
    exit_code: Option<i32>,
    ended_at: Option<DateTime<Utc>>,
    stdin: Option<ChildStdin>,
    stdout: BoundedBuffer,
    stderr: BoundedBuffer,
    redacted_error: Option<String>,
}

#[derive(Debug)]
struct ManagedProcess {
    id: String,
    command: String,
    cwd: PathBuf,
    started_at: DateTime<Utc>,
    pid: u32,
    process_group_id: Option<u32>,
    timeout: Option<Duration>,
    spill_path: PathBuf,
    state: Mutex<ProcessState>,
    changed: Condvar,
    stop_requested: AtomicBool,
}

impl ManagedProcess {
    fn snapshot(&self, stdout_offset: Option<u64>, stderr_offset: Option<u64>) -> ProcessSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (stdout, stdout_offset, stdout_gap) = state.stdout.snapshot(stdout_offset);
        let (stderr, stderr_offset, stderr_gap) = state.stderr.snapshot(stderr_offset);
        let truncated =
            state.stdout.truncated || state.stderr.truncated || stdout_gap || stderr_gap;
        let artifact_refs = truncated
            .then(|| format!("file://{}", self.spill_path.display()))
            .into_iter()
            .collect();
        ProcessSnapshot {
            process_id: self.id.clone(),
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            started_at: self.started_at,
            ended_at: state.ended_at,
            status: state.status,
            exit_code: state.exit_code,
            process_group_id: self.process_group_id,
            stdout,
            stderr,
            stdout_offset,
            stderr_offset,
            stdout_total_bytes: state.stdout.total_bytes,
            stderr_total_bytes: state.stderr.total_bytes,
            stdout_truncated: state.stdout.truncated || stdout_gap,
            stderr_truncated: state.stderr.truncated || stderr_gap,
            stdin_open: state.stdin.is_some(),
            artifact_refs,
            redacted_error: state.redacted_error.clone(),
        }
    }

    fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        self.changed.notify_all();
    }

    fn is_terminal(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status
            .is_terminal()
    }
}

#[derive(Debug)]
pub struct ProcessSupervisor {
    workspace: PathBuf,
    shell_path: Option<String>,
    command_prefix: Option<String>,
    config: ProcessSupervisorConfig,
    processes: Mutex<HashMap<String, Arc<ManagedProcess>>>,
    stopping: AtomicBool,
}

impl ProcessSupervisor {
    #[must_use]
    pub fn new(
        workspace: impl Into<PathBuf>,
        shell_path: Option<String>,
        command_prefix: Option<String>,
    ) -> Self {
        Self::with_config(
            workspace,
            shell_path,
            command_prefix,
            ProcessSupervisorConfig::default(),
        )
    }

    #[must_use]
    pub fn with_config(
        workspace: impl Into<PathBuf>,
        shell_path: Option<String>,
        command_prefix: Option<String>,
        mut config: ProcessSupervisorConfig,
    ) -> Self {
        config.output_capacity = config.output_capacity.max(1);
        config.poll_interval = config.poll_interval.max(Duration::from_millis(1));
        config.kill_grace = config.kill_grace.min(MAX_KILL_GRACE);
        Self {
            workspace: workspace.into(),
            shell_path,
            command_prefix,
            config,
            processes: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn spawn(
        self: &Arc<Self>,
        command: &str,
        cwd: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<String> {
        if self.stopping.load(Ordering::SeqCst) {
            return Err(Error::tool("exec", "process supervisor is stopping"));
        }
        if command.trim().is_empty() {
            return Err(Error::validation("command must not be empty"));
        }
        let cwd = cwd.unwrap_or(&self.workspace).to_path_buf();
        if !cwd.is_dir() {
            return Err(Error::tool(
                "exec",
                format!("working directory does not exist: {}", cwd.display()),
            ));
        }

        let shell = self.shell_path.as_deref().unwrap_or_else(|| {
            for path in ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"] {
                if Path::new(path).exists() {
                    return path;
                }
            }
            "sh"
        });
        let command = self
            .command_prefix
            .as_deref()
            .filter(|prefix| !prefix.trim().is_empty())
            .map_or_else(
                || command.to_string(),
                |prefix| format!("{prefix}\n{command}"),
            );
        let command = format!("trap 'code=$?; wait; exit $code' EXIT\n{command}");

        let mut child_command = command_with_default_sigpipe_in_dir(shell, &cwd)
            .map_err(|error| Error::tool("exec", format!("failed to prepare shell: {error}")))?;
        child_command
            .arg("-c")
            .arg(&command)
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        isolate_command_process_group(&mut child_command);
        let mut child = child_command
            .spawn()
            .map_err(|error| Error::tool("exec", format!("failed to spawn shell: {error}")))?;
        let pid = child.id();
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::tool("exec", "missing child stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::tool("exec", "missing child stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::tool("exec", "missing child stderr"))?;

        let id = format!("proc_{}", Uuid::new_v4().simple());
        let spill_path = std::env::temp_dir().join(format!("pi-{id}.log"));
        let spill = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&spill_path)
            .map_err(|error| {
                Error::tool("exec", format!("failed to create output spill: {error}"))
            })?;
        let spill = Arc::new(Mutex::new(spill));
        let process = Arc::new(ManagedProcess {
            id: id.clone(),
            command,
            cwd,
            started_at: Utc::now(),
            pid,
            process_group_id: Some(pid),
            timeout,
            spill_path,
            state: Mutex::new(ProcessState {
                status: ProcessStatus::Running,
                exit_code: None,
                ended_at: None,
                stdin: Some(stdin),
                stdout: BoundedBuffer::new(self.config.output_capacity),
                stderr: BoundedBuffer::new(self.config.output_capacity),
                redacted_error: None,
            }),
            changed: Condvar::new(),
            stop_requested: AtomicBool::new(false),
        });
        self.processes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.clone(), Arc::clone(&process));

        let (stdout_thread, stderr_thread) = spawn_output_pumps(&process, &spill, stdout, stderr);
        let config = self.config;
        thread::spawn(move || {
            monitor_process(&process, child, stdout_thread, stderr_thread, config);
        });
        Ok(id)
    }

    pub fn snapshot(
        &self,
        process_id: &str,
        stdout_offset: Option<u64>,
        stderr_offset: Option<u64>,
    ) -> Result<ProcessSnapshot> {
        let process = self.process(process_id)?;
        Ok(process.snapshot(stdout_offset, stderr_offset))
    }

    pub fn write_stdin(&self, process_id: &str, input: &[u8], close_stdin: bool) -> Result<()> {
        let process = self.process(process_id)?;
        let mut state = process
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status.is_terminal() {
            return Err(Error::tool(
                "write_to_process",
                format!("process `{process_id}` is no longer running"),
            ));
        }
        let Some(stdin) = state.stdin.as_mut() else {
            return Err(Error::tool(
                "write_to_process",
                format!("stdin for process `{process_id}` is closed"),
            ));
        };
        let write_result = stdin.write_all(input).and_then(|()| stdin.flush());
        if let Err(error) = write_result {
            state.stdin = None;
            return Err(Error::tool(
                "write_to_process",
                format!("failed to write stdin for process `{process_id}`: {error}"),
            ));
        }
        if close_stdin {
            state.stdin = None;
        }
        drop(state);
        process.changed.notify_all();
        Ok(())
    }

    pub fn close_stdin(&self, process_id: &str) -> Result<()> {
        let process = self.process(process_id)?;
        let mut state = process
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stdin.take().is_none() {
            return Err(Error::tool(
                "write_to_process",
                format!("stdin for process `{process_id}` is already closed"),
            ));
        }
        drop(state);
        process.changed.notify_all();
        Ok(())
    }

    pub fn kill(&self, process_id: &str, grace: Option<Duration>) -> Result<ProcessSnapshot> {
        let process = self.process(process_id)?;
        if process.is_terminal() {
            return Ok(process.snapshot(None, None));
        }
        process.request_stop();
        terminate_process_group_tree(Some(process.pid));
        let deadline = Instant::now() + grace.unwrap_or(self.config.kill_grace).min(MAX_KILL_GRACE);
        while !process.is_terminal() && Instant::now() < deadline {
            let state = process
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _guard = process
                .changed
                .wait_timeout(state, self.config.poll_interval)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if !process.is_terminal() {
            kill_process_group_tree(Some(process.pid));
        }
        Ok(process.snapshot(None, None))
    }

    pub fn cleanup_all(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let processes = self
            .processes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for process in &processes {
            if !process.is_terminal() {
                process.request_stop();
                terminate_process_group_tree(Some(process.pid));
            }
        }
        let deadline = Instant::now() + self.config.kill_grace;
        while Instant::now() < deadline && processes.iter().any(|process| !process.is_terminal()) {
            thread::sleep(self.config.poll_interval);
        }
        for process in processes {
            if !process.is_terminal() {
                kill_process_group_tree(Some(process.pid));
            }
        }
    }

    #[must_use]
    pub fn active_process_count(&self) -> usize {
        self.processes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|process| !process.is_terminal())
            .count()
    }

    fn process(&self, process_id: &str) -> Result<Arc<ManagedProcess>> {
        self.processes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(process_id)
            .cloned()
            .ok_or_else(|| Error::tool("get_output", format!("unknown process id `{process_id}`")))
    }

    async fn wait_for_terminal(
        &self,
        process_id: &str,
        on_update: Option<&(dyn Fn(ToolUpdate) + Send + Sync)>,
    ) -> Result<ProcessSnapshot> {
        let process = self.process(process_id)?;
        let cx = AgentCx::for_current_or_request();
        let mut stdout_offset = 0_u64;
        let mut stderr_offset = 0_u64;
        loop {
            let snapshot = process.snapshot(Some(stdout_offset), Some(stderr_offset));
            if !snapshot.stdout.is_empty() || !snapshot.stderr.is_empty() {
                if let Some(on_update) = on_update {
                    on_update(snapshot_update(&snapshot));
                }
                stdout_offset = snapshot.stdout_total_bytes;
                stderr_offset = snapshot.stderr_total_bytes;
            }
            if snapshot.status.is_terminal() {
                return Ok(process.snapshot(None, None));
            }
            if cx.checkpoint().is_err() {
                process.request_stop();
                kill_process_group_tree(Some(process.pid));
                return Ok(process.snapshot(None, None));
            }
            let now = cx
                .cx()
                .timer_driver()
                .map_or_else(wall_now, |timer| timer.now());
            sleep(now, self.config.poll_interval).await;
        }
    }

    async fn wait_for_change(
        &self,
        process_id: &str,
        stdout_offset: Option<u64>,
        stderr_offset: Option<u64>,
        wait: Duration,
    ) -> Result<ProcessSnapshot> {
        let process = self.process(process_id)?;
        let initial = process.snapshot(stdout_offset, stderr_offset);
        if initial.status.is_terminal() || !initial.stdout.is_empty() || !initial.stderr.is_empty()
        {
            return Ok(initial);
        }
        let wait = wait.min(MAX_WAIT_FOR_OUTPUT);
        let cx = AgentCx::for_current_or_request();
        let deadline = Instant::now() + wait;
        loop {
            if cx.checkpoint().is_err() || Instant::now() >= deadline {
                return Ok(process.snapshot(stdout_offset, stderr_offset));
            }
            let now = cx
                .cx()
                .timer_driver()
                .map_or_else(wall_now, |timer| timer.now());
            sleep(now, self.config.poll_interval).await;
            let snapshot = process.snapshot(stdout_offset, stderr_offset);
            if snapshot.status.is_terminal()
                || !snapshot.stdout.is_empty()
                || !snapshot.stderr.is_empty()
            {
                return Ok(snapshot);
            }
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        self.cleanup_all();
    }
}

fn spawn_output_pumps(
    process: &Arc<ManagedProcess>,
    spill: &Arc<Mutex<File>>,
    stdout: impl Read + Send + 'static,
    stderr: impl Read + Send + 'static,
) -> (thread::JoinHandle<()>, thread::JoinHandle<()>) {
    let stdout_process = Arc::clone(process);
    let stdout_spill = Arc::clone(spill);
    let stdout_thread = thread::spawn(move || {
        pump_output(stdout, false, &stdout_process, &stdout_spill);
    });
    let stderr_process = Arc::clone(process);
    let stderr_spill = Arc::clone(spill);
    let stderr_thread = thread::spawn(move || {
        pump_output(stderr, true, &stderr_process, &stderr_spill);
    });
    (stdout_thread, stderr_thread)
}

fn pump_output(
    mut reader: impl Read,
    is_stderr: bool,
    process: &ManagedProcess,
    spill: &Mutex<File>,
) {
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let bytes = &chunk[..read];
                {
                    let mut file = spill
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let label = if is_stderr {
                        b"[stderr] "
                    } else {
                        b"[stdout] "
                    };
                    let _ignored = file.write_all(label).and_then(|()| file.write_all(bytes));
                }
                let mut state = process
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if is_stderr {
                    state.stderr.append(bytes);
                } else {
                    state.stdout.append(bytes);
                }
                drop(state);
                process.changed.notify_all();
            }
            Err(error) => {
                let mut state = process
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.redacted_error = Some(format!("output reader failed: {error}"));
                drop(state);
                process.changed.notify_all();
                break;
            }
        }
    }
}

fn monitor_process(
    process: &ManagedProcess,
    mut child: Child,
    stdout_thread: thread::JoinHandle<()>,
    stderr_thread: thread::JoinHandle<()>,
    config: ProcessSupervisorConfig,
) {
    let started = Instant::now();
    let mut forced_status = None;
    let mut exit_status = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {}
            Err(error) => {
                let mut state = process
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.redacted_error = Some(format!("failed to poll child: {error}"));
                forced_status = Some(ProcessStatus::Failed);
                break;
            }
        }

        let timed_out = process
            .timeout
            .is_some_and(|timeout| started.elapsed() >= timeout);
        if timed_out || process.stop_requested.load(Ordering::SeqCst) {
            forced_status = Some(if timed_out {
                ProcessStatus::TimedOut
            } else {
                ProcessStatus::Cancelled
            });
            terminate_process_group_tree(Some(process.pid));
            let deadline = Instant::now() + config.kill_grace;
            while Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        exit_status = Some(status);
                        break;
                    }
                    Ok(None) => thread::sleep(config.poll_interval),
                    Err(_) => break,
                }
            }
            if exit_status.is_none() {
                kill_process_group_tree(Some(process.pid));
                let _ignored = child.kill();
                exit_status = child.wait().ok();
            }
            break;
        }
        thread::sleep(config.poll_interval);
    }

    let _ignored = stdout_thread.join();
    let _ignored = stderr_thread.join();
    if exit_status.is_none() {
        exit_status = child.wait().ok();
    }
    let mut state = process
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.stdin = None;
    state.exit_code = exit_status.map(exit_status_code);
    state.status = forced_status.unwrap_or_else(|| {
        exit_status.map_or(ProcessStatus::Failed, |status| {
            if status.success() {
                ProcessStatus::Succeeded
            } else {
                ProcessStatus::Failed
            }
        })
    });
    state.ended_at = Some(Utc::now());
    drop(state);
    process.changed.notify_all();
}

fn exit_status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            status.signal().map_or(-1, |signal| -signal)
        }
        #[cfg(not(unix))]
        {
            -1
        }
    })
}

fn snapshot_update(snapshot: &ProcessSnapshot) -> ToolUpdate {
    ToolUpdate {
        content: vec![ContentBlock::Text(TextContent::new(
            snapshot.combined_output(),
        ))],
        details: Some(snapshot_details(snapshot)),
    }
}

fn snapshot_output(snapshot: &ProcessSnapshot, is_error: bool) -> ToolOutput {
    ToolOutput {
        content: vec![ContentBlock::Text(TextContent::new(
            snapshot.combined_output(),
        ))],
        details: Some(snapshot_details(snapshot)),
        is_error,
    }
}

fn snapshot_details(snapshot: &ProcessSnapshot) -> Value {
    json!({
        "schema": PROCESS_OUTPUT_SCHEMA_V1,
        "processId": snapshot.process_id,
        "cwd": snapshot.cwd,
        "startedAt": snapshot.started_at,
        "endedAt": snapshot.ended_at,
        "status": snapshot.status,
        "exitCode": snapshot.exit_code,
        "processGroupId": snapshot.process_group_id,
        "stdoutOffset": snapshot.stdout_offset,
        "stderrOffset": snapshot.stderr_offset,
        "stdoutTotalBytes": snapshot.stdout_total_bytes,
        "stderrTotalBytes": snapshot.stderr_total_bytes,
        "stdoutTruncated": snapshot.stdout_truncated,
        "stderrTruncated": snapshot.stderr_truncated,
        "stdinOpen": snapshot.stdin_open,
        "artifactRefs": snapshot.artifact_refs,
        "error": snapshot.redacted_error,
    })
}

#[derive(Debug, Deserialize)]
struct StartProcessInput {
    command: String,
    #[serde(default, alias = "working_dir", alias = "workingDirectory")]
    cwd: Option<PathBuf>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    background: bool,
}

#[derive(Debug, Deserialize)]
struct GetOutputInput {
    #[serde(alias = "processId")]
    process_id: String,
    #[serde(default, alias = "stdoutOffset")]
    stdout_offset: Option<u64>,
    #[serde(default, alias = "stderrOffset")]
    stderr_offset: Option<u64>,
    #[serde(default, alias = "waitMs")]
    wait_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct WriteToProcessInput {
    #[serde(alias = "processId")]
    process_id: String,
    input: String,
    #[serde(default, alias = "closeStdin")]
    close_stdin: bool,
}

#[derive(Debug, Deserialize)]
struct KillShellInput {
    #[serde(alias = "processId")]
    process_id: String,
    #[serde(default, alias = "gracePeriodMs")]
    grace_period_ms: Option<u64>,
}

pub struct DevinProcessTool {
    name: &'static str,
    supervisor: Arc<ProcessSupervisor>,
    policy: Arc<ToolPolicyEngine>,
}

impl DevinProcessTool {
    #[must_use]
    pub const fn new(
        name: &'static str,
        supervisor: Arc<ProcessSupervisor>,
        policy: Arc<ToolPolicyEngine>,
    ) -> Self {
        Self {
            name,
            supervisor,
            policy,
        }
    }

    fn authorize(&self, call_id: &str, input: &Value) -> Result<()> {
        self.policy
            .ensure_process_authorized(&ToolRequest {
                call_id: call_id.to_string(),
                tool_name: self.name.to_string(),
                arguments: input.clone(),
                origin: ToolRequestOrigin::Native,
            })
            .map_err(|reason| Error::tool(self.name, reason))
    }

    fn complete(&self, call_id: &str, output: &ToolOutput) {
        let status = output
            .details
            .as_ref()
            .and_then(|details| details.get("status"))
            .and_then(Value::as_str)
            .map_or_else(
                || {
                    if output.is_error {
                        AuditStatus::Failed
                    } else {
                        AuditStatus::Succeeded
                    }
                },
                |status| match status {
                    "cancelled" => AuditStatus::Cancelled,
                    "timed_out" => AuditStatus::TimedOut,
                    "failed" => AuditStatus::Failed,
                    _ => AuditStatus::Succeeded,
                },
            );
        let artifact_refs = output
            .details
            .as_ref()
            .and_then(|details| details.get("artifactRefs"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        self.policy.complete(
            call_id,
            status,
            artifact_refs,
            output
                .is_error
                .then(|| "process tool execution failed".to_string()),
        );
    }
}

#[async_trait]
impl Tool for DevinProcessTool {
    fn name(&self) -> &str {
        self.name
    }

    fn label(&self) -> &str {
        match self.name {
            "exec" => "Exec",
            "shell_command" => "Shell Command",
            "get_output" => "Get Output",
            "write_to_process" => "Write to Process",
            "kill_shell" => "Kill Shell",
            _ => "Process",
        }
    }

    fn description(&self) -> &str {
        match self.name {
            "exec" => "Execute a shell command in the session-owned process supervisor.",
            "shell_command" => "Run a foreground or background shell command.",
            "get_output" => "Read bounded incremental output and status for a managed process.",
            "write_to_process" => "Write text to stdin of a running managed process.",
            "kill_shell" => "Terminate a managed process group gracefully, then forcefully.",
            _ => "Managed process operation.",
        }
    }

    fn parameters(&self) -> Value {
        process_tool_schema(self.name)
    }

    async fn execute(
        &self,
        tool_call_id: &str,
        input: Value,
        on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        if let Err(error) = self.authorize(tool_call_id, &input) {
            self.policy.complete(
                tool_call_id,
                AuditStatus::Denied,
                Vec::new(),
                Some("process tool authorization denied".to_string()),
            );
            return Err(error);
        }

        let result = match self.name {
            "exec" | "shell_command" => {
                let input: StartProcessInput = serde_json::from_value(input)
                    .map_err(|error| Error::validation(error.to_string()))?;
                let timeout = input.timeout.map(Duration::from_secs);
                let process_id =
                    self.supervisor
                        .spawn(&input.command, input.cwd.as_deref(), timeout)?;
                if input.background {
                    let snapshot = self.supervisor.snapshot(&process_id, None, None)?;
                    Ok(snapshot_output(&snapshot, false))
                } else {
                    let snapshot = self
                        .supervisor
                        .wait_for_terminal(&process_id, on_update.as_deref())
                        .await?;
                    let is_error = matches!(
                        snapshot.status,
                        ProcessStatus::Failed | ProcessStatus::Cancelled | ProcessStatus::TimedOut
                    );
                    Ok(snapshot_output(&snapshot, is_error))
                }
            }
            "get_output" => {
                let input: GetOutputInput = serde_json::from_value(input)
                    .map_err(|error| Error::validation(error.to_string()))?;
                let snapshot = self
                    .supervisor
                    .wait_for_change(
                        &input.process_id,
                        input.stdout_offset,
                        input.stderr_offset,
                        Duration::from_millis(input.wait_ms.unwrap_or(0)),
                    )
                    .await?;
                Ok(snapshot_output(&snapshot, false))
            }
            "write_to_process" => {
                let input: WriteToProcessInput = serde_json::from_value(input)
                    .map_err(|error| Error::validation(error.to_string()))?;
                self.supervisor.write_stdin(
                    &input.process_id,
                    input.input.as_bytes(),
                    input.close_stdin,
                )?;
                Ok(ToolOutput {
                    content: vec![ContentBlock::Text(TextContent::new("stdin written"))],
                    details: Some(json!({
                        "schema": PROCESS_CONTROL_SCHEMA_V1,
                        "processId": input.process_id,
                        "status": "succeeded",
                        "stdinClosed": input.close_stdin,
                    })),
                    is_error: false,
                })
            }
            "kill_shell" => {
                let input: KillShellInput = serde_json::from_value(input)
                    .map_err(|error| Error::validation(error.to_string()))?;
                let snapshot = self.supervisor.kill(
                    &input.process_id,
                    input.grace_period_ms.map(Duration::from_millis),
                )?;
                Ok(snapshot_output(&snapshot, false))
            }
            _ => Err(Error::tool(self.name, "unsupported process tool")),
        };

        match &result {
            Ok(output) => self.complete(tool_call_id, output),
            Err(_) => self.policy.complete(
                tool_call_id,
                AuditStatus::Failed,
                Vec::new(),
                Some("process tool execution failed".to_string()),
            ),
        }
        result
    }

    fn effects(&self) -> ToolEffects {
        match self.name {
            "get_output" => ToolEffects::read(),
            _ => ToolEffects::process(),
        }
    }
}

#[must_use]
pub fn process_tool_schema(name: &str) -> Value {
    match name {
        "exec" | "shell_command" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "command": {"type": "string", "minLength": 1},
                "cwd": {"type": "string"},
                "timeout": {"type": "integer", "minimum": 0},
                "background": {"type": "boolean", "default": false}
            },
            "required": ["command"]
        }),
        "get_output" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "process_id": {"type": "string", "minLength": 1},
                "stdout_offset": {"type": "integer", "minimum": 0},
                "stderr_offset": {"type": "integer", "minimum": 0},
                "wait_ms": {"type": "integer", "minimum": 0, "maximum": 30000}
            },
            "required": ["process_id"]
        }),
        "write_to_process" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "process_id": {"type": "string", "minLength": 1},
                "input": {"type": "string"},
                "close_stdin": {"type": "boolean", "default": false}
            },
            "required": ["process_id", "input"]
        }),
        "kill_shell" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "process_id": {"type": "string", "minLength": 1},
                "grace_period_ms": {"type": "integer", "minimum": 0, "maximum": 5000}
            },
            "required": ["process_id"]
        }),
        _ => json!({"type": "object", "additionalProperties": false}),
    }
}

#[must_use]
pub fn process_tools(
    enabled: &[&str],
    supervisor: &Arc<ProcessSupervisor>,
    policy: &Arc<ToolPolicyEngine>,
) -> Vec<Box<dyn Tool>> {
    enabled
        .iter()
        .filter_map(|name| {
            let name = match *name {
                "exec" => "exec",
                "shell_command" => "shell_command",
                "get_output" => "get_output",
                "write_to_process" => "write_to_process",
                "kill_shell" => "kill_shell",
                _ => return None,
            };
            Some(Box::new(DevinProcessTool::new(
                name,
                Arc::clone(supervisor),
                Arc::clone(policy),
            )) as Box<dyn Tool>)
        })
        .collect()
}
