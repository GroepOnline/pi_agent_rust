#![cfg(unix)]

use asupersync::runtime::RuntimeBuilder;
use pi::devin::{
    AgentMode, AuditLog, AuditStatus, DevinProcessTool, DevinSessionState, PermissionMode,
    ProcessStatus, ProcessSupervisor, ProcessSupervisorConfig, SandboxStatus, ToolPolicyEngine,
};
use pi::model::ContentBlock;
use pi::tools::{Tool, ToolRegistry};
use serde_json::json;
use std::future::Future;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

fn run_async<T>(future: impl Future<Output = T>) -> T {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build");
    runtime.block_on(future)
}

fn policy(
    workspace: &Path,
    permission_mode: PermissionMode,
) -> (Arc<ToolPolicyEngine>, Arc<AuditLog>) {
    let mut state = DevinSessionState::new("process-test", workspace);
    state.agent_mode = AgentMode::Normal;
    state.permission_mode = permission_mode;
    let audit = Arc::new(AuditLog::new(64));
    let policy = Arc::new(
        ToolPolicyEngine::new(Arc::new(RwLock::new(state))).with_audit(Arc::clone(&audit)),
    );
    (policy, audit)
}

fn supervisor(workspace: &Path) -> Arc<ProcessSupervisor> {
    Arc::new(ProcessSupervisor::with_config(
        workspace,
        None,
        None,
        ProcessSupervisorConfig {
            output_capacity: 4096,
            poll_interval: Duration::from_millis(5),
            kill_grace: Duration::from_millis(100),
        },
    ))
}

fn wait_for_terminal(
    supervisor: &ProcessSupervisor,
    process_id: &str,
    timeout: Duration,
) -> pi::devin::ProcessSnapshot {
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = supervisor
            .snapshot(process_id, None, None)
            .expect("snapshot");
        if snapshot.status != ProcessStatus::Running {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "process did not terminate");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_stdout(
    supervisor: &ProcessSupervisor,
    process_id: &str,
    needle: &str,
    timeout: Duration,
) -> pi::devin::ProcessSnapshot {
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = supervisor
            .snapshot(process_id, None, None)
            .expect("snapshot");
        if snapshot.stdout.contains(needle) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "stdout never contained {needle:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn text_content(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn foreground_process_streams_through_tool_updates() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (policy, audit) = policy(workspace.path(), PermissionMode::Bypass);
    let supervisor = supervisor(workspace.path());
    let tool = DevinProcessTool::new("exec", Arc::clone(&supervisor), Arc::clone(&policy));
    let updates = Arc::new(Mutex::new(Vec::new()));
    let updates_for_callback = Arc::clone(&updates);

    let output = run_async(tool.execute(
        "call-foreground",
        json!({"command": "printf first; sleep 0.05; printf second"}),
        Some(Box::new(move |update| {
            updates_for_callback
                .lock()
                .expect("updates lock")
                .push(text_content(&update.content));
        })),
    ))
    .expect("foreground tool succeeds");

    assert!(!output.is_error);
    assert!(text_content(&output.content).contains("firstsecond"));
    assert!(
        updates
            .lock()
            .expect("updates lock")
            .iter()
            .any(|update| update.contains("first"))
    );
    let record = audit
        .snapshot()
        .into_iter()
        .find(|record| record.call_id == "call-foreground")
        .expect("audit record");
    assert_eq!(record.status, AuditStatus::Succeeded);
}

#[test]
fn background_process_exposes_incremental_output() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let process_id = supervisor
        .spawn("printf one; sleep 0.1; printf two", None, None)
        .expect("spawn");

    let first = wait_for_stdout(&supervisor, &process_id, "one", Duration::from_secs(2));
    assert_eq!(first.status, ProcessStatus::Running);
    let second = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert!(second.stdout.contains("onetwo"));
    assert_eq!(second.status, ProcessStatus::Succeeded);
}

#[test]
fn stdin_reaches_interactive_process_and_can_be_closed() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let process_id = supervisor
        .spawn("IFS= read -r line; printf 'got:%s' \"$line\"", None, None)
        .expect("spawn");
    supervisor
        .write_stdin(&process_id, b"hello\n", true)
        .expect("write stdin");
    let snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert_eq!(snapshot.status, ProcessStatus::Succeeded);
    assert_eq!(snapshot.stdout, "got:hello");
    assert!(!snapshot.stdin_open);
}

#[test]
fn timeout_terminates_the_process_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let process_id = supervisor
        .spawn("sleep 10", None, Some(Duration::from_millis(50)))
        .expect("spawn");
    let snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert_eq!(snapshot.status, ProcessStatus::TimedOut);
}

#[test]
fn explicit_cancellation_marks_process_cancelled() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let process_id = supervisor.spawn("sleep 10", None, None).expect("spawn");
    supervisor.kill(&process_id, None).expect("kill");
    let snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert_eq!(snapshot.status, ProcessStatus::Cancelled);
}

#[test]
fn kill_shell_terminates_descendants_in_the_process_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let process_id = supervisor
        .spawn(
            "sleep 10 & child=$!; printf '%s' \"$child\"; wait",
            None,
            None,
        )
        .expect("spawn");
    let running = wait_for_stdout(&supervisor, &process_id, "1", Duration::from_secs(2));
    let child_pid = running.stdout.trim().parse::<u32>().expect("child pid");

    supervisor
        .kill(&process_id, None)
        .expect("kill process group");
    let snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert_eq!(snapshot.status, ProcessStatus::Cancelled);
    thread::sleep(Duration::from_millis(50));
    let alive = Command::new("kill")
        .args(["-0", &child_pid.to_string()])
        .status()
        .is_ok_and(|status| status.success());
    assert!(!alive, "descendant process survived group cleanup");
}

#[test]
fn unknown_process_id_fails_clearly() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let error = supervisor
        .snapshot("proc_missing", None, None)
        .expect_err("unknown process must fail")
        .to_string();
    assert!(error.contains("unknown process id"));
}

#[test]
fn closed_stdin_fails_clearly() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = supervisor(workspace.path());
    let process_id = supervisor.spawn("cat", None, None).expect("spawn");
    supervisor.close_stdin(&process_id).expect("close stdin");
    let error = supervisor
        .write_stdin(&process_id, b"data", false)
        .expect_err("closed stdin must fail")
        .to_string();
    assert!(error.contains("stdin") && error.contains("closed"));
    let _snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
}

#[test]
fn output_is_bounded_and_exposes_artifact_reference() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = Arc::new(ProcessSupervisor::with_config(
        workspace.path(),
        None,
        None,
        ProcessSupervisorConfig {
            output_capacity: 64,
            poll_interval: Duration::from_millis(5),
            kill_grace: Duration::from_millis(100),
        },
    ));
    let process_id = supervisor
        .spawn("head -c 4096 /dev/zero | tr '\\0' x", None, None)
        .expect("spawn");
    let snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert!(snapshot.stdout_truncated);
    assert!(snapshot.stdout.len() <= 64);
    assert_eq!(snapshot.stdout_total_bytes, 4096);
    assert_eq!(snapshot.artifact_refs.len(), 1);
}

#[test]
fn registry_drop_cleans_up_session_owned_background_processes() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (policy, _audit) = policy(workspace.path(), PermissionMode::Bypass);
    let registry = ToolRegistry::new_with_devin_policy(
        &["exec", "get_output", "write_to_process", "kill_shell"],
        workspace.path(),
        None,
        &policy,
    )
    .expect("registry");
    let supervisor = Arc::clone(registry.process_supervisor().expect("supervisor"));
    let process_id = supervisor.spawn("sleep 10", None, None).expect("spawn");
    drop(registry);
    let snapshot = wait_for_terminal(&supervisor, &process_id, Duration::from_secs(2));
    assert_eq!(snapshot.status, ProcessStatus::Cancelled);
    assert_eq!(supervisor.active_process_count(), 0);
}

#[test]
fn process_policy_modes_remain_fail_closed() {
    let workspace = tempfile::tempdir().expect("workspace");

    let mut plan_state = DevinSessionState::new("plan", workspace.path());
    plan_state.agent_mode = AgentMode::Plan;
    plan_state.permission_mode = PermissionMode::Bypass;
    let plan = ToolPolicyEngine::new(Arc::new(RwLock::new(plan_state)));
    for name in ["exec", "shell_command", "write_to_process", "kill_shell"] {
        let decision = plan.evaluate(&pi::devin::ToolRequest {
            call_id: format!("plan-{name}"),
            tool_name: name.to_string(),
            arguments: json!({"command": "true", "process_id": "proc"}),
            origin: pi::devin::ToolRequestOrigin::Native,
        });
        assert_eq!(decision.action, pi::devin::PolicyAction::Deny);
    }

    let outside = tempfile::tempdir().expect("outside");
    let (bypass, _audit) = policy(workspace.path(), PermissionMode::Bypass);
    let decision = bypass.evaluate(&pi::devin::ToolRequest {
        call_id: "bypass-scope".to_string(),
        tool_name: "exec".to_string(),
        arguments: json!({"command": "pwd", "cwd": outside.path()}),
        origin: pi::devin::ToolRequestOrigin::Native,
    });
    assert_eq!(decision.action, pi::devin::PolicyAction::Deny);

    let mut autonomous_state = DevinSessionState::new("autonomous", workspace.path());
    autonomous_state.permission_mode = PermissionMode::Autonomous;
    autonomous_state.sandbox_status = SandboxStatus::Unavailable;
    let autonomous = ToolPolicyEngine::new(Arc::new(RwLock::new(autonomous_state)));
    let decision = autonomous.evaluate(&pi::devin::ToolRequest {
        call_id: "autonomous-no-sandbox".to_string(),
        tool_name: "exec".to_string(),
        arguments: json!({"command": "true"}),
        origin: pi::devin::ToolRequestOrigin::Native,
    });
    assert_eq!(decision.action, pi::devin::PolicyAction::Deny);
}
