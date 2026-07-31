# Pi-Devin Rust parity progress

## Baseline

- Upstream: `Dicklesworthstone/pi_agent_rust`
- Pinned commit: `590d61899ae64e172f15d919632a9134ddec6fb6`
- Upstream version: `0.1.23`
- Implementation branch: `devin-rust-core`
- Writable fork: `OnlineChefGroep/pi_agent_rust`

The pristine `--all-features` check exposed an upstream `wasm-host` failure:
21 `Future + Send` errors converge on an `asupersync::sync::MutexGuard` held
across `await` in `src/extensions.rs`. This predates Pi-Devin changes. The
default-feature gate was stopped before completion when the project policy
changed to CI-only Rust validation.

The source-export worktree does not contain a Rust toolchain. The repository
verification lane therefore remains GitHub Actions using the pinned
`rust-toolchain.toml`; workflow/job results, not a combined status, are the
release gate.

## Implemented evidence

- Four ATIF-v1.7 transcripts exported by Devin `3000.2.17` expose the same 28
  function-calling tools. The installed binary at extraction time was
  `3000.3.22`; no current-version transcript was available.
- All four transcripts have identical JSON-schema hashes for every tool.
- `AgentMode` and `PermissionMode` are independent, session-scoped values.
- Devin mode, sandbox, workspace, and scope state round-trips through versioned
  custom session entries.
- Plan and Ask mode restrictions are policy decisions, not prompt decoration.
- Autonomous mode rejects activation without an active OS sandbox.
- Tool policy validates object arguments, classifies effects and risk, checks
  workspace/scoped paths, rejects traversal and symlink escapes, and returns
  allow, ask, deny, or sandbox.
- Native agent tool execution uses the same central policy gate before
  approvals, extension hooks, and tool execution.
- The Devin process surface (`exec`, `shell_command`, `get_output`,
  `write_to_process`, and `kill_shell`) is registered through `ToolRegistry`
  against one session-owned native supervisor. Foreground output follows the
  existing `ToolUpdate` route; background calls return a process ID and remain
  observable.
- Managed entries retain command/cwd/start metadata, process-group identity,
  stdin state, exit status, and bounded stdout/stderr windows. Large output is
  represented in audit by an artifact reference rather than copied into the
  audit record.
- Timeout, ambient cancellation, explicit kill, registry/session teardown, and
  drop cleanup terminate the complete process group, first with TERM and then
  KILL after a bounded grace period.
- Plan mode blocks process mutation tools. Normal and Smart require approval.
  Bypass still validates the process cwd against workspace/write scopes.
  Autonomous remains fail-closed without an active sandbox, and active-sandbox
  requests remain blocked until a real sandbox adapter exists.
- Audit records retain per-log salted argument hashes instead of raw arguments.
  Evaluation and execution update one record by `call_id` through pending,
  allowed/denied, succeeded/failed, cancelled, or timed-out states. A salt is
  owned by each `AuditLog`, so hashes are comparable only inside that log and
  are not cross-session fingerprints.

## Contract provenance

The four retained ATIF-v1.7 transcripts are pinned historical evidence from
Devin `3000.2.17`. The machine on which they were extracted had Devin
`3000.3.22` installed, but that does not make the transcripts evidence for
`3000.3.22`. A repository, public-web, and connected-library search on
2026-07-31 found no `3000.3.22` transcript whose provenance and digest could be
verified, so none was added. HiBench exposed a separate `3000.1.27` capture and
was not accepted as current-version parity evidence.

`tool_schema_manifest.json` retains the canonical parameter hashes extracted
from the four pinned transcripts. The original export did not retain the full
parameter objects. `process_tool_parameter_schemas.json` therefore records the
complete executable Rust contract together with those pinned hashes and
explicitly does not claim byte-for-byte reconstruction of the historical JSON.
Replacing that fixture with digest-verifiable transcript objects remains an
evidence upgrade, not a reason to leave the runtime tools schema-less.

## Remaining gaps

1. Expose persisted Devin state through TUI, ACP, and RPC.
2. Recover digest-verifiable full historical parameter objects and migrate the
   existing eight Pi tools behind the same canonical registry.
3. Implement persistent plan/todo tools.
4. Implement managed subagents, MCP, skills, hooks, and web/browser adapters.
5. Add disabled-by-default cloud XML parsing with no direct execution path.
6. Complete file mutation hashes/diffs and persistent audit/recovery sinks.
7. Run the end-to-end repository, plan, edit, background process, subagent,
   and MCP smoke test in CI.

## CI reproduction

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --test devin_contract --test devin_session_state
cargo test --test devin_process_supervisor
cargo test devin::
cargo test --all-targets
cargo build --release
```

The optional full-feature upstream defect remains separately reproducible with:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```
