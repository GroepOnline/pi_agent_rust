//! Bounded, secret-minimizing audit records for Devin tool calls.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Mutex;

use super::policy::{PolicyAction, RiskClass};

/// Coarse effect recorded without retaining sensitive arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    Read,
    Write,
    Process,
    Network,
    SessionState,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Pending,
    Allowed,
    Denied,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
}

/// Stable audit shape. Raw tool arguments and credentials are deliberately
/// excluded; callers store a canonical hash and redacted error text instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub call_id: String,
    pub session_id: String,
    pub parent_agent: Option<String>,
    pub tool_name: String,
    pub argument_hash: String,
    pub effects: Vec<ToolEffect>,
    pub risk: RiskClass,
    pub policy_action: PolicyAction,
    pub approval_source: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: AuditStatus,
    pub artifact_refs: Vec<String>,
    pub redacted_error: Option<String>,
}

/// In-memory bounded audit buffer. A persistent sink can consume these records
/// without changing policy or frontend code. Argument hashes use a random salt
/// owned by this log, so they are comparable only within this log and are not
/// cross-session fingerprints.
#[derive(Debug)]
pub struct AuditLog {
    capacity: usize,
    salt: [u8; 32],
    records: Mutex<VecDeque<AuditRecord>>,
}

impl AuditLog {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let mut salt = [0_u8; 32];
        salt[..16].copy_from_slice(first.as_bytes());
        salt[16..].copy_from_slice(second.as_bytes());
        Self {
            capacity: capacity.max(1),
            salt,
            records: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
        }
    }

    /// Insert a new record or replace the existing record for the same call.
    ///
    /// A tool call owns exactly one audit record for its complete lifecycle;
    /// repeated policy checks and execution updates therefore mutate in place.
    pub fn upsert(&self, record: AuditRecord) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = records
            .iter_mut()
            .find(|existing| existing.call_id == record.call_id)
        {
            *existing = record;
            return;
        }
        if records.len() == self.capacity {
            records.pop_front();
        }
        records.push_back(record);
    }

    /// Update the execution state for an existing call without appending a
    /// second record. Returns `false` when the call is unknown or when a
    /// different terminal outcome was already recorded.
    pub fn update(
        &self,
        call_id: &str,
        status: AuditStatus,
        approval_source: Option<String>,
        artifact_refs: Vec<String>,
        redacted_error: Option<String>,
    ) -> bool {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(record) = records
            .iter_mut()
            .find(|record| record.call_id == call_id)
        else {
            return false;
        };
        let current_terminal = matches!(
            record.status,
            AuditStatus::Denied
                | AuditStatus::Succeeded
                | AuditStatus::Failed
                | AuditStatus::Cancelled
                | AuditStatus::TimedOut
        );
        if current_terminal && record.status != status {
            return false;
        }
        record.status = status;
        if approval_source.is_some() {
            record.approval_source = approval_source;
        }
        if !artifact_refs.is_empty() {
            record.artifact_refs = artifact_refs;
        }
        if let Some(error) = redacted_error {
            record.redacted_error = Some(redact_error(&error));
        }
        if matches!(
            status,
            AuditStatus::Denied
                | AuditStatus::Succeeded
                | AuditStatus::Failed
                | AuditStatus::Cancelled
                | AuditStatus::TimedOut
        ) {
            record.ended_at.get_or_insert_with(Utc::now);
        }
        true
    }

    /// Finalize the newest open record for `call_id` once execution resolves.
    pub fn complete(&self, call_id: &str, status: AuditStatus, error: Option<String>) {
        let _updated = self.update(call_id, status, None, Vec::new(), error);
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn status(&self, call_id: &str) -> Option<AuditStatus> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|record| record.call_id == call_id)
            .map(|record| record.status)
    }

    #[must_use]
    pub(crate) fn hash_arguments(&self, arguments: &Value) -> String {
        argument_hash(arguments, &self.salt)
    }
}

/// Hash canonical JSON so equivalent object key order produces the same audit
/// identity while secret-bearing values never enter the record.
fn argument_hash(arguments: &Value, salt: &[u8; 32]) -> String {
    let canonical = canonical_json(arguments);
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(left, _)| *left);
            let body = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
    }
}

/// Redact common credential shapes before an error reaches an audit sink.
#[must_use]
pub fn redact_error(message: &str) -> String {
    let mut redact_next = false;
    message
        .split_whitespace()
        .map(|token| {
            if redact_next {
                redact_next = false;
                return "[REDACTED]";
            }
            let lower = token.to_ascii_lowercase();
            if lower.contains("token=")
                || lower.contains("password=")
                || lower.contains("secret=")
                || lower.contains("api_key=")
                || lower.contains("apikey=")
                || lower.starts_with("authorization:")
                || lower.starts_with("sk-")
            {
                "[REDACTED]"
            } else if lower == "bearer" {
                redact_next = true;
                "[REDACTED]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn argument_hash_is_independent_of_object_key_order() {
        let audit = AuditLog::new(8);
        assert_eq!(
            audit.hash_arguments(&json!({"a": 1, "b": {"x": true, "y": false}})),
            audit.hash_arguments(&json!({"b": {"y": false, "x": true}, "a": 1}))
        );
    }

    #[test]
    fn separate_audit_logs_use_distinct_hash_salts() {
        let arguments = json!({"token": "low-entropy"});
        assert_ne!(
            AuditLog::new(8).hash_arguments(&arguments),
            AuditLog::new(8).hash_arguments(&arguments)
        );
    }

    #[test]
    fn lifecycle_updates_replace_the_existing_call_record() {
        let audit = AuditLog::new(8);
        let now = Utc::now();
        let record = AuditRecord {
            call_id: "call-1".to_string(),
            session_id: "session".to_string(),
            parent_agent: None,
            tool_name: "exec".to_string(),
            argument_hash: "hash".to_string(),
            effects: vec![ToolEffect::Process],
            risk: RiskClass::Critical,
            policy_action: PolicyAction::Allow,
            approval_source: None,
            started_at: now,
            ended_at: None,
            status: AuditStatus::Pending,
            artifact_refs: Vec::new(),
            redacted_error: None,
        };
        audit.upsert(record.clone());
        audit.upsert(record);
        assert_eq!(audit.snapshot().len(), 1);
        assert!(audit.update(
            "call-1",
            AuditStatus::TimedOut,
            Some("policy".to_string()),
            vec!["artifact://output".to_string()],
            Some("token=secret timed out".to_string()),
        ));
        let records = audit.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, AuditStatus::TimedOut);
        assert_eq!(records[0].approval_source.as_deref(), Some("policy"));
        assert_eq!(records[0].artifact_refs, vec!["artifact://output"]);
        assert_eq!(records[0].redacted_error.as_deref(), Some("[REDACTED] timed out"));
        assert!(records[0].ended_at.is_some());
    }

    #[test]
    fn redacts_common_secret_tokens() {
        let redacted = redact_error("failed token=abc password=hunter2 Bearer abc sk-example");
        assert_eq!(
            redacted,
            "failed [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]"
        );
    }
}
