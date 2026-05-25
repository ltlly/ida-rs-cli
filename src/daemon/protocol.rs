//! JSON-line protocol for daemon IPC.
//!
//! Request format:  {"id": "uuid", "op": "command_name", "params": {...}, "target": "selector"}
//! Response format: {"id": "uuid", "ok": true/false, "result": ..., "error": "..."}

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A request from the CLI client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request ID (for correlating responses)
    pub id: String,
    /// Operation name (maps to CLI subcommands)
    pub op: String,
    /// Operation parameters
    #[serde(default)]
    pub params: Value,
    /// Target selector (target ID, filename, or "active")
    #[serde(default)]
    pub target: Option<String>,
}

/// A response from the daemon to the CLI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Correlating request ID
    pub id: String,
    /// Whether the operation succeeded
    pub ok: bool,
    /// Result payload (on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error message (on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn success(id: String, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: String, msg: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(msg.into()),
        }
    }
}
