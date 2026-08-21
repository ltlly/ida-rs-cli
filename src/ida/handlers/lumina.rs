//! Lumina metadata lookup and application.

use idalib::lumina::{self, PullStatus};
use idalib::IDB;
use serde_json::{json, Value};

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;

fn status_name(status: PullStatus) -> String {
    match status {
        PullStatus::BadPattern => "bad_pattern".to_string(),
        PullStatus::NotFound => "not_found".to_string(),
        PullStatus::Error => "error".to_string(),
        PullStatus::Ok => "ok".to_string(),
        PullStatus::Added => "added".to_string(),
        PullStatus::Unknown(code) => format!("unknown_{code}"),
    }
}

pub fn handle_pull(
    idb: &Option<IDB>,
    allow_lumina: bool,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    apply: bool,
    force: bool,
) -> Result<Value, ToolError> {
    if !allow_lumina {
        return Err(ToolError::InvalidParams(
            "Lumina access is disabled; restart ida-mcp with --allow-lumina or \
             IDA_MCP_ALLOW_LUMINA=true"
                .to_string(),
        ));
    }

    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let requested_address = resolve_address(idb, addr, name, offset)?;
    let function = db
        .function_at(requested_address)
        .ok_or(ToolError::FunctionNotFound(requested_address))?;
    let address = function.start_address();
    let previous_name = function.name();
    let result = lumina::pull(address, apply, force)?;
    let current_name = db.function_at(address).and_then(|func| func.name());

    Ok(json!({
        "address": format!("{address:#x}"),
        "status": status_name(result.status),
        "matched_name": result.name,
        "matched_size": result.size,
        "frequency": result.frequency,
        "score": result.score,
        "metadata_keys": result.metadata_keys,
        "applied": result.applied,
        "force": force,
        "backup_created": result.backup_created,
        "previous_name": previous_name,
        "current_name": current_name,
        "error": result.error,
    }))
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::handlers::lumina::{handle_pull, status_name};
    use idalib::lumina::PullStatus;

    #[test]
    fn unknown_status_keeps_raw_code() {
        assert_eq!(status_name(PullStatus::Unknown(17)), "unknown_17");
    }

    #[test]
    fn disabled_lumina_is_rejected_before_database_access() {
        let err = handle_pull(&None, false, Some(0x1000), None, 0, false, false)
            .expect_err("disabled Lumina access must be rejected");

        assert!(matches!(
            err,
            ToolError::InvalidParams(message) if message.contains("--allow-lumina")
        ));
    }
}
