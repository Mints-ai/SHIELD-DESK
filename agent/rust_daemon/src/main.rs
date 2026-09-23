use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BreakGlassApproval {
    token_id: String,
    action: String,
    primary_approver: String,
    secondary_approver: String,
    target_host: String,
    issued_at: u64,
    expires_at: u64,
}

struct PrivilegedExecutionDaemon {
    named_superadmins: HashSet<String>,
    executed_tokens: Mutex<HashSet<String>>,
    audit_chain_head: Mutex<String>,
}

impl PrivilegedExecutionDaemon {
    fn new(superadmins: Vec<&str>) -> Self {
        let mut set = HashSet::new();
        for admin in superadmins {
            set.insert(admin.to_string());
        }
        Self {
            named_superadmins: set,
            executed_tokens: Mutex::new(HashSet::new()),
            audit_chain_head: Mutex::new("0".repeat(64)),
        }
    }

    /// Validates Tier 3 Break-Glass Action:
    /// 1. Must have two DISTINCT human approvers.
    /// 2. Both approvers MUST be on the verified Named SuperAdmin roster.
    /// 3. Token cannot be expired or replayed.
    fn authorize_tier3_execution(&self, approval: &BreakGlassApproval) -> Result<String, String> {
        // Enforce Separation of Duties (Two-Person Rule)
        if approval.primary_approver == approval.secondary_approver {
            return Err("TWO_PERSON_RULE_VIOLATION: Primary and secondary approvers cannot be identical.".to_string());
        }

        // Validate Named SuperAdmin Roster
        if !self.named_superadmins.contains(&approval.primary_approver) {
            return Err(format!("UNAUTHORIZED_APPROVER: '{}' is not on the Named SuperAdmin roster.", approval.primary_approver));
        }
        if !self.named_superadmins.contains(&approval.secondary_approver) {
            return Err(format!("UNAUTHORIZED_APPROVER: '{}' is not on the Named SuperAdmin roster.", approval.secondary_approver));
        }

        // Anti-Replay Check
        let mut executed = self.executed_tokens.lock().unwrap();
        if executed.contains(&approval.token_id) {
            return Err("TOKEN_REPLAY_ATTEMPT: This Tier 3 token has already been consumed.".to_string());
        }

        // Expiration Check
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > approval.expires_at {
            return Err("TOKEN_EXPIRED: Tier 3 break-glass window has lapsed.".to_string());
        }

        // Mark as consumed
        executed.insert(approval.token_id.clone());

        // Cryptographic Hash Chaining
        let mut chain_head = self.audit_chain_head.lock().unwrap();
        let payload_str = format!("{}|{}|{}|{}|{}",
            approval.token_id, approval.action, approval.primary_approver, approval.secondary_approver, approval.target_host);

        let mut hasher = Sha256::new();
        hasher.update(chain_head.as_bytes());
        hasher.update(payload_str.as_bytes());
        let new_hash = hex::encode(hasher.finalize());

        *chain_head = new_hash.clone();

        Ok(format!(
            "TIER_3_AUTHORIZED: Command '{}' released for host '{}'. Tamper-proof hash: {}",
            approval.action, approval.target_host, &new_hash[..16]
        ))
    }
}

// Minimal hex encoding helper without external hex crate
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

fn main() {
    println!("[ShieldDesk Tier 3 Daemon] Initializing Privileged Break-Glass Sentinel (Rust)...");

    // Phase 5 Named SuperAdmin roster
    let daemon = PrivilegedExecutionDaemon::new(vec!["anand-techdir", "sec-eng-01", "sec-eng-02"]);

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let sample_approval = BreakGlassApproval {
        token_id: "tok-tier3-breakglass-001".to_string(),
        action: "emergency_reboot_hypervisor".to_string(),
        primary_approver: "anand-techdir".to_string(),
        secondary_approver: "sec-eng-01".to_string(),
        target_host: "HV-HOST-FIN-01".to_string(),
        issued_at: now,
        expires_at: now + 3600,
    };

    match daemon.authorize_tier3_execution(&sample_approval) {
        Ok(msg) => println!("[Success] {}", msg),
        Err(err) => eprintln!("[Denied] {}", err),
    }

    println!("[ShieldDesk Tier 3 Daemon] Listening on secure IPC socket...");
}
