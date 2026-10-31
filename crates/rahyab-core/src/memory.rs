//! Persistent learning: which candidates won, how fast they were, and who is in a
//! temporary cooldown after repeated failures. This is what makes the app *get better*
//! the longer it runs on a given network.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastGood {
    pub id: String,
    pub at: u64,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Memory {
    #[serde(default)]
    pub last_good: Option<LastGood>,
    /// EMA of latency in ms per candidate id.
    #[serde(default)]
    pub latency_ms: HashMap<String, u64>,
    #[serde(default)]
    pub wins: HashMap<String, u64>,
    #[serde(default)]
    pub fails: HashMap<String, u64>,
    /// Candidate id → unix timestamp until which it is skipped.
    #[serde(default)]
    pub cooldown_until: HashMap<String, u64>,
    /// Environment (as string) of the last successful connect, for fast re-classification.
    #[serde(default)]
    pub last_env: Option<String>,
}

impl Memory {
    pub fn load(path: &Path) -> Memory {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, s).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    pub fn note_win(&mut self, id: &str, latency_ms: u64, env: &str) {
        *self.wins.entry(id.to_string()).or_insert(0) += 1;
        self.fails.remove(id);
        self.cooldown_until.remove(id);
        let ema = self.latency_ms.entry(id.to_string()).or_insert(latency_ms);
        *ema = (*ema * 3 + latency_ms) / 4;
        self.last_good = Some(LastGood { id: id.to_string(), at: now_unix(), latency_ms });
        self.last_env = Some(env.to_string());
    }

    pub fn note_fail(&mut self, id: &str) {
        *self.fails.entry(id.to_string()).or_insert(0) += 1;
        let fails = *self.fails.get(id).unwrap_or(&0);
        // 3 consecutive failures → 2 min cooldown; grows with repeated failure.
        if fails >= 3 {
            let penalty = 120u64.saturating_mul(fails.saturating_sub(2).min(10));
            self.cooldown_until
                .insert(id.to_string(), now_unix() + penalty);
        }
    }

    pub fn in_cooldown(&self, id: &str) -> bool {
        self.cooldown_until
            .get(id)
            .map(|&until| now_unix() < until)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_after_repeated_fails() {
        let mut m = Memory::default();
        let id = "cand-1";
        m.note_fail(id);
        m.note_fail(id);
        assert!(!m.in_cooldown(id));
        m.note_fail(id);
        assert!(m.in_cooldown(id));
    }

    #[test]
    fn win_clears_cooldown_and_tracks_latency() {
        let mut m = Memory::default();
        m.note_fail("x");
        m.note_fail("x");
        m.note_fail("x");
        m.note_win("x", 300, "open");
        assert!(!m.in_cooldown("x"));
        assert_eq!(m.latency_ms["x"], 300);
        assert_eq!(m.last_good.as_ref().unwrap().id, "x");
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rahyab-test-{}", std::process::id()));
        let path = dir.join("mem.json");
        let mut m = Memory::default();
        m.note_win("abc", 120, "cdn-only");
        m.save(&path);
        let m2 = Memory::load(&path);
        assert_eq!(m2.last_good.as_ref().unwrap().id, "abc");
        let _ = std::fs::remove_dir_all(dir);
    }
}
