//! Authenticated checkpoint for a consented configuration transaction. No paths
//! or commands are stored; a replay can only offer restoration after consent.
use crate::settings::{configuration_digest, Profile};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Stopping,
    Saving,
    Starting,
    Verifying,
    Restoring,
    Committed,
    Restored,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub format: u32,
    pub operation_id: String,
    pub before: Profile,
    pub before_digest: String,
    pub after_digest: String,
    pub target_port: u16,
    pub originally_active: bool,
    pub phase: Phase,
}
impl Record {
    pub fn new(id: &str, before: &Profile, after: &Profile, active: bool) -> Result<Self, String> {
        let record = Self {
            format: 1,
            operation_id: id.into(),
            before: before.clone(),
            before_digest: configuration_digest(before)?,
            after_digest: configuration_digest(after)?,
            target_port: after.settings.proxy_port,
            originally_active: active,
            phase: Phase::Prepared,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.before.validate()?;
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.format != 1
            || uuid::Uuid::parse_str(&self.operation_id).is_err()
            || !digest(&self.before_digest)
            || !digest(&self.after_digest)
            || configuration_digest(&self.before)? != self.before_digest
            || self.target_port < 1024
        {
            return Err("Журнал настройки повреждён или несовместим".into());
        }
        Ok(())
    }
    pub fn pending(&self) -> bool {
        !matches!(self.phase, Phase::Committed | Phase::Restored)
    }
    pub fn accepts(&self, current: &Profile) -> Result<bool, String> {
        self.validate()?;
        let digest = configuration_digest(current)?;
        Ok(digest == self.before_digest || digest == self.after_digest)
    }
}
