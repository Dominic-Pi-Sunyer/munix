//! The Vault: credentials only the Tool Proxy reads. The agent only ever sees placeholders.

use std::collections::BTreeMap;
use std::fmt;

use munix_core::ids::VaultRef;

/// A secret. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    pub fn new(secret: impl Into<String>) -> Self {
        Credential(secret.into())
    }

    /// The secret itself, for the tool that needs it. Never log the result.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

/// Credentials keyed by their `vault://` reference.
#[derive(Debug, Default)]
pub struct Vault {
    entries: BTreeMap<VaultRef, Credential>,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, at: VaultRef, credential: Credential) {
        self.entries.insert(at, credential);
    }

    pub fn with(mut self, at: VaultRef, credential: Credential) -> Self {
        self.insert(at, credential);
        self
    }

    pub fn contains(&self, at: &VaultRef) -> bool {
        self.entries.contains_key(at)
    }

    pub fn get(&self, at: &VaultRef) -> Option<&Credential> {
        self.entries.get(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_show_in_debug() {
        let at: VaultRef = "vault://mail/demo".parse().unwrap();
        let vault = Vault::new().with(at.clone(), Credential::new("s3cret-token"));
        assert!(!format!("{vault:?}").contains("s3cret-token"));
        assert_eq!(
            vault.get(&at).map(Credential::expose_secret),
            Some("s3cret-token")
        );
    }
}
