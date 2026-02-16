use std::path::PathBuf;
use std::sync::Arc;

use passkey_authenticator::{Authenticator, UiHint, UserCheck, UserValidationMethod};
use passkey_client::Client;
use passkey_types::ctap2::{Aaguid, Ctap2Error};
use passkey_types::Passkey;
use public_suffix::PublicSuffixList;
use tokio::sync::Mutex;

use crate::storage::SqliteStore;

/// User validation that always reports presence=true, verification=true.
pub struct AlwaysVerifyUser;

#[async_trait::async_trait]
impl UserValidationMethod for AlwaysVerifyUser {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _hint: UiHint<'a, Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

/// Type alias for our concrete Client type.
pub type WebAuthnClient = Client<SqliteStore, AlwaysVerifyUser, PublicSuffixList, ()>;

/// Wrapper around passkey-rs Client + Authenticator.
pub struct WebAuthnBackend {
    client: Arc<Mutex<WebAuthnClient>>,
}

impl WebAuthnBackend {
    pub fn new(db_path: PathBuf) -> Result<Self, String> {
        let store = SqliteStore::new(db_path)
            .map_err(|e| format!("Failed to open credential store: {e}"))?;

        let authenticator = Authenticator::new(Aaguid::new_empty(), store, AlwaysVerifyUser);
        let client = Client::new(authenticator);

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    pub fn client(&self) -> &Arc<Mutex<WebAuthnClient>> {
        &self.client
    }
}
