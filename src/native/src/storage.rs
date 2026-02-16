use std::path::PathBuf;
use std::sync::Arc;

use coset::CborSerializable;
use passkey_authenticator::{CredentialStore, DiscoverabilitySupport, StoreInfo};
use passkey_types::ctap2::get_assertion::Options;
use passkey_types::ctap2::make_credential::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};
use passkey_types::ctap2::{Ctap2Error, StatusCode};
use passkey_types::webauthn::PublicKeyCredentialDescriptor;
use passkey_types::{Bytes, CredentialExtensions, Passkey};
use rusqlite::{params, Connection};
use tokio::sync::Mutex;

/// SQLite-backed credential store for passkeys.
/// Stores each Passkey field individually since Passkey doesn't implement Serialize.
/// CoseKey is serialized via coset's CborSerializable trait.
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn new(db_path: PathBuf) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(&db_path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS credentials (
                id              BLOB PRIMARY KEY,
                rp_id           TEXT NOT NULL,
                user_handle     BLOB,
                username        TEXT,
                user_display    TEXT,
                key_cbor        BLOB NOT NULL,
                counter         INTEGER,
                created_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );
            CREATE INDEX IF NOT EXISTS idx_rp_id ON credentials(rp_id);",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn conn(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }
}

fn cose_key_to_cbor(key: &coset::CoseKey) -> Result<Vec<u8>, StatusCode> {
    key.clone()
        .to_vec()
        .map_err(|_| Ctap2Error::InvalidCbor.into())
}

fn cose_key_from_cbor(data: &[u8]) -> Result<coset::CoseKey, StatusCode> {
    coset::CoseKey::from_slice(data).map_err(|_| Ctap2Error::InvalidCbor.into())
}

fn passkey_from_row(
    cred_id: Vec<u8>,
    rp_id: String,
    user_handle: Option<Vec<u8>>,
    username: Option<String>,
    user_display: Option<String>,
    key_cbor: Vec<u8>,
    counter: Option<u32>,
) -> Result<Passkey, StatusCode> {
    let key = cose_key_from_cbor(&key_cbor)?;
    Ok(Passkey {
        key,
        credential_id: Bytes::from(cred_id),
        rp_id,
        user_handle: user_handle.map(Bytes::from),
        username,
        user_display_name: user_display,
        counter,
        extensions: CredentialExtensions::default(),
    })
}

type CredRow = (Vec<u8>, String, Option<Vec<u8>>, Option<String>, Option<String>, Vec<u8>, Option<u32>);

#[async_trait::async_trait]
impl CredentialStore for SqliteStore {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        _user_handle: Option<&[u8]>,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        let conn = self.conn.lock().await;
        let mut passkeys = Vec::new();

        if let Some(ids) = ids {
            for desc in ids {
                let id_bytes: &[u8] = &desc.id;
                let result: Option<CredRow> = conn
                    .query_row(
                        "SELECT id, rp_id, user_handle, username, user_display, key_cbor, counter FROM credentials WHERE id = ?1 AND rp_id = ?2",
                        params![id_bytes, rp_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
                    )
                    .ok();
                if let Some((cred_id, rp, uh, un, ud, kc, ctr)) = result {
                    if let Ok(passkey) = passkey_from_row(cred_id, rp, uh, un, ud, kc, ctr) {
                        passkeys.push(passkey);
                    }
                }
            }
        } else {
            // Discoverable credential lookup: find all credentials for this rpId
            let mut stmt = conn
                .prepare("SELECT id, rp_id, user_handle, username, user_display, key_cbor, counter FROM credentials WHERE rp_id = ?1 ORDER BY created_at DESC")
                .map_err(|_| -> StatusCode { Ctap2Error::InvalidCbor.into() })?;
            let rows = stmt
                .query_map(params![rp_id], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Option<u32>>(6)?,
                    ))
                })
                .map_err(|_| -> StatusCode { Ctap2Error::InvalidCbor.into() })?;
            for row in rows.flatten() {
                let (cred_id, rp, uh, un, ud, kc, ctr) = row;
                if let Ok(passkey) = passkey_from_row(cred_id, rp, uh, un, ud, kc, ctr) {
                    passkeys.push(passkey);
                }
            }
        }

        if passkeys.is_empty() {
            Err(Ctap2Error::NoCredentials.into())
        } else {
            Ok(passkeys)
        }
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        _rp: PublicKeyCredentialRpEntity,
        _options: Options,
    ) -> Result<(), StatusCode> {
        let conn = self.conn.lock().await;
        let cred_id: &[u8] = &cred.credential_id;
        let rp_id = &cred.rp_id;
        let user_handle: &[u8] = &user.id;
        let user_name = user.name.as_deref();
        let user_display = user.display_name.as_deref();
        let key_cbor = cose_key_to_cbor(&cred.key)?;
        let counter = cred.counter;

        conn.execute(
            "INSERT OR REPLACE INTO credentials (id, rp_id, user_handle, username, user_display, key_cbor, counter)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![cred_id, rp_id, user_handle, user_name, user_display, key_cbor, counter],
        )
        .map_err(|_| -> StatusCode { Ctap2Error::InvalidCbor.into() })?;

        Ok(())
    }

    async fn update_credential(&mut self, cred: &Self::PasskeyItem) -> Result<(), StatusCode> {
        let conn = self.conn.lock().await;
        let cred_id: &[u8] = &cred.credential_id;
        let key_cbor = cose_key_to_cbor(&cred.key)?;
        let counter = cred.counter;

        conn.execute(
            "UPDATE credentials SET key_cbor = ?1, counter = ?2 WHERE id = ?3",
            params![key_cbor, counter, cred_id],
        )
        .map_err(|_| -> StatusCode { Ctap2Error::InvalidCbor.into() })?;

        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

/// Info about a stored credential, for listing purposes.
#[derive(serde::Serialize)]
pub struct StoredCredentialInfo {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Option<Vec<u8>>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub created_at: i64,
}

/// List stored credentials, optionally filtered by rpId.
pub async fn list_credentials(
    conn: &Arc<Mutex<Connection>>,
    rp_id: Option<&str>,
) -> Result<Vec<StoredCredentialInfo>, String> {
    let conn = conn.lock().await;
    let mut results = Vec::new();

    if let Some(rp) = rp_id {
        let mut stmt = conn
            .prepare("SELECT id, rp_id, user_handle, username, user_display, created_at FROM credentials WHERE rp_id = ?1 ORDER BY created_at DESC")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![rp], |row| {
                Ok(StoredCredentialInfo {
                    credential_id: row.get(0)?,
                    rp_id: row.get(1)?,
                    user_handle: row.get(2)?,
                    user_name: row.get(3)?,
                    user_display_name: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in rows.flatten() {
            results.push(row);
        }
    } else {
        let mut stmt = conn
            .prepare("SELECT id, rp_id, user_handle, username, user_display, created_at FROM credentials ORDER BY created_at DESC")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(StoredCredentialInfo {
                    credential_id: row.get(0)?,
                    rp_id: row.get(1)?,
                    user_handle: row.get(2)?,
                    user_name: row.get(3)?,
                    user_display_name: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in rows.flatten() {
            results.push(row);
        }
    }

    Ok(results)
}
