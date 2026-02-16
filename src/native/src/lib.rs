mod authenticator;
mod storage;

use std::path::PathBuf;
use std::sync::OnceLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use coset::iana::EnumI64;
use napi_derive::napi;
use passkey_client::DefaultClientData;
use passkey_types::webauthn::*;
use passkey_types::Bytes;

use authenticator::WebAuthnBackend;
use storage::list_credentials;

/// Global backend instance, initialized once.
static BACKEND: OnceLock<WebAuthnBackend> = OnceLock::new();

fn get_backend() -> napi::Result<&'static WebAuthnBackend> {
    BACKEND
        .get()
        .ok_or_else(|| napi::Error::from_reason("WebAuthn backend not initialized. Call initialize() first."))
}

// --- Types exposed to JS via napi ---

#[napi(object)]
pub struct PubKeyCredParam {
    pub r#type: String,
    pub alg: i32,
}

#[napi(object)]
pub struct CredentialDescriptor {
    /// base64url-encoded credential ID
    pub id: String,
    pub r#type: String,
}

#[napi(object)]
pub struct AuthenticatorSelectionOpts {
    pub resident_key: Option<String>,
    pub user_verification: Option<String>,
    pub authenticator_attachment: Option<String>,
}

#[napi(object)]
pub struct CreateCredentialOptions {
    pub origin: String,
    pub rp_id: String,
    pub rp_name: String,
    /// base64url-encoded user ID
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    /// base64url-encoded challenge
    pub challenge: String,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub exclude_credentials: Option<Vec<CredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionOpts>,
    pub timeout: Option<u32>,
}

#[napi(object)]
pub struct GetAssertionOptions {
    pub origin: String,
    pub rp_id: String,
    /// base64url-encoded challenge
    pub challenge: String,
    pub allow_credentials: Option<Vec<CredentialDescriptor>>,
    pub user_verification: Option<String>,
    pub timeout: Option<u32>,
}

#[napi(object)]
pub struct CreateCredentialResult {
    /// base64url-encoded credential ID
    pub credential_id: String,
    /// base64url-encoded raw ID
    pub raw_id: String,
    /// base64url-encoded attestation object
    pub attestation_object: String,
    /// base64url-encoded client data JSON
    pub client_data_json: String,
    /// Credential type, always "public-key"
    pub r#type: String,
    /// base64url-encoded authenticator data
    pub authenticator_data: String,
    /// Transports
    pub transports: Vec<String>,
    /// base64url-encoded public key DER (SubjectPublicKeyInfo)
    pub public_key: Option<String>,
    /// COSE algorithm identifier
    pub public_key_algorithm: i64,
}

#[napi(object)]
pub struct GetAssertionResult {
    /// base64url-encoded credential ID
    pub credential_id: String,
    /// base64url-encoded raw ID
    pub raw_id: String,
    /// base64url-encoded authenticator data
    pub authenticator_data: String,
    /// base64url-encoded client data JSON
    pub client_data_json: String,
    /// base64url-encoded signature
    pub signature: String,
    /// base64url-encoded user handle (may be empty)
    pub user_handle: Option<String>,
    /// Credential type
    pub r#type: String,
}

#[napi(object)]
pub struct StoredCredential {
    /// base64url-encoded credential ID
    pub credential_id: String,
    pub rp_id: String,
    /// base64url-encoded user handle
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub created_at: i64,
}

// --- Helpers ---

fn b64decode(s: &str) -> napi::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| napi::Error::from_reason(format!("Invalid base64url: {e}")))
}

fn b64encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn parse_resident_key(s: &str) -> ResidentKeyRequirement {
    match s {
        "required" => ResidentKeyRequirement::Required,
        "preferred" => ResidentKeyRequirement::Preferred,
        "discouraged" => ResidentKeyRequirement::Discouraged,
        _ => ResidentKeyRequirement::Preferred,
    }
}

fn parse_user_verification(s: &str) -> UserVerificationRequirement {
    match s {
        "required" => UserVerificationRequirement::Required,
        "preferred" => UserVerificationRequirement::Preferred,
        "discouraged" => UserVerificationRequirement::Discouraged,
        _ => UserVerificationRequirement::Preferred,
    }
}

// --- napi functions ---

/// Initialize the WebAuthn native backend with a path to store credentials.
#[napi]
pub fn initialize(storage_path: String) -> napi::Result<()> {
    let db_path = PathBuf::from(&storage_path).join("webauthn_credentials.db");

    // Create parent dirs if needed
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| napi::Error::from_reason(format!("Failed to create storage directory: {e}")))?;
    }

    let backend = WebAuthnBackend::new(db_path)
        .map_err(|e| napi::Error::from_reason(e))?;

    BACKEND.set(backend).map_err(|_| {
        napi::Error::from_reason("WebAuthn backend already initialized")
    })?;

    Ok(())
}

/// Create a new WebAuthn credential (registration).
#[napi]
pub async fn create_credential(options: CreateCredentialOptions) -> napi::Result<CreateCredentialResult> {
    let backend = get_backend()?;
    let mut client = backend.client().lock().await;

    let challenge = Bytes::from(b64decode(&options.challenge)?);
    let user_id = Bytes::from(b64decode(&options.user_id)?);

    let exclude: Option<Vec<PublicKeyCredentialDescriptor>> = {
        let list: Vec<PublicKeyCredentialDescriptor> = options
            .exclude_credentials
            .unwrap_or_default()
            .into_iter()
            .map(|c| -> napi::Result<PublicKeyCredentialDescriptor> {
                Ok(PublicKeyCredentialDescriptor {
                    ty: PublicKeyCredentialType::PublicKey,
                    id: Bytes::from(b64decode(&c.id)?),
                    transports: None,
                })
            })
            .collect::<napi::Result<Vec<_>>>()?;
        if list.is_empty() { None } else { Some(list) }
    };

    let pub_key_params: Vec<PublicKeyCredentialParameters> = options
        .pub_key_cred_params
        .into_iter()
        .map(|p| PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg: coset::iana::Algorithm::from_i64(p.alg as i64)
                .unwrap_or(coset::iana::Algorithm::ES256),
        })
        .collect();

    let auth_selection = options.authenticator_selection.map(|sel| {
        AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: Some(parse_resident_key(
                sel.resident_key.as_deref().unwrap_or("preferred"),
            )),
            require_resident_key: false,
            user_verification: parse_user_verification(
                sel.user_verification.as_deref().unwrap_or("preferred"),
            ),
        }
    });

    let creation_options = CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: Some(options.rp_id.clone()),
                name: options.rp_name,
            },
            user: PublicKeyCredentialUserEntity {
                id: user_id,
                display_name: options.user_display_name,
                name: options.user_name,
            },
            challenge,
            pub_key_cred_params: pub_key_params,
            timeout: options.timeout,
            exclude_credentials: exclude,
            authenticator_selection: auth_selection,
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    let origin = url::Url::parse(&options.origin)
        .map_err(|e| napi::Error::from_reason(format!("Invalid origin: {e}")))?;

    let result = client
        .register(&origin, creation_options, DefaultClientData)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Registration failed: {e:?}")))?;

    let response = &result.response;

    let transports: Vec<String> = response
        .transports
        .as_ref()
        .map(|t| t.iter().map(|tr| format!("{tr:?}").to_lowercase()).collect())
        .unwrap_or_else(|| vec!["internal".to_string()]);

    Ok(CreateCredentialResult {
        credential_id: result.id.clone(),
        raw_id: b64encode(&result.raw_id),
        attestation_object: b64encode(&response.attestation_object),
        client_data_json: b64encode(&response.client_data_json),
        r#type: "public-key".to_string(),
        authenticator_data: b64encode(&response.authenticator_data),
        transports,
        public_key: response.public_key.as_ref().map(|pk| b64encode(pk)),
        public_key_algorithm: response.public_key_algorithm,
    })
}

/// Get a WebAuthn assertion (authentication).
#[napi]
pub async fn get_assertion(options: GetAssertionOptions) -> napi::Result<GetAssertionResult> {
    let backend = get_backend()?;
    let mut client = backend.client().lock().await;

    let challenge = Bytes::from(b64decode(&options.challenge)?);

    let allow: Option<Vec<PublicKeyCredentialDescriptor>> = {
        let list: Vec<PublicKeyCredentialDescriptor> = options
            .allow_credentials
            .unwrap_or_default()
            .into_iter()
            .map(|c| -> napi::Result<PublicKeyCredentialDescriptor> {
                Ok(PublicKeyCredentialDescriptor {
                    ty: PublicKeyCredentialType::PublicKey,
                    id: Bytes::from(b64decode(&c.id)?),
                    transports: None,
                })
            })
            .collect::<napi::Result<Vec<_>>>()?;
        if list.is_empty() { None } else { Some(list) }
    };

    let request_options = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge,
            timeout: options.timeout,
            rp_id: Some(options.rp_id.clone()),
            allow_credentials: allow,
            user_verification: parse_user_verification(
                options.user_verification.as_deref().unwrap_or("preferred"),
            ),
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    let origin = url::Url::parse(&options.origin)
        .map_err(|e| napi::Error::from_reason(format!("Invalid origin: {e}")))?;

    let result = client
        .authenticate(&origin, request_options, DefaultClientData)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Authentication failed: {e:?}")))?;

    let response = &result.response;

    Ok(GetAssertionResult {
        credential_id: result.id.clone(),
        raw_id: b64encode(&result.raw_id),
        authenticator_data: b64encode(&response.authenticator_data),
        client_data_json: b64encode(&response.client_data_json),
        signature: b64encode(&response.signature),
        user_handle: response.user_handle.as_ref().map(|uh| b64encode(uh)),
        r#type: "public-key".to_string(),
    })
}

/// List stored credentials, optionally filtered by rpId.
#[napi]
pub async fn list_stored_credentials(rp_id: Option<String>) -> napi::Result<Vec<StoredCredential>> {
    let backend = get_backend()?;
    let client = backend.client().lock().await;
    let store = client.authenticator().store();
    let conn = store.conn();

    let infos = list_credentials(conn, rp_id.as_deref())
        .await
        .map_err(|e| napi::Error::from_reason(e))?;

    Ok(infos
        .into_iter()
        .map(|info| StoredCredential {
            credential_id: b64encode(&info.credential_id),
            rp_id: info.rp_id,
            user_handle: info.user_handle.as_ref().map(|uh| b64encode(uh)),
            user_name: info.user_name,
            user_display_name: info.user_display_name,
            created_at: info.created_at,
        })
        .collect())
}
