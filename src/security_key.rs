//! Connexion en deux étapes par clé de sécurité FIDO2 (WebAuthn), par USB
//! (hidraw) ou par NFC (lecteurs PC/SC, via `pcscd`).
//!
//! Le serveur fournit des options d'assertion WebAuthn; la clé les signe avec
//! un `clientDataJSON` dont l'origine est celle du coffre web. La réponse est
//! renvoyée au serveur, en JSON, comme jeton 2FA du fournisseur WebAuthn.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use futures::StreamExt as _;
use webauthn_authenticator_rs::{
    AuthenticatorBackend,
    ctap2::CtapAuthenticator,
    prelude::{RequestChallengeResponse, Url, WebauthnAuthenticator, WebauthnCError},
    transport::{AnyTransport, TokenEvent, Transport as _},
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
};

/// Délai laissé pour brancher ou approcher la clé, puis la toucher.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Événements envoyés à l'interface pendant l'opération.
#[derive(Debug)]
pub enum KeyEvent {
    /// Aucune clé détectée : l'utilisateur doit la brancher ou l'approcher.
    Waiting,
    /// La clé attend d'être touchée.
    Touch,
    /// La clé traite la demande.
    Processing,
    /// La clé exige son NIP; répondre `None` pour annuler.
    Pin(mpsc::Sender<Option<String>>),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Aucune clé de sécurité détectée à temps.")]
    Timeout,
    #[error("Opération annulée.")]
    Cancelled,
    #[error("Cette clé n'est pas enregistrée pour ce compte.")]
    UnknownCredential,
    #[error("Défi WebAuthn invalide : {0}")]
    BadChallenge(String),
    #[error("Clé de sécurité : {0}")]
    Device(String),
}

impl From<WebauthnCError> for KeyError {
    fn from(e: WebauthnCError) -> Self {
        use webauthn_authenticator_rs::error::CtapError;
        match e {
            WebauthnCError::Ctap(CtapError::Ctap2NoCredentials) => Self::UnknownCredential,
            WebauthnCError::Ctap(
                CtapError::Ctap2UserActionTimeout | CtapError::Ctap2ActionTimeout,
            ) => Self::Timeout,
            WebauthnCError::Cancelled | WebauthnCError::Ctap(CtapError::Ctap2OperationDenied) => {
                Self::Cancelled
            }
            e => Self::Device(format!("{e:?}")),
        }
    }
}

/// Convertit les options renvoyées par le serveur (Bitwarden ou Vaultwarden)
/// en requête WebAuthn.
pub fn parse_options(options: serde_json::Value) -> Result<RequestChallengeResponse, KeyError> {
    // Les deux serveurs renvoient directement `PublicKeyCredentialRequestOptions`;
    // on accepte aussi la forme enveloppée `{ "publicKey": … }`.
    let wrapped = if options.get("publicKey").is_some() {
        options
    } else {
        serde_json::json!({ "publicKey": options })
    };
    serde_json::from_value(wrapped).map_err(|e| KeyError::BadChallenge(e.to_string()))
}

/// Signe le défi avec `backend` et retourne la réponse JSON attendue par le serveur.
pub fn assert_with<B: AuthenticatorBackend>(
    backend: B,
    origin: Url,
    options: RequestChallengeResponse,
) -> Result<String, KeyError> {
    let credential = WebauthnAuthenticator::new(backend).do_authentication(origin, options)?;
    serde_json::to_string(&credential).map_err(|e| KeyError::Device(e.to_string()))
}

/// Pont entre les rappels de la bibliothèque CTAP et l'interface GTK.
#[derive(Debug)]
struct ChannelUi {
    events: async_channel::Sender<KeyEvent>,
    cancelled: Arc<AtomicBool>,
}

impl UiCallback for ChannelUi {
    fn request_pin(&self) -> Option<String> {
        let (tx, rx) = mpsc::channel();
        self.events.send_blocking(KeyEvent::Pin(tx)).ok()?;
        rx.recv_timeout(Duration::from_secs(120)).ok().flatten()
    }

    fn request_touch(&self) {
        let _ = self.events.try_send(KeyEvent::Touch);
    }

    fn processing(&self) {
        let _ = self.events.try_send(KeyEvent::Processing);
    }

    fn fingerprint_enrollment_feedback(&self, _: u32, _: Option<EnrollSampleStatus>) {}

    fn cable_qr_code(&self, _: CableRequestType, _: String) {}

    fn dismiss_qr_code(&self) {}

    fn cable_status_update(&self, _: CableState) {}
}

/// Attend une clé FIDO2 (USB ou NFC) puis signe le défi. Bloquant : à exécuter
/// hors du fil principal. `cancelled` permet d'abandonner l'attente.
pub fn authenticate(
    origin: Url,
    options: RequestChallengeResponse,
    events: async_channel::Sender<KeyEvent>,
    cancelled: Arc<AtomicBool>,
) -> Result<String, KeyError> {
    // La bibliothèque appelle `futures::executor::block_on` en interne : un
    // environnement multi-fil garde le pilote d'entrées-sorties actif.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| KeyError::Device(e.to_string()))?;
    let ui = ChannelUi {
        events: events.clone(),
        cancelled: cancelled.clone(),
    };
    runtime.block_on(async {
        let transport = AnyTransport::new().await?;
        let mut tokens = transport.watch().await?;
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        let authenticator = loop {
            if ui.cancelled.load(Ordering::Relaxed) {
                return Err(KeyError::Cancelled);
            }
            // Réveil périodique pour tenir compte d'une annulation.
            let wait = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_millis(500));
            if wait.is_zero() {
                return Err(KeyError::Timeout);
            }
            match tokio::time::timeout(wait, tokens.next()).await {
                Err(_) => continue,
                Ok(None) => return Err(KeyError::Timeout),
                Ok(Some(TokenEvent::EnumerationComplete)) => {
                    let _ = events.try_send(KeyEvent::Waiting);
                }
                Ok(Some(TokenEvent::Removed(_))) => {}
                Ok(Some(TokenEvent::Added(token))) => {
                    if let Some(authenticator) = CtapAuthenticator::new(token, &ui).await {
                        break authenticator;
                    }
                }
            }
        };
        let _ = events.try_send(KeyEvent::Touch);
        tokio::task::block_in_place(|| assert_with(authenticator, origin, options))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_bitwarden_et_vaultwarden() {
        let raw = serde_json::json!({
            "challenge": "AAECAwQFBgcICQoLDA0ODw",
            "timeout": 60000,
            "rpId": "vault.bitwarden.com",
            "allowCredentials": [{ "type": "public-key", "id": "AQID" }],
            "userVerification": "discouraged",
            "extensions": {},
            "status": "ok",
            "errorMessage": ""
        });
        let request = parse_options(raw.clone()).unwrap();
        assert_eq!(request.public_key.rp_id, "vault.bitwarden.com");
        assert_eq!(request.public_key.allow_credentials.len(), 1);
        let wrapped = parse_options(serde_json::json!({ "publicKey": raw })).unwrap();
        assert_eq!(wrapped.public_key.rp_id, "vault.bitwarden.com");
    }

    #[test]
    fn options_invalides() {
        assert!(parse_options(serde_json::json!({ "rpId": 3 })).is_err());
    }
}
