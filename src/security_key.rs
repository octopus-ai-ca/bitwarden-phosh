//! Connexion en deux étapes par clé de sécurité FIDO2 (WebAuthn), par USB
//! (hidraw) ou par NFC : lecteurs PC/SC (`pcscd`) ou, à défaut, puce NFC
//! intégrée du téléphone par le démon NCI (voir [`crate::nfc_nci`]).
//!
//! Le serveur fournit des options d'assertion WebAuthn; la clé les signe avec
//! un `clientDataJSON` dont l'origine est celle du coffre web. La réponse est
//! renvoyée au serveur, en JSON, comme jeton 2FA du fournisseur WebAuthn.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use futures::StreamExt as _;
use tokio::net::UnixStream;
use webauthn_authenticator_rs::{
    AuthenticatorBackend,
    ctap2::CtapAuthenticator,
    prelude::{RequestChallengeResponse, Url, WebauthnAuthenticator, WebauthnCError},
    transport::{AnyTransport, Token, TokenEvent, Transport as _},
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
};

use crate::nfc_nci::{self, Nci, NciToken};

/// Délai laissé pour brancher ou approcher la clé, puis la toucher.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Après la saisie du NIP, si la clé a quitté le champ, nouvel essai chaque
/// seconde pendant ce délai (avec le même NIP, sans le redemander).
const PIN_RETRY_WINDOW: Duration = Duration::from_secs(5);
const PIN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

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
    /// La clé a été perdue après la saisie du NIP : nouvel essai n° `.0`.
    Retrying(u32),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Aucune clé de sécurité détectée à temps.")]
    Timeout,
    #[error("Opération annulée.")]
    Cancelled,
    #[error("Cette clé n'est pas enregistrée pour ce compte.")]
    UnknownCredential,
    #[error("NIP de la clé incorrect.")]
    WrongPin,
    #[error("NIP de la clé bloqué : retirez puis rebranchez la clé, ou réinitialisez-la.")]
    PinBlocked,
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
            WebauthnCError::Ctap(CtapError::Ctap2PinInvalid | CtapError::Ctap2PinAuthInvalid) => {
                Self::WrongPin
            }
            WebauthnCError::Ctap(CtapError::Ctap2PinBlocked | CtapError::Ctap2PinAuthBlocked) => {
                Self::PinBlocked
            }
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

impl KeyError {
    /// Erreur de transport (clé retirée du champ ou débranchée) : un nouvel
    /// essai a un sens. Un NIP refusé n'est jamais réessayé, pour ne pas
    /// consommer les essais de la clé.
    fn is_transport(&self) -> bool {
        matches!(self, Self::Device(_))
    }
}

/// Pont entre les rappels de la bibliothèque CTAP et l'interface GTK.
#[derive(Debug)]
struct ChannelUi {
    events: async_channel::Sender<KeyEvent>,
    cancelled: Arc<AtomicBool>,
    /// NIP saisi pendant cette opération, et moment de sa validation.
    pin: std::sync::Mutex<Option<(String, std::time::Instant)>>,
}

impl ChannelUi {
    fn pin_validated_at(&self) -> Option<std::time::Instant> {
        self.pin.lock().ok()?.as_ref().map(|(_, at)| *at)
    }

    fn forget_pin(&self) {
        if let Ok(mut pin) = self.pin.lock() {
            *pin = None;
        }
    }
}

impl UiCallback for ChannelUi {
    fn request_pin(&self) -> Option<String> {
        // Nouvel essai après la perte de la clé : même NIP, sans redemander.
        if let Some((pin, _)) = self.pin.lock().ok()?.as_ref() {
            return Some(pin.clone());
        }
        let (tx, rx) = mpsc::channel();
        self.events.send_blocking(KeyEvent::Pin(tx)).ok()?;
        let pin = rx.recv_timeout(Duration::from_secs(120)).ok().flatten()?;
        if let Ok(mut cached) = self.pin.lock() {
            *cached = Some((pin.clone(), std::time::Instant::now()));
        }
        Some(pin)
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
    authenticate_with(origin, options, events, cancelled, nfc_nci::socket_path())
}

/// Comme [`authenticate`], avec le chemin du socket du démon NCI.
fn authenticate_with(
    origin: Url,
    options: RequestChallengeResponse,
    events: async_channel::Sender<KeyEvent>,
    cancelled: Arc<AtomicBool>,
    nci_socket: std::path::PathBuf,
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
        pin: std::sync::Mutex::new(None),
    };
    runtime.block_on(async {
        let mut deadline = tokio::time::Instant::now() + TIMEOUT;
        let mut retries = 0;
        loop {
            let result = attempt(
                &ui,
                &events,
                &nci_socket,
                deadline,
                origin.clone(),
                options.clone(),
            )
            .await;
            let error = match result {
                Ok(token) => return Ok(token),
                Err(error) => error,
            };
            if matches!(error, KeyError::WrongPin | KeyError::PinBlocked) {
                ui.forget_pin();
                return Err(error);
            }
            // Clé perdue peu après la validation du NIP : nouvel essai chaque
            // seconde, jusqu'à 5 s après la validation.
            let Some(validated_at) = ui.pin_validated_at() else {
                return Err(error);
            };
            let window_end = validated_at + PIN_RETRY_WINDOW;
            let next = std::time::Instant::now() + PIN_RETRY_INTERVAL;
            if !error.is_transport() || next > window_end || cancelled.load(Ordering::Relaxed) {
                return Err(error);
            }
            retries += 1;
            eprintln!("clé perdue après le NIP ({error}) : nouvel essai {retries}");
            let _ = events.try_send(KeyEvent::Retrying(retries));
            tokio::time::sleep(PIN_RETRY_INTERVAL).await;
            deadline = tokio::time::Instant::from_std(window_end);
        }
    })
}

/// Une tentative : attend une clé (USB, PC/SC ou puce intégrée) jusqu'à
/// `deadline`, puis signe le défi.
async fn attempt(
    ui: &ChannelUi,
    events: &async_channel::Sender<KeyEvent>,
    nci_socket: &std::path::Path,
    deadline: tokio::time::Instant,
    origin: Url,
    options: RequestChallengeResponse,
) -> Result<String, KeyError> {
    let mut request = Some((origin, options));
    {
        let transport = AnyTransport::new().await?;
        // Repli : sans service PC/SC, la puce NFC intégrée passe par le démon NCI.
        let use_nci = transport.nfc.is_none() && nci_socket.exists();
        let mut tokens = transport.watch().await?;
        let is_cancelled = || ui.cancelled.load(Ordering::Relaxed);

        let nci_search = find_nci_key(nci_socket, deadline, &is_cancelled, ui);
        tokio::pin!(nci_search);
        let mut nci_running = use_nci;

        loop {
            if is_cancelled() {
                return Err(KeyError::Cancelled);
            }
            // Réveil périodique pour tenir compte d'une annulation.
            let wait = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_millis(500));
            if wait.is_zero() {
                return Err(KeyError::Timeout);
            }
            tokio::select! {
                found = &mut nci_search, if nci_running => match found {
                    Ok(authenticator) => {
                        let (origin, options) = request.take().ok_or(KeyError::Cancelled)?;
                        return finish(authenticator, events, origin, options);
                    }
                    Err(nfc_nci::NciError::Cancelled) => return Err(KeyError::Cancelled),
                    Err(nfc_nci::NciError::Timeout) => return Err(KeyError::Timeout),
                    Err(e) => {
                        // Le démon NCI est indisponible : on continue avec l'USB.
                        eprintln!("NFC intégré indisponible : {e}");
                        nci_running = false;
                    }
                },
                event = tokio::time::timeout(wait, tokens.next()) => match event {
                    Err(_) => {}
                    Ok(None) => {
                        if !nci_running {
                            return Err(KeyError::Timeout);
                        }
                    }
                    Ok(Some(TokenEvent::EnumerationComplete)) => {
                        let _ = events.try_send(KeyEvent::Waiting);
                    }
                    Ok(Some(TokenEvent::Removed(_))) => {}
                    Ok(Some(TokenEvent::Added(token))) => {
                        if let Some(authenticator) = CtapAuthenticator::new(token, ui).await {
                            let (origin, options) = request.take().ok_or(KeyError::Cancelled)?;
                            return finish(authenticator, events, origin, options);
                        }
                    }
                },
            }
        }
    }
}

/// Signe le défi avec la clé trouvée (hors de l'exécuteur asynchrone).
fn finish<T: Token>(
    authenticator: CtapAuthenticator<'_, T, ChannelUi>,
    events: &async_channel::Sender<KeyEvent>,
    origin: Url,
    options: RequestChallengeResponse,
) -> Result<String, KeyError> {
    let _ = events.try_send(KeyEvent::Touch);
    tokio::task::block_in_place(|| assert_with(authenticator, origin, options))
}

/// Attend une clé FIDO2 posée sur la puce NFC intégrée (démon NCI). Les cartes
/// sans applet FIDO sont ignorées et la recherche reprend.
async fn find_nci_key<'a>(
    socket: &std::path::Path,
    deadline: tokio::time::Instant,
    cancelled: &dyn Fn() -> bool,
    ui: &'a ChannelUi,
) -> Result<CtapAuthenticator<'a, NciToken<UnixStream>, ChannelUi>, nfc_nci::NciError> {
    loop {
        // Chaque tentative ouvre sa propre connexion : le démon reprend la main
        // sur le contrôleur dès qu'elle se ferme.
        let stream = UnixStream::connect(socket).await?;
        let mut nci = Nci::new(stream);
        nci.activate_iso_dep(deadline, cancelled).await?;
        if let Some(authenticator) = CtapAuthenticator::new(NciToken::new(nci), ui).await {
            return Ok(authenticator);
        }
        // Carte ISO-DEP sans applet FIDO (carte bancaire, etc.) : on réessaie.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
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

    /// Options d'assertion de test.
    fn test_options() -> RequestChallengeResponse {
        parse_options(serde_json::json!({
            "challenge": "AAECAwQFBgcICQoLDA0ODw",
            "timeout": 60000,
            "rpId": "localhost",
            "allowCredentials": [{ "type": "public-key", "id": "AQID" }],
            "userVerification": "discouraged"
        }))
        .unwrap()
    }

    /// Lance le contrôleur NCI simulé sur `socket` (un seul client) et retourne
    /// les APDU reçus par la clé.
    fn spawn_controller(socket: std::path::PathBuf) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
        spawn_controllers(socket, vec![false])
    }

    /// Un contrôleur simulé par connexion successive (`true` : clé à NIP qui
    /// quitte le champ juste après la saisie du NIP).
    fn spawn_controllers(
        socket: std::path::PathBuf,
        sessions: Vec<bool>,
    ) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::from_std(listener).unwrap();
                let stats = Arc::new(std::sync::Mutex::new(
                    crate::nfc_nci::tests::Stats::default(),
                ));
                for pin_then_lost in sessions {
                    let (stream, _) = listener.accept().await.unwrap();
                    crate::nfc_nci::tests::run_controller(stream, stats.clone(), pin_then_lost)
                        .await;
                }
                stats.lock().unwrap().apdus.clone()
            })
        })
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("coffre-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Vérifie qu'`authenticate` a trouvé la clé NFC et lui a envoyé
    /// GetAssertion (refusé faute d'identifiant connu).
    fn assert_reached_nfc_key(result: Result<String, KeyError>, apdus: &[Vec<u8>]) {
        assert!(
            matches!(result, Err(KeyError::UnknownCredential)),
            "résultat : {result:?}"
        );
        assert!(apdus.iter().any(|a| a.get(5) == Some(&0x02)));
    }

    /// Sans pcscd, `authenticate` passe par le socket du démon NCI (ici le
    /// contrôleur simulé, directement).
    #[test]
    fn repli_nfc_integre_par_le_demon_nci() {
        let dir = temp_dir("nci");
        let socket = dir.join("nci.sock");
        let controller = spawn_controller(socket.clone());
        let (events, _rx) = async_channel::unbounded();
        let result = authenticate_with(
            Url::parse("http://localhost:8000").unwrap(),
            test_options(),
            events,
            Arc::new(AtomicBool::new(false)),
            socket,
        );
        assert_reached_nfc_key(result, &controller.join().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Même parcours à travers le vrai relais C (`contrib/nci-bridge`) :
    /// Coffre → socket du pont → pont C → « HAL » (contrôleur simulé).
    /// `make -C contrib/nci-bridge` puis
    /// `COFFRE_NCI_BRIDGE=contrib/nci-bridge/test_nci_bridge cargo test pont_c -- --ignored`
    #[test]
    #[ignore]
    fn repli_nfc_via_pont_c() {
        let Ok(bridge) = std::env::var("COFFRE_NCI_BRIDGE") else {
            eprintln!("COFFRE_NCI_BRIDGE non défini : test ignoré");
            return;
        };
        let dir = temp_dir("pont");
        let controller_socket = dir.join("controleur.sock");
        let bridge_socket = dir.join("nci.sock");
        let controller = spawn_controller(controller_socket.clone());
        let mut relay = std::process::Command::new(bridge)
            .arg("relay")
            .arg(&bridge_socket)
            .arg(&controller_socket)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Attend « relais prêt ».
        let mut ready = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(relay.stdout.take().unwrap()),
            &mut ready,
        )
        .unwrap();
        assert_eq!(ready.trim(), "relais prêt");

        let (events, _rx) = async_channel::unbounded();
        let result = authenticate_with(
            Url::parse("http://localhost:8000").unwrap(),
            test_options(),
            events,
            Arc::new(AtomicBool::new(false)),
            bridge_socket,
        );
        let apdus = controller.join().unwrap();
        assert!(relay.wait().unwrap().success());
        assert_reached_nfc_key(result, &apdus);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// La clé quitte le champ juste après la saisie de son NIP : Coffre
    /// réessaie (sans redemander le NIP) et atteint la clé reposée.
    #[test]
    fn reessai_apres_nip_si_la_cle_quitte_le_champ() {
        let dir = temp_dir("nip");
        let socket = dir.join("nci.sock");
        let controller = spawn_controllers(socket.clone(), vec![true, false]);
        let (events, rx) = async_channel::unbounded();
        let answers = std::thread::spawn(move || {
            let (mut prompts, mut retries) = (0, Vec::new());
            while let Ok(event) = rx.recv_blocking() {
                match event {
                    KeyEvent::Pin(reply) => {
                        prompts += 1;
                        reply.send(Some("1234".into())).unwrap();
                    }
                    KeyEvent::Retrying(n) => retries.push(n),
                    _ => {}
                }
            }
            (prompts, retries)
        });
        let started = std::time::Instant::now();
        let result = authenticate_with(
            Url::parse("http://localhost:8000").unwrap(),
            test_options(),
            events,
            Arc::new(AtomicBool::new(false)),
            socket,
        );
        let apdus = controller.join().unwrap();
        let (prompts, retries) = answers.join().unwrap();
        assert_eq!(prompts, 1, "le NIP ne doit être demandé qu'une fois");
        assert_eq!(retries, vec![1]);
        assert!(started.elapsed() >= PIN_RETRY_INTERVAL);
        assert_reached_nfc_key(result, &apdus);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
