//! Couche d'accès au coffre, bâtie sur le SDK officiel Bitwarden (option GPL-3.0).
//!
//! Le SDK se charge de l'authentification, de la dérivation de clés, du
//! déchiffrement et de la persistance (base SQLite : jetons d'accès et éléments
//! **chiffrés**). Les clés déchiffrées ne vivent que dans le `KeyStore` du SDK
//! et sont effacées au verrouillage.
//!
//! Fichiers, dans `$XDG_DATA_HOME/coffre/` (droits 0700) :
//! - `vault.sqlite` : état du SDK (jetons, éléments chiffrés);
//! - `account.json` : serveur, courriel et clés *protégées* nécessaires au
//!   déverrouillage hors ligne.

mod ops;

pub use ops::*;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::{
    Client, ClientBuilder, ClientSettings, DeviceType, OrganizationId, UserId,
    auth::login::{
        PasswordLoginRequest, TwoFactorEmailRequest, TwoFactorProvider, TwoFactorRequest,
    },
    client::persisted_state::OrganizationSharedKey,
    key_management::{
        LocalUserDataKeyState, MasterPasswordUnlockData, SymmetricKeySlotId,
        account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::{InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
    },
};
use bitwarden_crypto::{EncString, Kdf, UnsignedSharedKey, safe::PasswordProtectedKeyEnvelope};
use bitwarden_generators::{GeneratorClientsExt, PasswordGeneratorRequest};
use bitwarden_state::{
    DatabaseConfiguration, SettingItem,
    registry::StateRegistry,
    repository::{RepositoryItem, RepositoryMigrationStep, RepositoryMigrations},
};
use bitwarden_vault::{
    Cipher, CipherId, CipherRepromptType, CipherType, CipherView, Folder, LoginUriView, LoginView,
    PasswordHistoryView, SecureNoteType, SecureNoteView, VaultClientExt,
};

/// Version des clients officiels dont le SDK utilisé reproduit le comportement ;
/// envoyée dans l'en-tête `Bitwarden-Client-Version`, que les serveurs (dont
/// Vaultwarden) consultent pour activer les fonctions récentes.
const COMPAT_CLIENT_VERSION: &str = "2026.9.0";

/// Identifiant d'appareil qu'envoie la connexion par mot de passe du SDK.
const SDK_LOGIN_DEVICE_ID: &str = "b86dd6ab-4265-4ddf-a7f1-eb28d5677f33";

/// Extrait les options WebAuthn (fournisseur 7) d'une réponse « 2FA requise ».
fn webauthn_options(response: &serde_json::Value) -> Option<serde_json::Value> {
    let providers = response.as_object()?.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case("TwoFactorProviders2")
            .then_some(value)
    })?;
    providers.get("7").filter(|v| v.is_object()).cloned()
}

/// Nombre d'essais de NIP avant d'exiger le mot de passe maître.
pub const PIN_ATTEMPTS: u8 = 5;
/// Nombre d'anciens mots de passe conservés (comme les clients officiels).
const PASSWORD_HISTORY_LEN: usize = 5;

/// Serveur Bitwarden visé.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(tag = "type", content = "url")]
pub enum Server {
    /// bitwarden.com (région États-Unis)
    #[default]
    BitwardenUs,
    /// bitwarden.eu (région Europe)
    BitwardenEu,
    /// Instance auto-hébergée (Bitwarden ou Vaultwarden), p. ex. `https://coffre.exemple.ca`
    SelfHosted(String),
}

impl Server {
    /// Nom affiché : domaine du serveur.
    pub fn label(&self) -> String {
        match self {
            Self::BitwardenUs => "bitwarden.com".into(),
            Self::BitwardenEu => "bitwarden.eu".into(),
            Self::SelfHosted(url) => url
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_owned(),
        }
    }

    /// Retourne `(api_url, identity_url)`.
    fn urls(&self) -> Result<(String, String), Error> {
        match self {
            Self::BitwardenUs => Ok((
                "https://api.bitwarden.com".into(),
                "https://identity.bitwarden.com".into(),
            )),
            Self::BitwardenEu => Ok((
                "https://api.bitwarden.eu".into(),
                "https://identity.bitwarden.eu".into(),
            )),
            Self::SelfHosted(url) => {
                let base = url.trim().trim_end_matches('/');
                if !(base.starts_with("https://") || base.starts_with("http://")) || base.len() < 9
                {
                    return Err(Error::InvalidServerUrl);
                }
                Ok((format!("{base}/api"), format!("{base}/identity")))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Adresse du serveur invalide (elle doit commencer par https://).")]
    InvalidServerUrl,
    #[error("Mot de passe maître incorrect.")]
    WrongPassword,
    #[error("Courriel ou mot de passe maître incorrect.")]
    BadCredentials,
    #[error("Code de vérification invalide.")]
    BadTwoFactorCode,
    #[error("NIP incorrect ({0} essai(s) restant(s)).")]
    WrongPin(u8),
    #[error("Trop d'essais : le NIP est désactivé, utilisez le mot de passe maître.")]
    PinDisabled,
    #[error("Cette méthode de connexion en deux étapes n'est pas encore prise en charge.")]
    UnsupportedTwoFactor,
    #[error("Session expirée : reconnectez-vous pour synchroniser.")]
    SessionExpired,
    #[error("Réponse du serveur incomplète : {0}")]
    MissingData(&'static str),
    #[error("Élément introuvable.")]
    ItemNotFound,
    #[error("Le nom de l'élément est obligatoire.")]
    EmptyName,
    #[error("Vous n'avez pas le droit de modifier cet élément.")]
    ReadOnly,
    #[error("Fichier illisible ou d'un format inattendu.")]
    Malformed,
    #[error("Ce fichier est chiffré : exportez-le sans chiffrement pour l'importer.")]
    EncryptedImport,
    #[error("Échec de la connexion : {0}")]
    Login(String),
    #[error("Échec de l'envoi du courriel : {0}")]
    TwoFactorEmail(#[from] bitwarden_core::auth::login::TwoFactorEmailError),
    #[error("Erreur réseau : {0}")]
    Api(String),
    #[error("Erreur de chiffrement : {0}")]
    Crypto(String),
    #[error("Erreur de stockage : {0}")]
    Storage(String),
    #[error("Erreur de déchiffrement : {0}")]
    Decrypt(#[from] bitwarden_vault::DecryptError),
}

impl From<bitwarden_core::auth::login::LoginError> for Error {
    fn from(e: bitwarden_core::auth::login::LoginError) -> Self {
        let message = e.to_string();
        // Messages renvoyés tels quels par bitwarden.com et Vaultwarden.
        if message.contains("Username or password is incorrect") {
            Self::BadCredentials
        } else if message.contains("Two-step token is invalid")
            || message.contains("Invalid TOTP code")
            || message.contains("TOTP code is not a number")
        {
            Self::BadTwoFactorCode
        } else {
            Self::Login(message)
        }
    }
}

fn storage<E: std::fmt::Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}

/// Méthodes 2FA proposées par le serveur et prises en charge ici.
#[derive(Debug, Clone, Copy)]
pub struct TwoFactorOptions {
    pub authenticator: bool,
    pub email: bool,
    /// YubiKey OTP : la clé « tape » un code de 44 caractères (USB).
    pub yubikey: bool,
    /// Clé de sécurité FIDO2 (USB ou NFC).
    pub webauthn: bool,
}

impl TwoFactorOptions {
    /// Méthodes proposées, de la plus pratique sur téléphone à la moins pratique.
    pub fn methods(&self) -> Vec<TwoFactorMethod> {
        [
            (self.webauthn, TwoFactorMethod::WebAuthn),
            (self.yubikey, TwoFactorMethod::YubiKey),
            (self.authenticator, TwoFactorMethod::Authenticator),
            (self.email, TwoFactorMethod::Email),
        ]
        .into_iter()
        .filter_map(|(available, method)| available.then_some(method))
        .collect()
    }
}

pub enum LoginOutcome {
    Authenticated,
    TwoFactorRequired(TwoFactorOptions),
}

/// Méthode 2FA choisie par l'utilisateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorMethod {
    Authenticator,
    Email,
    YubiKey,
    WebAuthn,
}

impl TwoFactorMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::Authenticator => "Application d'authentification",
            Self::Email => "Code par courriel",
            Self::YubiKey => "YubiKey (code OTP)",
            Self::WebAuthn => "Clé de sécurité (USB ou NFC)",
        }
    }
}

/// Type d'élément que l'on peut créer depuis l'application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Login,
    SecureNote,
}

/// Contenu éditable d'un élément (identifiant ou note sécurisée).
#[derive(Debug, Clone, Default)]
pub struct ItemDraft {
    pub name: String,
    pub username: String,
    pub password: String,
    pub uri: String,
    pub totp: String,
    pub notes: String,
    /// Dossier (`None` : aucun dossier).
    pub folder_id: Option<String>,
    pub favorite: bool,
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

impl ItemDraft {
    pub fn from_view(view: &CipherView) -> Self {
        let login = view.login.as_ref();
        Self {
            name: view.name.clone(),
            username: login.and_then(|l| l.username.clone()).unwrap_or_default(),
            password: login.and_then(|l| l.password.clone()).unwrap_or_default(),
            uri: login
                .and_then(|l| l.uris.as_ref())
                .and_then(|u| u.first())
                .and_then(|u| u.uri.clone())
                .unwrap_or_default(),
            totp: login.and_then(|l| l.totp.clone()).unwrap_or_default(),
            notes: view.notes.clone().unwrap_or_default(),
            folder_id: view.folder_id.map(|id| id.to_string()),
            favorite: view.favorite,
        }
    }

    /// Applique le brouillon à une vue d'identifiant existante (ou vide) en
    /// conservant les champs que l'application ne sait pas modifier.
    fn apply_login(&self, mut login: LoginView) -> LoginView {
        // Le mot de passe (non rogné) est conservé tel que saisi.
        let password = (!self.password.is_empty()).then(|| self.password.clone());
        login.username = non_empty(&self.username);
        login.password = password;
        login.totp = non_empty(&self.totp);
        let mut uris = login.uris.take().unwrap_or_default();
        match non_empty(&self.uri) {
            Some(uri) => match uris.first_mut() {
                Some(first) if first.uri.as_deref() != Some(uri.as_str()) => {
                    first.uri = Some(uri);
                    first.uri_checksum = None;
                }
                Some(_) => {}
                None => uris.push(LoginUriView {
                    uri: Some(uri),
                    r#match: None,
                    uri_checksum: None,
                }),
            },
            None => {
                if !uris.is_empty() {
                    uris.remove(0);
                }
            }
        }
        login.uris = (!uris.is_empty()).then_some(uris);
        login.generate_checksums();
        login
    }
}

fn empty_login() -> LoginView {
    LoginView {
        username: None,
        password: None,
        password_revision_date: None,
        uris: None,
        totp: None,
        autofill_on_page_load: None,
        fido2_credentials: None,
    }
}

/// Données persistées (aucun secret en clair) pour restaurer la session et
/// déverrouiller hors ligne.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Account {
    server: Server,
    email: String,
    user_id: Option<UserId>,
    kdf: Kdf,
    master_password_unlock: MasterPasswordUnlockData,
    account_state: WrappedAccountCryptographicState,
    org_keys: HashMap<OrganizationId, UnsignedSharedKey>,
    #[serde(default)]
    last_sync: Option<chrono::DateTime<chrono::Utc>>,
}

struct PinState {
    envelope: PasswordProtectedKeyEnvelope,
    attempts_left: u8,
}

fn data_dir() -> PathBuf {
    gtk::glib::user_data_dir().join(crate::APP_NAME)
}

fn account_path() -> PathBuf {
    data_dir().join("account.json")
}

fn migrations() -> RepositoryMigrations {
    use RepositoryMigrationStep::Add;
    RepositoryMigrations::new(vec![
        Add(Cipher::data()),
        Add(Folder::data()),
        Add(SettingItem::data()),
        Add(OrganizationSharedKey::data()),
        Add(LocalUserDataKeyState::data()),
        Add(bitwarden_send::Send::data()),
    ])
}

fn ensure_data_dir() -> Result<PathBuf, Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = data_dir();
    std::fs::create_dir_all(&dir).map_err(storage)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(storage)?;
    Ok(dir)
}

/// Limite au propriétaire les fichiers créés par SQLite (base, journal).
fn restrict_permissions(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600));
    }
}

/// Supprime toutes les données locales (déconnexion ou nouveau compte).
pub fn wipe_local_data() {
    let dir = data_dir();
    if dir.exists()
        && let Err(e) = std::fs::remove_dir_all(&dir)
    {
        eprintln!("impossible de supprimer {}: {e}", dir.display());
    }
}

/// Session d'un compte. `Clone` partage le même client SDK (Arc interne).
#[derive(Clone)]
pub struct Session {
    client: Client,
    server: Server,
    email: String,
    account: Option<Arc<Account>>,
    pin: Arc<Mutex<Option<PinState>>>,
}

impl Session {
    async fn open(server: &Server, device_id: &str, email: &str) -> Result<Self, Error> {
        let (api_url, identity_url) = server.urls()?;
        let dir = ensure_data_dir()?;
        let registry = StateRegistry::new_with_db(
            DatabaseConfiguration::Sqlite {
                db_name: "vault".into(),
                folder_path: dir,
            },
            migrations(),
        )
        .await
        .map_err(storage)?;
        restrict_permissions(&data_dir());
        let settings = ClientSettings {
            identity_url,
            api_url,
            user_agent: format!("{}/{}", crate::APP_NAME, env!("CARGO_PKG_VERSION")),
            device_type: DeviceType::LinuxDesktop,
            device_identifier: Some(device_id.to_owned()),
            bitwarden_client_version: Some(COMPAT_CLIENT_VERSION.into()),
            bitwarden_package_type: None,
        };
        let client = ClientBuilder::new()
            .with_settings(settings)
            .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
            .with_state(registry)
            .build();
        Ok(Self {
            client,
            server: server.clone(),
            email: email.trim().to_owned(),
            account: None,
            pin: Arc::default(),
        })
    }

    /// Nouvelle session vierge : efface d'abord toute donnée locale précédente.
    pub async fn create(server: &Server, device_id: &str, email: &str) -> Result<Self, Error> {
        server.urls()?;
        wipe_local_data();
        Self::open(server, device_id, email).await
    }

    /// Restaure la session enregistrée lors d'un lancement précédent (verrouillée).
    pub async fn restore(device_id: &str) -> Option<Result<Self, Error>> {
        let data = std::fs::read(account_path()).ok()?;
        let account: Account = match serde_json::from_slice(&data) {
            Ok(account) => account,
            Err(e) => return Some(Err(storage(e))),
        };
        Some(
            Self::open(&account.server, device_id, &account.email)
                .await
                .map(|mut session| {
                    session.account = Some(Arc::new(account));
                    session
                }),
        )
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    /// Connexion par mot de passe maître, avec code 2FA facultatif.
    pub async fn login(
        &self,
        password: String,
        two_factor: Option<(TwoFactorMethod, String)>,
    ) -> Result<LoginOutcome, Error> {
        let two_factor = two_factor.map(|(method, token)| TwoFactorRequest {
            // Les codes saisis peuvent contenir des espaces; la réponse WebAuthn
            // (JSON) est transmise telle quelle.
            token: match method {
                TwoFactorMethod::WebAuthn => token,
                _ => token.trim().replace(' ', ""),
            },
            provider: match method {
                TwoFactorMethod::Authenticator => TwoFactorProvider::Authenticator,
                TwoFactorMethod::Email => TwoFactorProvider::Email,
                TwoFactorMethod::YubiKey => TwoFactorProvider::Yubikey,
                TwoFactorMethod::WebAuthn => TwoFactorProvider::WebAuthn,
            },
            remember: false,
        });
        let response = self
            .client
            .auth()
            .login_password(&PasswordLoginRequest {
                email: self.email.clone(),
                password,
                two_factor,
            })
            .await?;
        match response.two_factor {
            Some(providers) => {
                let options = TwoFactorOptions {
                    authenticator: providers.authenticator.is_some(),
                    email: providers.email.is_some(),
                    yubikey: providers.yubi_key.is_some(),
                    webauthn: providers.web_authn.is_some(),
                };
                if !options.methods().is_empty() {
                    Ok(LoginOutcome::TwoFactorRequired(options))
                } else {
                    Err(Error::UnsupportedTwoFactor)
                }
            }
            None => Ok(LoginOutcome::Authenticated),
        }
    }

    /// Origine du coffre web, inscrite dans le `clientDataJSON` WebAuthn : le
    /// serveur n'accepte que les signatures produites pour cette origine.
    pub fn web_origin(&self) -> Result<url::Url, Error> {
        let origin = match &self.server {
            Server::BitwardenUs => "https://vault.bitwarden.com".to_owned(),
            Server::BitwardenEu => "https://vault.bitwarden.eu".to_owned(),
            Server::SelfHosted(url) => url::Url::parse(url.trim())
                .map_err(|_| Error::InvalidServerUrl)?
                .origin()
                .ascii_serialization(),
        };
        url::Url::parse(&origin).map_err(|_| Error::InvalidServerUrl)
    }

    /// Obtient un défi WebAuthn neuf pour la connexion en deux étapes.
    ///
    /// Le SDK ne transmet pas les options WebAuthn reçues du serveur : on refait
    /// donc la même demande de jeton que lui, sans code 2FA, et on lit
    /// `TwoFactorProviders2["7"]` dans la réponse. Le serveur remplace à chaque
    /// fois le défi précédent; c'est celui-ci que vérifiera la connexion suivante.
    pub async fn webauthn_challenge(&self, password: &str) -> Result<serde_json::Value, Error> {
        use bitwarden_core::key_management::MasterPasswordAuthenticationData;

        let kdf = self
            .client
            .auth()
            .prelogin(self.email.clone())
            .await
            .map_err(|e| Error::Api(e.to_string()))?;
        let hash = MasterPasswordAuthenticationData::derive(password, &kdf, &self.email)
            .map_err(|e| Error::Crypto(e.to_string()))?
            .master_password_authentication_hash
            .to_string();
        // Mêmes champs que la requête de connexion du SDK.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("scope", "api offline_access")
            .append_pair("client_id", "web")
            .append_pair("deviceType", &(DeviceType::ChromeBrowser as u8).to_string())
            .append_pair("deviceIdentifier", SDK_LOGIN_DEVICE_ID)
            .append_pair("deviceName", "firefox")
            .append_pair("grant_type", "password")
            .append_pair("username", &self.email)
            .append_pair("password", &hash)
            .finish();
        let config = self.client.internal.get_api_configurations();
        let identity = &config.identity_config;
        let text = identity
            .client
            .post(format!("{}/connect/token", identity.base_path))
            .header(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Api(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::Api(e.to_string()))?;
        let response: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| Error::Api(e.to_string()))?;
        webauthn_options(&response).ok_or(Error::MissingData("défi WebAuthn"))
    }

    /// Demande au serveur d'envoyer le code 2FA par courriel.
    pub async fn send_two_factor_email(&self, password: String) -> Result<(), Error> {
        self.client
            .auth()
            .send_two_factor_email(&TwoFactorEmailRequest {
                password,
                email: self.email.clone(),
            })
            .await?;
        Ok(())
    }

    /// Télécharge le coffre, l'enregistre (chiffré) et met à jour les données de déverrouillage.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let config = self.client.internal.get_api_configurations();
        let sync = config.api_client.sync_api().get(None).await.map_err(|e| {
            let message = e.to_string();
            if message.contains("401") || message.to_lowercase().contains("not authenticated") {
                Error::SessionExpired
            } else {
                Error::Api(message)
            }
        })?;

        let profile = sync.profile.ok_or(Error::MissingData("profil"))?;

        let kdf = match self.account.as_ref() {
            Some(account) => account.kdf.clone(),
            None => match self.client.internal.get_kdf().await {
                Ok(kdf) => kdf,
                Err(_) => self
                    .client
                    .auth()
                    .prelogin(self.email.clone())
                    .await
                    .map_err(|e| Error::Api(e.to_string()))?,
            },
        };

        // Serveurs récents : `userDecryption.masterPasswordUnlock`.
        // Serveurs plus anciens (certaines versions de Vaultwarden) : clé du profil + KDF.
        let master_password_unlock = match sync
            .user_decryption
            .as_deref()
            .and_then(|d| d.master_password_unlock.as_deref())
            .map(MasterPasswordUnlockData::try_from)
        {
            Some(Ok(data)) => data,
            _ => MasterPasswordUnlockData {
                kdf: kdf.clone(),
                master_key_wrapped_user_key: profile
                    .key
                    .as_deref()
                    .ok_or(Error::MissingData("clé utilisateur"))?
                    .parse::<EncString>()
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                salt: self.email.to_lowercase(),
                contained_key_id: None,
            },
        };

        let account_state = match profile
            .account_keys
            .as_deref()
            .map(WrappedAccountCryptographicState::try_from)
        {
            Some(Ok(state)) => state,
            _ => WrappedAccountCryptographicState::V1 {
                private_key: profile
                    .private_key
                    .as_deref()
                    .ok_or(Error::MissingData("clé privée"))?
                    .parse()
                    .map_err(|e: bitwarden_crypto::CryptoError| Error::Crypto(e.to_string()))?,
            },
        };

        let org_keys: HashMap<_, _> = profile
            .organizations
            .unwrap_or_default()
            .into_iter()
            .filter_map(|org| {
                let id = OrganizationId::new(org.id?);
                let key = org.key?.parse().ok()?;
                Some((id, key))
            })
            .collect();

        let user_id = profile.id.map(UserId::new);
        if let Some(user_id) = user_id
            && self.client.internal.get_user_id().is_none()
        {
            let _ = self.client.internal.init_user_id(user_id).await;
        }

        let ciphers: Vec<_> = sync
            .ciphers
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| Cipher::try_from(c).ok())
            .filter_map(|c| Some((c.id?, c)))
            .collect();
        self.client
            .platform()
            .state()
            .get::<Cipher>()
            .map_err(storage)?
            .replace_all(ciphers)
            .await
            .map_err(storage)?;

        let org_keys_changed = self
            .account
            .as_ref()
            .is_none_or(|a| a.org_keys.len() != org_keys.len());

        // Dossiers et Send, chiffrés, pour les listes et le mode hors ligne.
        let folders: Vec<_> = sync
            .folders
            .unwrap_or_default()
            .into_iter()
            .filter_map(|f| Folder::try_from(f).ok())
            .filter_map(|f| Some((f.id?, f)))
            .collect();
        self.client
            .platform()
            .state()
            .get::<Folder>()
            .map_err(storage)?
            .replace_all(folders)
            .await
            .map_err(storage)?;
        let sends: Vec<_> = sync
            .sends
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| bitwarden_send::Send::try_from(s).ok())
            .filter_map(|s| Some((s.id?, s)))
            .collect();
        self.client
            .platform()
            .state()
            .get::<bitwarden_send::Send>()
            .map_err(storage)?
            .replace_all(sends)
            .await
            .map_err(storage)?;

        let account = Account {
            server: self.server.clone(),
            email: self.email.clone(),
            user_id,
            kdf,
            master_password_unlock,
            account_state,
            org_keys,
            last_sync: Some(chrono::Utc::now()),
        };
        save_account(&account)?;
        self.account = Some(Arc::new(account));

        if org_keys_changed && self.is_unlocked() {
            self.init_org_crypto().await?;
        }
        Ok(())
    }

    pub fn is_unlocked(&self) -> bool {
        self.client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeySlotId::User)
    }

    fn account(&self) -> Result<&Account, Error> {
        self.account
            .as_deref()
            .ok_or(Error::MissingData("synchronisation"))
    }

    async fn init_user_crypto(&self, method: InitUserCryptoMethod) -> Result<(), Error> {
        let account = self.account()?;
        if let Some(user_id) = account.user_id
            && self.client.internal.get_user_id().is_none()
        {
            let _ = self.client.internal.init_user_id(user_id).await;
        }
        self.client
            .crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: None,
                kdf_params: account.kdf.clone(),
                email: self.email.clone(),
                account_cryptographic_state: account.account_state.clone(),
                method,
                upgrade_token: None,
            })
            .await
            .map_err(|e| Error::Crypto(e.to_string()))?;
        self.init_org_crypto().await
    }

    async fn init_org_crypto(&self) -> Result<(), Error> {
        let account = self.account()?;
        if !account.org_keys.is_empty() {
            self.client
                .crypto()
                .initialize_org_crypto(InitOrgCryptoRequest {
                    organization_keys: account.org_keys.clone(),
                })
                .await
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        Ok(())
    }

    /// Déverrouille localement (sans réseau) avec le mot de passe maître.
    pub async fn unlock(&self, password: String) -> Result<(), Error> {
        if self.is_unlocked() {
            return self.init_org_crypto().await;
        }
        let master_password_unlock = self.account()?.master_password_unlock.clone();
        self.init_user_crypto(InitUserCryptoMethod::MasterPasswordUnlock {
            password,
            master_password_unlock,
        })
        .await
        .map_err(|e| match e {
            Error::Crypto(_) => Error::WrongPassword,
            e => e,
        })?;
        // Un déverrouillage par mot de passe réarme le compteur d'essais du NIP.
        if let Some(pin) = self.pin.lock().expect("verrou NIP").as_mut() {
            pin.attempts_left = PIN_ATTEMPTS;
        }
        Ok(())
    }

    /// Le NIP n'est conservé qu'en mémoire : il est perdu à la fermeture de
    /// l'application, comme l'option par défaut des clients officiels.
    pub fn has_pin(&self) -> bool {
        self.pin.lock().expect("verrou NIP").is_some()
    }

    pub fn set_pin(&self, pin: String) -> Result<(), Error> {
        let response = self
            .client
            .crypto()
            .enroll_pin(pin)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        *self.pin.lock().expect("verrou NIP") = Some(PinState {
            envelope: response.pin_protected_user_key_envelope,
            attempts_left: PIN_ATTEMPTS,
        });
        Ok(())
    }

    pub fn clear_pin(&self) {
        *self.pin.lock().expect("verrou NIP") = None;
    }

    pub async fn unlock_with_pin(&self, pin: String) -> Result<(), Error> {
        let envelope = self
            .pin
            .lock()
            .expect("verrou NIP")
            .as_ref()
            .map(|p| p.envelope.clone())
            .ok_or(Error::PinDisabled)?;
        let result = self
            .init_user_crypto(InitUserCryptoMethod::PinEnvelope {
                pin,
                pin_protected_user_key_envelope: envelope,
            })
            .await;
        let mut guard = self.pin.lock().expect("verrou NIP");
        match result {
            Ok(()) => {
                if let Some(state) = guard.as_mut() {
                    state.attempts_left = PIN_ATTEMPTS;
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("échec du déverrouillage par NIP : {e}");
                let left = guard
                    .as_ref()
                    .map_or(0, |s| s.attempts_left.saturating_sub(1));
                if left == 0 {
                    *guard = None;
                    Err(Error::PinDisabled)
                } else {
                    if let Some(state) = guard.as_mut() {
                        state.attempts_left = left;
                    }
                    Err(Error::WrongPin(left))
                }
            }
        }
    }

    /// Efface toutes les clés déchiffrées de la mémoire.
    pub fn lock(&self) {
        self.client.internal.get_key_store().clear();
    }

    /// Déconnexion : verrouille, oublie le NIP et supprime les données locales.
    pub fn logout(&self) {
        self.lock();
        self.clear_pin();
        wipe_local_data();
    }

    async fn stored_ciphers(&self) -> Result<Vec<Cipher>, Error> {
        self.client
            .platform()
            .state()
            .get::<Cipher>()
            .map_err(storage)?
            .list()
            .await
            .map_err(storage)
    }

    /// Liste déchiffrée du coffre (hors corbeille et archive), triée par nom.
    #[cfg(test)]
    pub async fn list(&self) -> Result<Vec<bitwarden_vault::CipherListView>, Error> {
        self.list_scope(Scope::Vault).await
    }

    fn parse_id(id: &str) -> Result<CipherId, Error> {
        id.parse().map_err(|_| Error::ItemNotFound)
    }

    /// Déchiffre un élément complet (mot de passe, notes, etc.).
    pub async fn get(&self, id: &str) -> Result<CipherView, Error> {
        let cipher = self
            .client
            .platform()
            .state()
            .get::<Cipher>()
            .map_err(storage)?
            .get(Self::parse_id(id)?)
            .await
            .map_err(storage)?
            .ok_or(Error::ItemNotFound)?;
        Ok(self.client.vault().ciphers().decrypt(cipher).await?)
    }

    /// Chiffre `view` avec le SDK et l'envoie au serveur (création si `id` est `None`),
    /// puis resynchronise le coffre local.
    async fn save_view(&mut self, id: Option<CipherId>, view: CipherView) -> Result<(), Error> {
        use bitwarden_api_api::models::CipherRequestModel;
        let context = self
            .client
            .vault()
            .ciphers()
            .encrypt(view)
            .await
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let request = CipherRequestModel::from(context);
        let api = self.client.internal.get_api_configurations();
        let ciphers = api.api_client.ciphers_api();
        match id {
            Some(id) => ciphers.put(id.into(), Some(request)).await.map(drop),
            None => ciphers.post(Some(request)).await.map(drop),
        }
        .map_err(|e| Error::Api(e.to_string()))?;
        self.sync().await
    }

    /// Crée un élément sur le serveur.
    pub async fn create_item(&mut self, kind: ItemKind, draft: ItemDraft) -> Result<(), Error> {
        let name = non_empty(&draft.name).ok_or(Error::EmptyName)?;
        let now = chrono::Utc::now();
        let (r#type, login, secure_note) = match kind {
            ItemKind::Login => (
                CipherType::Login,
                Some(draft.apply_login(empty_login())),
                None,
            ),
            ItemKind::SecureNote => (
                CipherType::SecureNote,
                None,
                Some(SecureNoteView {
                    r#type: SecureNoteType::Generic,
                }),
            ),
        };
        let view = CipherView {
            partial: false,
            id: None,
            organization_id: None,
            folder_id: draft
                .folder_id
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|_| Error::ItemNotFound)?,
            collection_ids: vec![],
            key: None,
            name,
            notes: non_empty(&draft.notes),
            r#type,
            login,
            identity: None,
            card: None,
            secure_note,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: draft.favorite,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: now,
            deleted_date: None,
            revision_date: now,
            archived_date: None,
        };
        self.save_view(None, view).await
    }

    /// Modifie un élément existant; l'ancien mot de passe rejoint l'historique.
    pub async fn edit_item(&mut self, id: &str, draft: ItemDraft) -> Result<(), Error> {
        let name = non_empty(&draft.name).ok_or(Error::EmptyName)?;
        let cipher_id = Self::parse_id(id)?;
        let mut view = self.get(id).await?;
        if !view.edit {
            return Err(Error::ReadOnly);
        }
        view.name = name;
        view.notes = non_empty(&draft.notes);
        view.favorite = draft.favorite;
        view.folder_id = draft
            .folder_id
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| Error::ItemNotFound)?;
        if let Some(login) = view.login.take() {
            let old_password = login.password.clone();
            let login = draft.apply_login(login);
            if let Some(old) = old_password.filter(|old| Some(old) != login.password.as_ref()) {
                let now = chrono::Utc::now();
                let mut history = vec![PasswordHistoryView {
                    password: old,
                    last_used_date: now,
                }];
                history.extend(view.password_history.take().unwrap_or_default());
                history.truncate(PASSWORD_HISTORY_LEN);
                view.password_history = Some(history);
                view.login = Some(LoginView {
                    password_revision_date: Some(now),
                    ..login
                });
            } else {
                view.login = Some(login);
            }
        }
        self.save_view(Some(cipher_id), view).await
    }

    /// Envoie l'élément à la corbeille (récupérable depuis le coffre web).
    pub async fn trash(&self, id: &str) -> Result<(), Error> {
        self.client
            .vault()
            .ciphers()
            .soft_delete(Self::parse_id(id)?)
            .await
            .map_err(|e| Error::Api(e.to_string()))
    }

    /// Mot de passe aléatoire de 20 caractères (générateur du SDK).
    pub fn generate_password(&self) -> Result<String, Error> {
        self.client
            .generator()
            .password(PasswordGeneratorRequest {
                lowercase: true,
                uppercase: true,
                numbers: true,
                special: true,
                length: 20,
                avoid_ambiguous: true,
                min_lowercase: Some(1),
                min_uppercase: Some(1),
                min_number: Some(1),
                min_special: Some(1),
                custom_required_chars: None,
                custom_allowed_chars: None,
                max_consecutive: None,
            })
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

fn save_account(account: &Account) -> Result<(), Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    ensure_data_dir()?;
    let path = account_path();
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(account).map_err(storage)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(storage)?;
    file.write_all(&data).map_err(storage)?;
    file.sync_all().map_err(storage)?;
    std::fs::rename(&tmp, &path).map_err(storage)
}

/// Code TOTP courant et secondes restantes, à partir de la clé stockée dans l'élément.
pub fn totp(key: &str) -> Option<(String, u32)> {
    let response = bitwarden_vault::generate_totp(key.to_owned(), None).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let period = u64::from(response.period.max(1));
    let remaining = (period - now % period) as u32;
    Some((response.code, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_auto_hebergees() {
        let server = Server::SelfHosted("https://coffre.exemple.ca/ ".into());
        let (api, identity) = server.urls().unwrap();
        assert_eq!(api, "https://coffre.exemple.ca/api");
        assert_eq!(identity, "https://coffre.exemple.ca/identity");
    }

    #[test]
    fn url_invalide_refusee() {
        assert!(
            Server::SelfHosted("coffre.exemple.ca".into())
                .urls()
                .is_err()
        );
        assert!(Server::SelfHosted(String::new()).urls().is_err());
    }

    #[test]
    fn serveur_serialise_en_json() {
        let json = serde_json::to_string(&Server::SelfHosted("https://a.b".into())).unwrap();
        assert_eq!(json, r#"{"type":"SelfHosted","url":"https://a.b"}"#);
        assert_eq!(
            serde_json::from_str::<Server>(&json).unwrap(),
            Server::SelfHosted("https://a.b".into())
        );
    }

    #[test]
    fn totp_rfc6238() {
        let (code, remaining) = totp("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&remaining));
    }

    #[test]
    fn brouillon_applique_a_un_identifiant() {
        let draft = ItemDraft {
            name: "Exemple".into(),
            username: " moi@exemple.ca ".into(),
            password: " secret ".into(),
            uri: "https://exemple.ca".into(),
            totp: String::new(),
            notes: String::new(),
            ..Default::default()
        };
        let login = draft.apply_login(empty_login());
        assert_eq!(login.username.as_deref(), Some("moi@exemple.ca"));
        // Les espaces d'un mot de passe sont significatifs.
        assert_eq!(login.password.as_deref(), Some(" secret "));
        assert_eq!(login.totp, None);
        let uris = login.uris.unwrap();
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0].uri.as_deref(), Some("https://exemple.ca"));
    }

    #[test]
    fn brouillon_vide_retire_le_site() {
        let mut login = empty_login();
        login.uris = Some(vec![LoginUriView {
            uri: Some("https://ancien.ca".into()),
            r#match: None,
            uri_checksum: None,
        }]);
        let login = ItemDraft::default().apply_login(login);
        assert!(login.uris.is_none());
        assert!(login.password.is_none());
    }

    /// Vérifie le chemin réseau réel : `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn connexion_refusee_sur_bitwarden_com() {
        crate::runtime().block_on(async {
            let session = Session::create(
                &Server::BitwardenUs,
                "00000000-0000-4000-8000-000000000000",
                "coffre-test-inexistant@example.com",
            )
            .await
            .unwrap();
            let result = session.login("mauvais mot de passe".into(), None).await;
            let err = result.err().expect("la connexion aurait dû échouer");
            eprintln!("erreur obtenue : {err}");
            assert!(matches!(err, Error::BadCredentials));
        });
    }

    /// Parcours complet contre un serveur Vaultwarden local :
    /// `COFFRE_E2E_SERVER=http://127.0.0.1:8000 cargo test e2e -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn e2e_vaultwarden() {
        let Ok(server_url) = std::env::var("COFFRE_E2E_SERVER") else {
            eprintln!("COFFRE_E2E_SERVER non défini : test ignoré");
            return;
        };
        let server = Server::SelfHosted(server_url.clone());
        let email = format!("e2e-{}@exemple.ca", uuid::Uuid::new_v4().simple());
        let password = "Mot de passe maître très long 123!".to_owned();
        let device = "11111111-2222-4333-8444-555555555555";

        crate::runtime().block_on(async {
            // 1. Inscription (clés générées côté client par le SDK).
            register_account(&server_url, &email, &password).await;

            // 2. Mauvais mot de passe, puis connexion, synchro et déverrouillage.
            let mut session = Session::create(&server, device, &email).await.unwrap();
            assert!(matches!(
                session.login("mauvais".into(), None).await,
                Err(Error::BadCredentials)
            ));
            assert!(matches!(
                session.login(password.clone(), None).await.unwrap(),
                LoginOutcome::Authenticated
            ));
            session.sync().await.unwrap();
            session.unlock(password.clone()).await.unwrap();
            assert!(session.is_unlocked());
            assert!(session.list().await.unwrap().is_empty());

            // 3. Création d'un identifiant et d'une note.
            let draft = ItemDraft {
                name: "Exemple".into(),
                username: "moi@exemple.ca".into(),
                password: "ancien-secret".into(),
                uri: "https://exemple.ca".into(),
                totp: "JBSWY3DPEHPK3PXP".into(),
                notes: "note privée".into(),
                ..Default::default()
            };
            session
                .create_item(ItemKind::Login, draft.clone())
                .await
                .unwrap();
            session
                .create_item(
                    ItemKind::SecureNote,
                    ItemDraft {
                        name: "Note".into(),
                        notes: "contenu".into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let items = session.list().await.unwrap();
            assert_eq!(items.len(), 2);
            let id = items
                .iter()
                .find(|i| i.name == "Exemple")
                .unwrap()
                .id
                .unwrap()
                .to_string();
            let view = session.get(&id).await.unwrap();
            let login = view.login.as_ref().unwrap();
            assert_eq!(login.password.as_deref(), Some("ancien-secret"));
            assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
            assert_eq!(view.notes.as_deref(), Some("note privée"));

            // 4. Modification : l'ancien mot de passe passe dans l'historique.
            let generated = session.generate_password().unwrap();
            assert_eq!(generated.chars().count(), 20);
            let edited = ItemDraft {
                password: generated.clone(),
                name: "Exemple modifié".into(),
                ..draft
            };
            session.edit_item(&id, edited).await.unwrap();
            let view = session.get(&id).await.unwrap();
            assert_eq!(view.name, "Exemple modifié");
            assert_eq!(
                view.login.as_ref().unwrap().password.as_deref(),
                Some(generated.as_str())
            );
            let history = view.password_history.unwrap();
            assert_eq!(history[0].password, "ancien-secret");

            // 5. NIP : mauvais NIP, puis bon NIP après verrouillage.
            session.set_pin("2468".into()).unwrap();
            session.lock();
            assert!(!session.is_unlocked());
            assert!(matches!(
                session.unlock_with_pin("1111".into()).await,
                Err(Error::WrongPin(4))
            ));
            session.unlock_with_pin("2468".into()).await.unwrap();
            assert!(session.is_unlocked());

            // 6. Corbeille.
            session.trash(&id).await.unwrap();
            assert_eq!(session.list().await.unwrap().len(), 1);

            // 7. Restauration de session (nouveau lancement) : verrouillée, sans NIP,
            //    déverrouillage hors ligne puis synchro avec le jeton persisté.
            session.lock();
            drop(session);
            let mut restored = Session::restore(device).await.unwrap().unwrap();
            assert_eq!(restored.email(), email);
            assert!(!restored.is_unlocked());
            assert!(!restored.has_pin());
            assert!(matches!(
                restored.unlock("mauvais".into()).await,
                Err(Error::WrongPassword)
            ));
            restored.unlock(password.clone()).await.unwrap();
            assert_eq!(restored.list().await.unwrap().len(), 1);
            restored.sync().await.unwrap();
            assert_eq!(restored.list().await.unwrap()[0].name, "Note");

            // 8. Déconnexion : plus rien à restaurer.
            if std::env::var_os("COFFRE_E2E_KEEP").is_some() {
                // Garde le compte pour une vérification manuelle de l'interface.
                restored
                    .create_item(
                        ItemKind::Login,
                        ItemDraft {
                            name: "Banque Nationale".into(),
                            username: "client@exemple.ca".into(),
                            password: "S3cret!".into(),
                            uri: "https://www.bnc.ca".into(),
                            totp: "JBSWY3DPEHPK3PXP".into(),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                eprintln!("compte conservé : {email}");
                return;
            }
            restored.logout();
            assert!(Session::restore(device).await.is_none());
            eprintln!("parcours complet réussi pour {email}");
        });
    }

    /// Opérations du coffre contre un Vaultwarden local : dossiers, favoris,
    /// archive, corbeille, export, import, Send, appareils, générateurs.
    /// `COFFRE_E2E_SERVER=http://localhost:8000 cargo test e2e_operations -- --ignored`
    /// (`COFFRE_E2E_KEEP=1` garde le compte, rempli de données de démonstration).
    #[test]
    #[ignore]
    fn e2e_operations_vaultwarden() {
        use super::ops::{ExportKind, ImportKind, PasswordOptions, Scope, SendDraft};

        let Ok(server_url) = std::env::var("COFFRE_E2E_SERVER") else {
            eprintln!("COFFRE_E2E_SERVER non défini : test ignoré");
            return;
        };
        let server = Server::SelfHosted(server_url.clone());
        let email = format!("ops-{}@exemple.ca", uuid::Uuid::new_v4().simple());
        let password = "Mot de passe maître très long 123!".to_owned();
        let device = "11111111-2222-4333-8444-666666666666";

        crate::runtime().block_on(async {
            register_account(&server_url, &email, &password).await;
            let mut session = Session::create(&server, device, &email).await.unwrap();
            session.login(password.clone(), None).await.unwrap();
            session.sync().await.unwrap();
            session.unlock(password.clone()).await.unwrap();
            assert!(session.last_sync().is_some());

            // Dossiers.
            session.create_folder("Travail").await.unwrap();
            session.create_folder("Perso").await.unwrap();
            let folders = session.folders().await.unwrap();
            assert_eq!(
                folders.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                ["Perso", "Travail"]
            );
            let work = folders[1].id.clone();
            session
                .rename_folder(&folders[0].id, "Personnel")
                .await
                .unwrap();
            assert_eq!(session.folders().await.unwrap()[0].name, "Personnel");

            // Élément dans un dossier, en favori dès la création.
            session
                .create_item(
                    ItemKind::Login,
                    ItemDraft {
                        name: "GitHub".into(),
                        username: "octo".into(),
                        password: "gh-secret".into(),
                        uri: "https://github.com".into(),
                        folder_id: Some(work.clone()),
                        favorite: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            session
                .create_item(
                    ItemKind::SecureNote,
                    ItemDraft {
                        name: "Codes Wi-Fi".into(),
                        notes: "maison : 1234".into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let items = session.list_scope(Scope::Vault).await.unwrap();
            let github = items.iter().find(|i| i.name == "GitHub").unwrap();
            assert!(github.favorite);
            assert_eq!(github.folder_id.map(|f| f.to_string()), Some(work.clone()));
            let github_id = github.id.unwrap().to_string();
            let note_id = items
                .iter()
                .find(|i| i.name == "Codes Wi-Fi")
                .unwrap()
                .id
                .unwrap()
                .to_string();

            // Favori retiré puis remis.
            session.set_favorite(&github_id, false).await.unwrap();
            assert!(!session.get(&github_id).await.unwrap().favorite);
            session.set_favorite(&github_id, true).await.unwrap();

            // Archive : retiré du coffre, puis désarchivé.
            session.set_archived(&note_id, true).await.unwrap();
            assert_eq!(session.list_scope(Scope::Vault).await.unwrap().len(), 1);
            assert_eq!(session.list_scope(Scope::Archive).await.unwrap().len(), 1);
            session.set_archived(&note_id, false).await.unwrap();
            assert!(session.list_scope(Scope::Archive).await.unwrap().is_empty());

            // Corbeille : restauration, puis suppression définitive.
            session.trash(&note_id).await.unwrap();
            session.sync().await.unwrap();
            assert_eq!(session.list_scope(Scope::Trash).await.unwrap().len(), 1);
            session.restore_item(&note_id).await.unwrap();
            session.sync().await.unwrap();
            assert!(session.list_scope(Scope::Trash).await.unwrap().is_empty());
            session.trash(&note_id).await.unwrap();
            session.delete_permanently(&note_id).await.unwrap();
            session.sync().await.unwrap();
            assert!(session.list_scope(Scope::Trash).await.unwrap().is_empty());
            assert_eq!(session.list_scope(Scope::Vault).await.unwrap().len(), 1);

            // Suppression d'un dossier : l'élément reste, sans dossier.
            session.delete_folder(&work).await.unwrap();
            assert_eq!(session.folders().await.unwrap().len(), 1);
            let github = session.get(&github_id).await.unwrap();
            assert!(github.folder_id.is_none());

            // Export : mot de passe maître vérifié, JSON lisible et réimportable.
            assert!(session.verify_master_password("mauvais").await.is_err());
            session.verify_master_password(&password).await.unwrap();
            let json = session.export(ExportKind::Json, None).await.unwrap();
            assert!(json.contains("gh-secret"));
            let csv = session.export(ExportKind::Csv, None).await.unwrap();
            assert!(csv.contains("GitHub"));
            let protected = session
                .export(ExportKind::EncryptedJson, Some("fichier".into()))
                .await
                .unwrap();
            assert!(!protected.contains("gh-secret"));
            assert!(matches!(
                session
                    .import(
                        ImportKind::BitwardenJson,
                        protected.into_bytes(),
                        None,
                        None
                    )
                    .await,
                Err(Error::EncryptedImport)
            ));
            let count = session
                .import(ImportKind::BitwardenJson, json.into_bytes(), None, None)
                .await
                .unwrap();
            assert_eq!(count.items, 1);
            assert_eq!(session.list_scope(Scope::Vault).await.unwrap().len(), 2);

            // Send texte : lien, liste, suppression.
            let url = session
                .create_send(SendDraft {
                    name: "Adresse".into(),
                    text: "123, rue Principale".into(),
                    days: 7,
                    max_access_count: Some(3),
                    password: None,
                    hide_text: false,
                })
                .await
                .unwrap()
                .unwrap();
            assert!(url.contains("/#/send/"));
            session.sync().await.unwrap();
            let sends = session.sends().await.unwrap();
            assert_eq!(sends.len(), 1);
            assert_eq!(sends[0].max_access_count, Some(3));
            session.delete_send(&sends[0].id).await.unwrap();
            session.sync().await.unwrap();
            assert!(session.sends().await.unwrap().is_empty());

            // Compte : appareils, phrase d'empreinte, générateurs.
            assert!(!session.devices().await.unwrap().is_empty());
            assert_eq!(session.fingerprint_phrase().unwrap().split('-').count(), 5);
            let generated = session
                .generate_with(&PasswordOptions {
                    length: 32,
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(generated.chars().count(), 32);

            if std::env::var_os("COFFRE_E2E_KEEP").is_some() {
                seed_demo(&mut session).await;
                eprintln!("compte conservé : {email}");
                return;
            }
            session.logout();
            eprintln!("opérations réussies pour {email}");
        });
    }

    /// Données de démonstration (captures d'écran).
    async fn seed_demo(session: &mut Session) {
        use super::ops::SendDraft;
        session.create_folder("Banque").await.unwrap();
        session.create_folder("Travail").await.unwrap();
        let folders = session.folders().await.unwrap();
        let folder = |name: &str| {
            folders
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.id.clone())
        };
        let logins = [
            (
                "Banque Nationale",
                "client@exemple.ca",
                "https://www.bnc.ca",
                Some("Banque"),
                true,
            ),
            (
                "Desjardins",
                "mgordon",
                "https://www.desjardins.com",
                Some("Banque"),
                true,
            ),
            (
                "Hydro-Québec",
                "mgordon@exemple.ca",
                "https://www.hydroquebec.com",
                None,
                false,
            ),
            (
                "Amazon",
                "mgordon@exemple.ca",
                "https://www.amazon.ca",
                None,
                false,
            ),
            (
                "Proton Mail",
                "mgordon@proton.me",
                "https://proton.me",
                Some("Travail"),
                false,
            ),
            (
                "Wikipédia",
                "MGordon",
                "https://fr.wikipedia.org",
                None,
                false,
            ),
        ];
        for (name, username, uri, dir, favorite) in logins {
            session
                .create_item(
                    ItemKind::Login,
                    ItemDraft {
                        name: name.into(),
                        username: username.into(),
                        password: session.generate_password().unwrap(),
                        uri: uri.into(),
                        totp: if favorite {
                            "JBSWY3DPEHPK3PXP".into()
                        } else {
                            String::new()
                        },
                        folder_id: dir.and_then(folder),
                        favorite,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
        session
            .create_item(
                ItemKind::SecureNote,
                ItemDraft {
                    name: "Codes Wi-Fi".into(),
                    notes: "Maison : 1234-5678".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        session
            .create_send(SendDraft {
                name: "Adresse du chalet".into(),
                text: "123, chemin du Lac".into(),
                days: 7,
                max_access_count: Some(5),
                password: None,
                hide_text: false,
            })
            .await
            .unwrap();
        session.sync().await.unwrap();
    }

    /// Crée un compte sur le serveur de test (clés générées par le SDK).
    async fn register_account(server_url: &str, email: &str, password: &str) {
        let keys = Client::new(None)
            .auth()
            .make_register_keys(email.to_owned(), password.to_owned(), Kdf::default_pbkdf2())
            .unwrap();
        let body = serde_json::json!({
            "email": email,
            "name": "E2E",
            "kdf": 0,
            "kdfIterations": 600000,
            "key": keys.encrypted_user_key.to_string(),
            "masterPasswordHash": keys.master_password_hash.to_string(),
            "keys": {
                "publicKey": keys.keys.public.to_string(),
                "encryptedPrivateKey": keys.keys.private.to_string(),
            },
        });
        let response = reqwest::Client::new()
            .post(format!("{server_url}/identity/accounts/register"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "inscription : {}",
            response.text().await.unwrap()
        );
    }

    /// Clé logicielle empruntée, pour la réutiliser entre enregistrement et connexion.
    struct Borrowed<'a>(&'a mut webauthn_authenticator_rs::softtoken::SoftToken);

    impl webauthn_authenticator_rs::AuthenticatorBackendHashedClientData for Borrowed<'_> {
        fn perform_register(
            &mut self,
            client_data_hash: Vec<u8>,
            options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
            timeout_ms: u32,
        ) -> Result<
            webauthn_rs_proto::RegisterPublicKeyCredential,
            webauthn_authenticator_rs::prelude::WebauthnCError,
        > {
            self.0
                .perform_register(client_data_hash, options, timeout_ms)
        }

        fn perform_auth(
            &mut self,
            client_data_hash: Vec<u8>,
            options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
            timeout_ms: u32,
        ) -> Result<
            webauthn_rs_proto::PublicKeyCredential,
            webauthn_authenticator_rs::prelude::WebauthnCError,
        > {
            self.0.perform_auth(client_data_hash, options, timeout_ms)
        }
    }

    /// 2FA par clé de sécurité contre Vaultwarden, avec une clé FIDO2 logicielle
    /// (même bibliothèque CTAP2 que pour les clés USB/NFC) :
    /// `COFFRE_E2E_SERVER=http://localhost:8000 cargo test e2e_webauthn -- --ignored`
    /// (WebAuthn exige https, ou http sur `localhost`.)
    #[test]
    #[ignore]
    fn e2e_webauthn_vaultwarden() {
        use bitwarden_core::client::persisted_state::AUTHENTICATION_TOKENS;
        use bitwarden_core::key_management::MasterPasswordAuthenticationData;
        use webauthn_authenticator_rs::prelude::{
            CreationChallengeResponse, WebauthnAuthenticator,
        };

        let Ok(server_url) = std::env::var("COFFRE_E2E_SERVER") else {
            eprintln!("COFFRE_E2E_SERVER non défini : test ignoré");
            return;
        };
        let server = Server::SelfHosted(server_url.clone());
        let email = format!("webauthn-{}@exemple.ca", uuid::Uuid::new_v4().simple());
        let password = "Mot de passe maître très long 123!".to_owned();
        let device = "11111111-2222-4333-8444-555555555555";

        crate::runtime().block_on(async {
            register_account(&server_url, &email, &password).await;
            let session = Session::create(&server, device, &email).await.unwrap();
            assert!(matches!(
                session.login(password.clone(), None).await.unwrap(),
                LoginOutcome::Authenticated
            ));

            // Activation de la 2FA WebAuthn avec une clé logicielle.
            let token = session
                .client
                .platform()
                .state()
                .setting(AUTHENTICATION_TOKENS)
                .unwrap()
                .get()
                .await
                .unwrap()
                .unwrap()
                .access_token;
            let hash =
                MasterPasswordAuthenticationData::derive(&password, &Kdf::default_pbkdf2(), &email)
                    .unwrap()
                    .master_password_authentication_hash
                    .to_string();
            let http = reqwest::Client::new();
            let creation: serde_json::Value = http
                .post(format!(
                    "{server_url}/api/two-factor/get-webauthn-challenge"
                ))
                .bearer_auth(&token)
                .json(&serde_json::json!({ "masterPasswordHash": hash }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let creation: CreationChallengeResponse =
                serde_json::from_value(serde_json::json!({ "publicKey": creation })).unwrap();
            let origin = session.web_origin().unwrap();
            let (mut soft, _) = webauthn_authenticator_rs::softtoken::SoftToken::new(true).unwrap();
            let credential = WebauthnAuthenticator::new(Borrowed(&mut soft))
                .do_registration(origin.clone(), creation)
                .unwrap();
            let response = http
                .put(format!("{server_url}/api/two-factor/webauthn"))
                .bearer_auth(&token)
                .json(&serde_json::json!({
                    "id": 1,
                    "name": "Clé de test",
                    "masterPasswordHash": hash,
                    "deviceResponse": credential,
                }))
                .send()
                .await
                .unwrap();
            assert!(
                response.status().is_success(),
                "activation WebAuthn : {}",
                response.text().await.unwrap()
            );

            // Nouvelle connexion : la clé de sécurité est exigée.
            let mut session = Session::create(&server, device, &email).await.unwrap();
            let options = match session.login(password.clone(), None).await.unwrap() {
                LoginOutcome::TwoFactorRequired(options) => options,
                LoginOutcome::Authenticated => panic!("la 2FA aurait dû être exigée"),
            };
            assert!(options.webauthn);
            assert_eq!(options.methods()[0], TwoFactorMethod::WebAuthn);

            // Une clé inconnue est refusée par l'authentificateur…
            let challenge = session.webauthn_challenge(&password).await.unwrap();
            let request = crate::security_key::parse_options(challenge).unwrap();
            let (other, _) = webauthn_authenticator_rs::softtoken::SoftToken::new(true).unwrap();
            assert!(matches!(
                crate::security_key::assert_with(other, origin.clone(), request),
                Err(crate::security_key::KeyError::UnknownCredential)
                    | Err(crate::security_key::KeyError::Device(_))
            ));

            // … une assertion falsifiée est refusée par le serveur…
            let challenge = session.webauthn_challenge(&password).await.unwrap();
            let request = crate::security_key::parse_options(challenge).unwrap();
            let assertion =
                crate::security_key::assert_with(Borrowed(&mut soft), origin.clone(), request)
                    .unwrap();
            let forged = assertion.replacen("\"signature\":\"", "\"signature\":\"AAAA", 1);
            assert!(
                session
                    .login(password.clone(), Some((TwoFactorMethod::WebAuthn, forged)))
                    .await
                    .is_err()
            );

            // … et la bonne clé ouvre la session.
            let challenge = session.webauthn_challenge(&password).await.unwrap();
            let request = crate::security_key::parse_options(challenge).unwrap();
            let assertion =
                crate::security_key::assert_with(Borrowed(&mut soft), origin, request).unwrap();
            assert!(matches!(
                session
                    .login(
                        password.clone(),
                        Some((TwoFactorMethod::WebAuthn, assertion))
                    )
                    .await
                    .unwrap(),
                LoginOutcome::Authenticated
            ));
            session.sync().await.unwrap();
            session.unlock(password.clone()).await.unwrap();
            assert!(session.is_unlocked());
            session.logout();
            eprintln!("2FA WebAuthn réussie pour {email}");
        });
    }
}
