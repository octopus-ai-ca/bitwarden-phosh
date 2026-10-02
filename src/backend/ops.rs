//! Opérations du coffre au-delà de la connexion : dossiers, favoris, archive,
//! corbeille, export, import, Send, appareils, phrase d'empreinte, générateurs
//! et icônes de sites.

use bitwarden_api_api::models::{
    CipherRequestModel, FolderWithIdRequestModel, ImportCiphersRequestModel, Int32Int32KeyValuePair,
};
use bitwarden_exporters::{ExportFormat, ExporterClientExt};
use bitwarden_generators::{
    GeneratorClientsExt, PassphraseGeneratorRequest, PasswordGeneratorRequest,
    UsernameGeneratorRequest,
};
use bitwarden_importers::{ImportOptions, ImportTargetFolder, ImporterClientExt};
use bitwarden_send::{SendAddRequest, SendAuthType, SendClientExt, SendTextView, SendViewType};
use bitwarden_vault::{
    CardView, CipherListView, CipherRepromptType, CipherType, CipherView, FieldType, FieldView,
    Folder, FolderAddEditRequest, FolderId, FolderView, LoginUriView, SecureNoteType,
    SecureNoteView, VaultClientExt,
};
use chrono::{DateTime, Utc};

use super::{Error, Server, Session, empty_login, non_empty, storage};

/// Éléments à lister.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Coffre courant (hors corbeille et archive).
    Vault,
    Trash,
    Archive,
}

/// Dossier déchiffré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderInfo {
    pub id: String,
    pub name: String,
}

/// Formats d'export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Json,
    Csv,
    /// JSON chiffré par un mot de passe propre au fichier.
    EncryptedJson,
}

impl ExportKind {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json | Self::EncryptedJson => "json",
        }
    }
}

/// Formats d'import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// Export Bitwarden `.json` non chiffré (Bitwarden, Vaultwarden, Coffre).
    BitwardenJson,
    /// Base KeePass `.kdbx` (avec son mot de passe).
    Keepass,
}

/// Résultat d'un import.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportCount {
    pub items: u32,
    pub folders: u32,
}

/// Appareil connecté au compte.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub kind: String,
    pub first_login: Option<DateTime<Utc>>,
    pub current: bool,
}

/// Send (partage chiffré) déchiffré.
#[derive(Debug, Clone)]
pub struct SendInfo {
    pub id: String,
    pub name: String,
    pub url: Option<String>,
    pub deletion_date: DateTime<Utc>,
    pub access_count: u32,
    pub max_access_count: Option<u32>,
    pub has_password: bool,
}

/// Nouveau Send texte.
#[derive(Debug, Clone, Default)]
pub struct SendDraft {
    pub name: String,
    pub text: String,
    /// Suppression automatique après ce nombre de jours.
    pub days: u32,
    pub max_access_count: Option<u32>,
    pub password: Option<String>,
    /// Masquer le texte par défaut au destinataire.
    pub hide_text: bool,
}

/// Options du générateur de mots de passe.
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    pub length: u8,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub min_numbers: u8,
    pub min_special: u8,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 14,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: true,
            min_numbers: 1,
            min_special: 1,
            avoid_ambiguous: false,
        }
    }
}

/// Options du générateur de phrases de passe.
#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    pub words: u8,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 4,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Options du générateur de noms d'utilisateur (mot aléatoire).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsernameOptions {
    pub capitalize: bool,
    pub include_number: bool,
}

fn api<E: std::fmt::Display>(e: E) -> Error {
    Error::Api(e.to_string())
}

fn crypto<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

fn parse_folder_id(id: &str) -> Result<FolderId, Error> {
    id.parse().map_err(|_| Error::ItemNotFound)
}

fn uuid(id: &str) -> Result<uuid::Uuid, Error> {
    id.parse().map_err(|_| Error::ItemNotFound)
}

/// Nom d'hôte d'une adresse saisie avec ou sans schéma.
pub fn host_of(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if uri.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(uri)
        .or_else(|_| url::Url::parse(&format!("https://{uri}")))
        .ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    parsed.host_str().map(str::to_lowercase)
}

impl Session {
    // ----- Listes -----

    /// Éléments déchiffrés selon `scope`, triés par nom.
    pub async fn list_scope(&self, scope: Scope) -> Result<Vec<CipherListView>, Error> {
        let ciphers = self
            .stored_ciphers()
            .await?
            .into_iter()
            .filter(|c| match scope {
                Scope::Vault => c.deleted_date.is_none() && c.archived_date.is_none(),
                Scope::Trash => c.deleted_date.is_some(),
                Scope::Archive => c.deleted_date.is_none() && c.archived_date.is_some(),
            })
            .collect();
        let result = self
            .client
            .vault()
            .ciphers()
            .decrypt_list_with_failures(ciphers)
            .await;
        if !result.failures.is_empty() {
            eprintln!(
                "{} élément(s) impossibles à déchiffrer",
                result.failures.len()
            );
        }
        let mut items = result.successes;
        items.sort_by_key(|item| item.name.to_lowercase());
        Ok(items)
    }

    /// Date de la dernière synchronisation réussie.
    pub fn last_sync(&self) -> Option<DateTime<Utc>> {
        self.account.as_ref().and_then(|a| a.last_sync)
    }

    // ----- Dossiers -----

    async fn stored_folders(&self) -> Result<Vec<Folder>, Error> {
        self.client
            .platform()
            .state()
            .get::<Folder>()
            .map_err(storage)?
            .list()
            .await
            .map_err(storage)
    }

    /// Dossiers personnels, triés par nom.
    #[allow(deprecated)]
    pub async fn folders(&self) -> Result<Vec<FolderInfo>, Error> {
        let folders = self
            .client
            .vault()
            .folders()
            .decrypt_list(self.stored_folders().await?)
            .map_err(crypto)?;
        let mut folders: Vec<_> = folders
            .into_iter()
            .filter_map(|f| {
                Some(FolderInfo {
                    id: f.id?.to_string(),
                    name: f.name,
                })
            })
            .collect();
        folders.sort_by_key(|f| f.name.to_lowercase());
        Ok(folders)
    }

    pub async fn create_folder(&mut self, name: &str) -> Result<(), Error> {
        let name = non_empty(name).ok_or(Error::EmptyName)?;
        self.client
            .vault()
            .folders()
            .create(FolderAddEditRequest { name })
            .await
            .map_err(api)?;
        Ok(())
    }

    pub async fn rename_folder(&mut self, id: &str, name: &str) -> Result<(), Error> {
        let name = non_empty(name).ok_or(Error::EmptyName)?;
        self.client
            .vault()
            .folders()
            .edit(parse_folder_id(id)?, FolderAddEditRequest { name })
            .await
            .map_err(api)?;
        Ok(())
    }

    /// Supprime un dossier (ses éléments passent dans « Aucun dossier »).
    pub async fn delete_folder(&mut self, id: &str) -> Result<(), Error> {
        let config = self.client.internal.get_api_configurations();
        config
            .api_client
            .folders_api()
            .delete(id)
            .await
            .map_err(api)?;
        self.sync().await
    }

    // ----- Favoris, archive, corbeille -----

    pub async fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<(), Error> {
        let cipher_id = Self::parse_id(id)?;
        let mut view = self.get(id).await?;
        view.favorite = favorite;
        self.save_view(Some(cipher_id), view).await
    }

    /// Archive (exclu du coffre et de la recherche) ou désarchive un élément.
    pub async fn set_archived(&mut self, id: &str, archived: bool) -> Result<(), Error> {
        let config = self.client.internal.get_api_configurations();
        let ciphers = config.api_client.ciphers_api();
        if archived {
            ciphers.put_archive(uuid(id)?).await.map(drop)
        } else {
            ciphers.put_unarchive(uuid(id)?).await.map(drop)
        }
        .map_err(api)?;
        self.sync().await
    }

    /// Restaure un élément de la corbeille.
    pub async fn restore_item(&self, id: &str) -> Result<(), Error> {
        self.client
            .vault()
            .ciphers()
            .restore(Self::parse_id(id)?)
            .await
            .map_err(api)?;
        Ok(())
    }

    /// Supprime définitivement un élément (irréversible).
    pub async fn delete_permanently(&self, id: &str) -> Result<(), Error> {
        self.client
            .vault()
            .ciphers()
            .delete(Self::parse_id(id)?)
            .await
            .map_err(api)
    }

    // ----- Export et import -----

    /// Vérifie le mot de passe maître (avant un export, comme les clients officiels).
    pub async fn verify_master_password(&self, password: &str) -> Result<(), Error> {
        let wrapped = self
            .account()?
            .master_password_unlock
            .master_key_wrapped_user_key
            .to_string();
        self.client
            .auth()
            .validate_password_user_key(password.to_owned(), wrapped)
            .await
            .map(drop)
            .map_err(|_| Error::WrongPassword)
    }

    /// Exporte le coffre personnel (hors corbeille) dans le format demandé.
    pub async fn export(
        &self,
        kind: ExportKind,
        file_password: Option<String>,
    ) -> Result<String, Error> {
        let format = match kind {
            ExportKind::Json => ExportFormat::Json,
            ExportKind::Csv => ExportFormat::Csv,
            ExportKind::EncryptedJson => ExportFormat::EncryptedJson {
                password: file_password
                    .filter(|p| !p.is_empty())
                    .ok_or(Error::MissingData("mot de passe du fichier"))?,
            },
        };
        let ciphers = self
            .stored_ciphers()
            .await?
            .into_iter()
            .filter(|c| c.deleted_date.is_none() && c.organization_id.is_none())
            .collect();
        self.client
            .exporters()
            .export_vault(self.stored_folders().await?, ciphers, format)
            .await
            .map_err(crypto)
    }

    /// Importe des éléments dans le coffre personnel, éventuellement dans un dossier.
    pub async fn import(
        &mut self,
        kind: ImportKind,
        data: Vec<u8>,
        file_password: Option<String>,
        folder_id: Option<String>,
    ) -> Result<ImportCount, Error> {
        let count = match kind {
            ImportKind::Keepass => {
                let target_folder = match folder_id {
                    Some(id) => {
                        let name = self
                            .folders()
                            .await?
                            .into_iter()
                            .find(|f| f.id == id)
                            .map(|f| f.name)
                            .ok_or(Error::ItemNotFound)?;
                        Some(ImportTargetFolder {
                            id: parse_folder_id(&id)?,
                            name,
                        })
                    }
                    None => None,
                };
                let summary = self
                    .client
                    .importers()
                    .import_kdbx(
                        data,
                        file_password.filter(|p| !p.is_empty()),
                        None,
                        ImportOptions {
                            organization_id: None,
                            target_folder,
                            target_collection: None,
                            restricted_types: vec![],
                        },
                    )
                    .await
                    .map_err(|e| Error::Api(e.to_string()))?;
                ImportCount {
                    items: summary.ciphers.iter().map(|c| c.count).sum(),
                    folders: summary.folders,
                }
            }
            ImportKind::BitwardenJson => {
                let text = String::from_utf8(data).map_err(|_| Error::Malformed)?;
                self.import_bitwarden_json(&text, folder_id).await?
            }
        };
        self.sync().await?;
        Ok(count)
    }

    #[allow(deprecated)]
    async fn import_bitwarden_json(
        &mut self,
        text: &str,
        target_folder: Option<String>,
    ) -> Result<ImportCount, Error> {
        let export: BitwardenExport = serde_json::from_str(text).map_err(|_| Error::Malformed)?;
        if export.encrypted {
            return Err(Error::EncryptedImport);
        }

        // Dossiers du fichier (sauf si tout va dans un dossier choisi).
        let mut folder_index = std::collections::HashMap::new();
        let mut folders = Vec::new();
        if target_folder.is_none() {
            for folder in &export.folders {
                let encrypted = self
                    .client
                    .vault()
                    .folders()
                    .encrypt(FolderView {
                        id: None,
                        name: folder.name.clone(),
                        revision_date: Utc::now(),
                    })
                    .map_err(crypto)?;
                folder_index.insert(folder.id.clone(), folders.len() as i32);
                folders.push(FolderWithIdRequestModel {
                    name: encrypted.name.to_string(),
                    id: None,
                });
            }
        }

        let target = target_folder.as_deref().map(parse_folder_id).transpose()?;
        let mut ciphers = Vec::new();
        let mut relationships = Vec::new();
        for item in export.items {
            let Some(mut view) = item.to_view() else {
                continue;
            };
            view.folder_id = target;
            let context = self
                .client
                .vault()
                .ciphers()
                .encrypt(view)
                .await
                .map_err(crypto)?;
            if let Some(index) = item.folder_id.as_ref().and_then(|id| folder_index.get(id)) {
                relationships.push(Int32Int32KeyValuePair {
                    key: Some(ciphers.len() as i32),
                    value: Some(*index),
                });
            }
            ciphers.push(CipherRequestModel::from(context));
        }

        let count = ImportCount {
            items: ciphers.len() as u32,
            folders: folders.len() as u32,
        };
        if count.items == 0 && count.folders == 0 {
            return Ok(count);
        }
        let config = self.client.internal.get_api_configurations();
        config
            .api_client
            .import_ciphers_api()
            .post_import(Some(ImportCiphersRequestModel {
                folders: Some(folders),
                ciphers: Some(ciphers),
                folder_relationships: Some(relationships),
            }))
            .await
            .map_err(api)?;
        Ok(count)
    }

    // ----- Send -----

    async fn stored_sends(&self) -> Result<Vec<bitwarden_send::Send>, Error> {
        self.client
            .platform()
            .state()
            .get::<bitwarden_send::Send>()
            .map_err(storage)?
            .list()
            .await
            .map_err(storage)
    }

    /// Lien public d'un Send : `<coffre web>/#/send/<accès>/<clé base64url>`.
    fn send_url(&self, access_id: &str, key: &str) -> Option<String> {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(key)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key))
            .ok()?;
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let origin = self.web_origin().ok()?;
        Some(format!(
            "{}/#/send/{access_id}/{key}",
            origin.as_str().trim_end_matches('/')
        ))
    }

    /// Sends du compte, du plus récent au plus ancien.
    pub async fn sends(&self) -> Result<Vec<SendInfo>, Error> {
        let mut out = Vec::new();
        for send in self.stored_sends().await? {
            let Ok(view) = self.client.sends().decrypt(send) else {
                continue;
            };
            let Some(id) = view.id else { continue };
            let url = match (&view.access_id, &view.key) {
                (Some(access), Some(key)) => self.send_url(access, key),
                _ => None,
            };
            out.push(SendInfo {
                id: id.to_string(),
                name: view.name,
                url,
                deletion_date: view.deletion_date,
                access_count: view.access_count,
                max_access_count: view.max_access_count,
                has_password: view.has_password,
            });
        }
        out.sort_by_key(|send| std::cmp::Reverse(send.deletion_date));
        Ok(out)
    }

    /// Crée un Send texte et retourne son lien.
    pub async fn create_send(&self, draft: SendDraft) -> Result<Option<String>, Error> {
        let name = non_empty(&draft.name).ok_or(Error::EmptyName)?;
        if draft.text.trim().is_empty() {
            return Err(Error::MissingData("texte"));
        }
        let view = self
            .client
            .sends()
            .create(SendAddRequest {
                name,
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some(draft.text),
                    hidden: draft.hide_text,
                }),
                max_access_count: draft.max_access_count,
                disabled: false,
                hide_email: false,
                deletion_date: Utc::now()
                    + chrono::Duration::days(i64::from(draft.days.clamp(1, 31))),
                expiration_date: None,
                auth: match draft.password.filter(|p| !p.is_empty()) {
                    Some(password) => SendAuthType::Password { password },
                    None => SendAuthType::None,
                },
            })
            .await
            .map_err(api)?;
        Ok(match (&view.access_id, &view.key) {
            (Some(access), Some(key)) => self.send_url(access, key),
            _ => None,
        })
    }

    pub async fn delete_send(&self, id: &str) -> Result<(), Error> {
        self.client
            .sends()
            .delete(id.parse().map_err(|_| Error::ItemNotFound)?)
            .await
            .map_err(api)
    }

    // ----- Compte -----

    /// Appareils connectés au compte, du plus récent au plus ancien.
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, Error> {
        let config = self.client.internal.get_api_configurations();
        let list = config
            .api_client
            .devices_api()
            .get_all()
            .await
            .map_err(api)?;
        let mut devices: Vec<_> = list
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|d| DeviceInfo {
                name: d.name.unwrap_or_default(),
                kind: d.r#type.map(device_label).unwrap_or("Appareil").to_owned(),
                first_login: d
                    .creation_date
                    .and_then(|date| DateTime::parse_from_rfc3339(&date).ok())
                    .map(|date| date.with_timezone(&Utc)),
                current: d.identifier.as_deref() == Some(super::SDK_LOGIN_DEVICE_ID),
            })
            .collect();
        devices.sort_by_key(|d| std::cmp::Reverse((d.current, d.first_login)));
        Ok(devices)
    }

    /// Phrase d'empreinte du compte (à comparer avec celle du coffre web).
    pub fn fingerprint_phrase(&self) -> Result<String, Error> {
        let user_id = self
            .account()?
            .user_id
            .ok_or(Error::MissingData("identifiant du compte"))?;
        self.client
            .platform()
            .user_fingerprint(user_id.to_string())
            .map_err(crypto)
    }

    /// Adresse du coffre web pour une page de paramètres (2FA, mot de passe…).
    pub fn web_vault_page(&self, route: &str) -> Option<String> {
        let origin = self.web_origin().ok()?;
        Some(format!(
            "{}/#/{route}",
            origin.as_str().trim_end_matches('/')
        ))
    }

    // ----- Générateurs -----

    pub fn generate_with(&self, options: &PasswordOptions) -> Result<String, Error> {
        self.client
            .generator()
            .password(PasswordGeneratorRequest {
                lowercase: options.lowercase,
                uppercase: options.uppercase,
                numbers: options.numbers,
                special: options.special,
                length: options.length,
                avoid_ambiguous: options.avoid_ambiguous,
                min_lowercase: options.lowercase.then_some(1),
                min_uppercase: options.uppercase.then_some(1),
                min_number: options.numbers.then_some(options.min_numbers),
                min_special: options.special.then_some(options.min_special),
                custom_required_chars: None,
                custom_allowed_chars: None,
                max_consecutive: None,
            })
            .map_err(crypto)
    }

    pub fn generate_passphrase(&self, options: &PassphraseOptions) -> Result<String, Error> {
        self.client
            .generator()
            .passphrase(PassphraseGeneratorRequest {
                num_words: options.words,
                word_separator: options.separator.clone(),
                capitalize: options.capitalize,
                include_number: options.include_number,
            })
            .map_err(crypto)
    }

    pub async fn generate_username(&self, options: &UsernameOptions) -> Result<String, Error> {
        self.client
            .generator()
            .username(UsernameGeneratorRequest::Word {
                capitalize: options.capitalize,
                include_number: options.include_number,
            })
            .await
            .map_err(crypto)
    }

    // ----- Icônes des sites -----

    /// Adresse de l'icône d'un site, selon le service d'icônes du serveur.
    pub fn icon_url(&self, host: &str) -> Option<String> {
        let base = match &self.server {
            Server::BitwardenUs => "https://icons.bitwarden.net".to_owned(),
            Server::BitwardenEu => "https://icons.bitwarden.eu".to_owned(),
            Server::SelfHosted(url) => format!("{}/icons", url.trim().trim_end_matches('/')),
        };
        Some(format!("{base}/{host}/icon.png"))
    }

    /// Télécharge l'icône d'un site (PNG), ou `None` si le service n'en a pas.
    pub async fn fetch_icon(&self, host: &str) -> Option<Vec<u8>> {
        let url = self.icon_url(host)?;
        let response = self
            .client
            .internal
            .get_http_client()
            .get(url)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let bytes = response.bytes().await.ok()?;
        (!bytes.is_empty()).then(|| bytes.to_vec())
    }

    pub fn server(&self) -> &Server {
        &self.server
    }
}

fn device_label(kind: bitwarden_api_api::models::DeviceType) -> &'static str {
    use bitwarden_api_api::models::DeviceType as D;
    match kind {
        D::Android | D::AndroidAmazon => "Application Android",
        D::iOS => "Application iOS",
        D::ChromeExtension => "Extension - Chrome",
        D::FirefoxExtension => "Extension - Firefox",
        D::OperaExtension => "Extension - Opera",
        D::EdgeExtension => "Extension - Edge",
        D::VivaldiExtension => "Extension - Vivaldi",
        D::SafariExtension => "Extension - Safari",
        D::DuckDuckGoExtension => "Extension - DuckDuckGo",
        D::WindowsDesktop | D::UWP => "Bureau - Windows",
        D::MacOsDesktop => "Bureau - macOS",
        D::LinuxDesktop => "Bureau - Linux",
        D::ChromeBrowser => "Application web - Chrome",
        D::FirefoxBrowser => "Application web - Firefox",
        D::OperaBrowser => "Application web - Opera",
        D::EdgeBrowser => "Application web - Edge",
        D::SafariBrowser => "Application web - Safari",
        D::VivaldiBrowser => "Application web - Vivaldi",
        D::DuckDuckGoBrowser => "Application web - DuckDuckGo",
        D::IEBrowser | D::UnknownBrowser => "Application web",
        D::WindowsCLI | D::MacOsCLI | D::LinuxCLI => "Ligne de commande",
        D::SDK => "SDK",
        D::Server => "Serveur",
        _ => "Appareil",
    }
}

// ----- Format d'export Bitwarden (.json non chiffré) -----

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<ExportFolder>,
    #[serde(default)]
    items: Vec<ExportItem>,
}

#[derive(serde::Deserialize)]
struct ExportFolder {
    id: String,
    name: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportItem {
    #[serde(rename = "type")]
    kind: u8,
    name: String,
    folder_id: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    reprompt: u8,
    login: Option<ExportLogin>,
    card: Option<ExportCard>,
    #[serde(default)]
    fields: Vec<ExportField>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<ExportUri>,
}

#[derive(serde::Deserialize)]
struct ExportUri {
    uri: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(serde::Deserialize)]
struct ExportField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type", default)]
    kind: u8,
}

impl ExportItem {
    /// Vue SDK de l'élément (identifiants, notes et cartes ; autres types ignorés).
    fn to_view(&self) -> Option<CipherView> {
        let now = Utc::now();
        let (r#type, login, secure_note, card) = match self.kind {
            1 => {
                let source = self.login.as_ref();
                let mut login = empty_login();
                login.username = source.and_then(|l| l.username.clone());
                login.password = source.and_then(|l| l.password.clone());
                login.totp = source.and_then(|l| l.totp.clone());
                let uris: Vec<_> = source
                    .map(|l| l.uris.as_slice())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|u| u.uri.clone())
                    .map(|uri| LoginUriView {
                        uri: Some(uri),
                        r#match: None,
                        uri_checksum: None,
                    })
                    .collect();
                login.uris = (!uris.is_empty()).then_some(uris);
                (CipherType::Login, Some(login), None, None)
            }
            2 => (
                CipherType::SecureNote,
                None,
                Some(SecureNoteView {
                    r#type: SecureNoteType::Generic,
                }),
                None,
            ),
            3 => {
                let c = self.card.as_ref()?;
                (
                    CipherType::Card,
                    None,
                    None,
                    Some(CardView {
                        cardholder_name: c.cardholder_name.clone(),
                        exp_month: c.exp_month.clone(),
                        exp_year: c.exp_year.clone(),
                        code: c.code.clone(),
                        brand: c.brand.clone(),
                        number: c.number.clone(),
                    }),
                )
            }
            _ => return None,
        };
        let fields: Vec<_> = self
            .fields
            .iter()
            .map(|f| FieldView {
                name: f.name.clone(),
                value: f.value.clone(),
                r#type: match f.kind {
                    1 => FieldType::Hidden,
                    2 => FieldType::Boolean,
                    _ => FieldType::Text,
                },
                linked_id: None,
            })
            .collect();
        Some(CipherView {
            partial: false,
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: self.name.clone(),
            notes: self.notes.clone(),
            r#type,
            login,
            identity: None,
            card,
            secure_note,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: self.favorite,
            reprompt: if self.reprompt == 1 {
                CipherRepromptType::Password
            } else {
                CipherRepromptType::None
            },
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: (!fields.is_empty()).then_some(fields),
            password_history: None,
            creation_date: now,
            deleted_date: None,
            revision_date: now,
            archived_date: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hote_des_adresses() {
        assert_eq!(
            host_of("https://www.BNC.ca/login").as_deref(),
            Some("www.bnc.ca")
        );
        assert_eq!(host_of("github.com").as_deref(), Some("github.com"));
        assert_eq!(host_of("ssh://serveur"), None);
        assert_eq!(host_of(""), None);
    }

    #[test]
    fn lecture_export_bitwarden() {
        let json = r#"{
            "encrypted": false,
            "folders": [{"id": "f1", "name": "Banques"}],
            "items": [
                {"id": "a", "organizationId": null, "folderId": "f1", "type": 1,
                 "reprompt": 0, "name": "BNC", "notes": null, "favorite": true,
                 "login": {"username": "moi", "password": "secret", "totp": null,
                           "uris": [{"match": null, "uri": "https://bnc.ca"}]},
                 "collectionIds": null},
                {"id": "b", "type": 2, "name": "Note", "notes": "texte",
                 "secureNote": {"type": 0}, "favorite": false},
                {"id": "c", "type": 4, "name": "Identité", "identity": {}}
            ]
        }"#;
        let export: BitwardenExport = serde_json::from_str(json).unwrap();
        assert_eq!(export.folders.len(), 1);
        let views: Vec<_> = export
            .items
            .iter()
            .filter_map(ExportItem::to_view)
            .collect();
        assert_eq!(views.len(), 2, "les identités sont ignorées");
        let login = views[0].login.as_ref().unwrap();
        assert_eq!(login.password.as_deref(), Some("secret"));
        assert!(views[0].favorite);
        assert_eq!(views[1].notes.as_deref(), Some("texte"));
    }
}
