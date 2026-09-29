//! Couche d'accès au coffre, bâtie sur le SDK officiel Bitwarden (option GPL-3.0).
//!
//! Le SDK se charge de l'authentification, de la dérivation de clés et du
//! déchiffrement. Ce module ne conserve en mémoire que des données chiffrées
//! (éléments du coffre, clés protégées); les clés déchiffrées vivent dans le
//! `KeyStore` du SDK et sont effacées au verrouillage.

use std::collections::HashMap;
use std::sync::Arc;

use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::{
    Client, ClientBuilder, ClientSettings, DeviceType, OrganizationId,
    auth::login::{
        PasswordLoginRequest, TwoFactorEmailRequest, TwoFactorProvider, TwoFactorRequest,
    },
    key_management::{
        MasterPasswordUnlockData, SymmetricKeySlotId,
        account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::{InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
    },
};
use bitwarden_crypto::{EncString, Kdf, UnsignedSharedKey};
use bitwarden_vault::{Cipher, CipherListView, CipherView, VaultClientExt};

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
    #[error("Cette méthode de connexion en deux étapes n'est pas encore prise en charge.")]
    UnsupportedTwoFactor,
    #[error("Réponse du serveur incomplète : {0}")]
    MissingData(&'static str),
    #[error("Élément introuvable.")]
    ItemNotFound,
    #[error("Échec de la connexion : {0}")]
    Login(#[from] bitwarden_core::auth::login::LoginError),
    #[error("Échec de l'envoi du courriel : {0}")]
    TwoFactorEmail(#[from] bitwarden_core::auth::login::TwoFactorEmailError),
    #[error("Échec de la synchronisation : {0}")]
    Api(String),
    #[error("Erreur de chiffrement : {0}")]
    Crypto(String),
    #[error("Erreur de déchiffrement : {0}")]
    Decrypt(#[from] bitwarden_vault::DecryptError),
}

/// Méthodes 2FA proposées par le serveur et prises en charge ici.
#[derive(Debug, Clone, Copy)]
pub struct TwoFactorOptions {
    pub authenticator: bool,
    pub email: bool,
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
}

/// Données chiffrées nécessaires pour déverrouiller sans repasser par le serveur.
#[derive(Clone)]
struct UnlockData {
    kdf: Kdf,
    master_password_unlock: MasterPasswordUnlockData,
    account_state: String,
    org_keys: HashMap<OrganizationId, UnsignedSharedKey>,
}

/// Session d'un compte : client SDK, éléments chiffrés et données de déverrouillage.
///
/// `Clone` partage le même client SDK (Arc interne).
#[derive(Clone)]
pub struct Session {
    client: Client,
    email: String,
    unlock: Option<Arc<UnlockData>>,
    ciphers: Arc<Vec<Cipher>>,
}

impl Session {
    pub fn new(server: &Server, device_id: &str, email: &str) -> Result<Self, Error> {
        let (api_url, identity_url) = server.urls()?;
        let settings = ClientSettings {
            identity_url,
            api_url,
            user_agent: format!("{}/{}", crate::APP_NAME, env!("CARGO_PKG_VERSION")),
            device_type: DeviceType::LinuxDesktop,
            device_identifier: Some(device_id.to_owned()),
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        };
        let client = ClientBuilder::new()
            .with_settings(settings)
            .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
            .build();
        Ok(Self {
            client,
            email: email.trim().to_owned(),
            unlock: None,
            ciphers: Arc::default(),
        })
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
            token: token.trim().replace(' ', ""),
            provider: match method {
                TwoFactorMethod::Authenticator => TwoFactorProvider::Authenticator,
                TwoFactorMethod::Email => TwoFactorProvider::Email,
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
                };
                if options.authenticator || options.email {
                    Ok(LoginOutcome::TwoFactorRequired(options))
                } else {
                    Err(Error::UnsupportedTwoFactor)
                }
            }
            None => Ok(LoginOutcome::Authenticated),
        }
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

    /// Télécharge le coffre et met à jour les données de déverrouillage.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let config = self.client.internal.get_api_configurations();
        let sync = config
            .api_client
            .sync_api()
            .get(None)
            .await
            .map_err(|e| Error::Api(e.to_string()))?;

        let profile = sync.profile.ok_or(Error::MissingData("profil"))?;

        let kdf = match self.unlock.as_ref() {
            Some(unlock) => unlock.kdf.clone(),
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

        let org_keys = profile
            .organizations
            .unwrap_or_default()
            .into_iter()
            .filter_map(|org| {
                let id = OrganizationId::new(org.id?);
                let key = org.key?.parse().ok()?;
                Some((id, key))
            })
            .collect();

        let ciphers = sync
            .ciphers
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| Cipher::try_from(c).ok())
            .filter(|c| c.deleted_date.is_none())
            .collect();

        self.unlock = Some(Arc::new(UnlockData {
            kdf,
            master_password_unlock,
            account_state: serde_json::to_string(&account_state)
                .map_err(|e| Error::Crypto(e.to_string()))?,
            org_keys,
        }));
        self.ciphers = Arc::new(ciphers);
        Ok(())
    }

    pub fn is_unlocked(&self) -> bool {
        self.client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeySlotId::User)
    }

    /// Déverrouille localement (sans réseau) à partir des données de la dernière synchro.
    pub async fn unlock(&self, password: String) -> Result<(), Error> {
        let unlock = self
            .unlock
            .as_ref()
            .ok_or(Error::MissingData("synchronisation"))?;
        if !self.is_unlocked() {
            let account_cryptographic_state = serde_json::from_str(&unlock.account_state)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            self.client
                .crypto()
                .initialize_user_crypto(InitUserCryptoRequest {
                    user_id: None,
                    kdf_params: unlock.kdf.clone(),
                    email: self.email.clone(),
                    account_cryptographic_state,
                    method: InitUserCryptoMethod::MasterPasswordUnlock {
                        password,
                        master_password_unlock: unlock.master_password_unlock.clone(),
                    },
                    upgrade_token: None,
                })
                .await
                .map_err(|_| Error::WrongPassword)?;
        }
        if !unlock.org_keys.is_empty() {
            self.client
                .crypto()
                .initialize_org_crypto(InitOrgCryptoRequest {
                    organization_keys: unlock.org_keys.clone(),
                })
                .await
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        Ok(())
    }

    /// Efface toutes les clés déchiffrées de la mémoire.
    pub fn lock(&self) {
        self.client.internal.get_key_store().clear();
    }

    /// Liste déchiffrée (noms, sous-titres) des éléments, triée par nom.
    pub async fn list(&self) -> Vec<CipherListView> {
        let result = self
            .client
            .vault()
            .ciphers()
            .decrypt_list_with_failures(self.ciphers.as_ref().clone())
            .await;
        if !result.failures.is_empty() {
            eprintln!(
                "{} élément(s) impossibles à déchiffrer",
                result.failures.len()
            );
        }
        let mut items = result.successes;
        items.sort_by_key(|item| item.name.to_lowercase());
        items
    }

    /// Déchiffre un élément complet (mot de passe, notes, etc.).
    pub async fn get(&self, id: &str) -> Result<CipherView, Error> {
        let cipher = self
            .ciphers
            .iter()
            .find(|c| c.id.is_some_and(|cid| cid.to_string() == id))
            .cloned()
            .ok_or(Error::ItemNotFound)?;
        Ok(self.client.vault().ciphers().decrypt(cipher).await?)
    }
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

    /// Vérifie le chemin réseau réel : `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn connexion_refusee_sur_bitwarden_com() {
        crate::runtime().block_on(async {
            let session = Session::new(
                &Server::BitwardenUs,
                "00000000-0000-4000-8000-000000000000",
                "coffre-test-inexistant@example.com",
            )
            .unwrap();
            let result = session.login("mauvais mot de passe".into(), None).await;
            let err = result.err().expect("la connexion aurait dû échouer");
            eprintln!("erreur obtenue : {err}");
        });
    }
}
