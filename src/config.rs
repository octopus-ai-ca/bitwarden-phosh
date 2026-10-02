//! Préférences non sensibles persistées entre les lancements (serveur,
//! courriel, identifiant d'appareil, réglages). Aucun secret n'est écrit ici.

use std::path::PathBuf;

use crate::backend::Server;

/// Thème de l'interface.
#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Theme {
    /// Suit le réglage du système.
    #[default]
    System,
    Light,
    Dark,
}

/// Action à l'expiration de la session (inactivité).
#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    #[default]
    Lock,
    Logout,
}

/// Délais proposés pour l'expiration de la session, en minutes (0 : jamais).
pub const LOCK_TIMEOUTS: [(u32, &str); 7] = [
    (1, "1 minute"),
    (5, "5 minutes"),
    (15, "15 minutes"),
    (30, "30 minutes"),
    (60, "1 heure"),
    (240, "4 heures"),
    (0, "Jamais"),
];

/// Délais proposés pour l'effacement du presse-papier, en secondes (0 : jamais).
pub const CLIPBOARD_DELAYS: [(u32, &str); 6] = [
    (10, "10 secondes"),
    (20, "20 secondes"),
    (30, "30 secondes"),
    (60, "1 minute"),
    (300, "5 minutes"),
    (0, "Jamais"),
];

fn default_true() -> bool {
    true
}

fn default_lock_minutes() -> u32 {
    5
}

fn default_clipboard_seconds() -> u32 {
    30
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub theme: Theme,
    /// Rangées plus denses.
    #[serde(default)]
    pub compact: bool,
    /// Icônes des sites web (service d'icônes du serveur).
    #[serde(default = "default_true")]
    pub show_icons: bool,
    /// Boutons de copie rapide dans la liste du coffre.
    #[serde(default = "default_true")]
    pub quick_copy: bool,
    #[serde(default = "default_lock_minutes")]
    pub lock_minutes: u32,
    #[serde(default)]
    pub timeout_action: TimeoutAction,
    #[serde(default = "default_clipboard_seconds")]
    pub clipboard_seconds: u32,
    /// Copier le code TOTP après le mot de passe (comme l'extension).
    #[serde(default)]
    pub auto_copy_totp: bool,
}

impl Default for Config {
    fn default() -> Self {
        // Mêmes valeurs par défaut que lors de la lecture d'un fichier incomplet.
        serde_json::from_str("{}").expect("configuration par défaut")
    }
}

fn path() -> PathBuf {
    gtk::glib::user_config_dir()
        .join(crate::APP_NAME)
        .join("config.json")
}

impl Config {
    /// Charge la configuration; génère un identifiant d'appareil au besoin.
    pub fn load() -> Self {
        let mut config: Self = std::fs::read(path())
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        if config.device_id.is_empty() {
            config.device_id = uuid::Uuid::new_v4().to_string();
            config.save();
        }
        config
    }

    pub fn save(&self) {
        let path = path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match serde_json::to_vec_pretty(self) {
            Ok(data) => {
                if let Err(e) = std::fs::write(&path, data) {
                    eprintln!("impossible d'écrire {}: {e}", path.display());
                }
            }
            Err(e) => eprintln!("sérialisation de la configuration: {e}"),
        }
    }
}
