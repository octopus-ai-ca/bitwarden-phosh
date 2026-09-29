//! Préférences non sensibles persistées entre les lancements
//! (serveur, courriel, identifiant d'appareil). Aucun secret n'est écrit ici.

use std::path::PathBuf;

use crate::backend::Server;

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub device_id: String,
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
