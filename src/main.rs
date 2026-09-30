//! Coffre : client Bitwarden adaptatif pour Phosh et GNOME.

mod backend;
mod config;
mod nfc_nci;
mod security_key;
mod ui;

use adw::prelude::*;
use gtk::glib;

pub const APP_ID: &str = "ca.octopusai.Coffre";
pub const APP_NAME: &str = "coffre";

/// Environnement Tokio partagé : le SDK (reqwest) en a besoin pour ses appels réseau.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("impossible de créer l'environnement Tokio")
    })
}

/// Exécute `future` sur Tokio, puis `done` sur le fil principal GTK avec le résultat.
pub fn spawn<F, T>(future: F, done: impl FnOnce(T) + 'static)
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handle = runtime().spawn(future);
    glib::spawn_future_local(async move {
        match handle.await {
            Ok(value) => done(value),
            Err(e) => eprintln!("tâche interrompue : {e}"),
        }
    });
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        if let Some(window) = app.active_window() {
            window.present();
            return;
        }
        ui::App::new(app).present();
    });
    app.run()
}
