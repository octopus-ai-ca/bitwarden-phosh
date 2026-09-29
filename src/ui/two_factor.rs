//! Connexion en deux étapes : application d'authentification, courriel,
//! YubiKey OTP (USB) et clé de sécurité FIDO2 (USB ou NFC).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use adw::prelude::*;

use super::login::login;
use super::{App, page, pill_button, set_busy};
use crate::backend::{Session, TwoFactorMethod, TwoFactorOptions};
use crate::security_key::{self, KeyEvent};

const KEY_BUTTON: &str = "Utiliser la clé de sécurité";

/// Widgets et état partagés de la page.
struct Page {
    app: App,
    session: Session,
    password: String,
    method: Cell<TwoFactorMethod>,
    status: adw::StatusPage,
    /// Groupe (choix de méthode, code), masqué s'il n'a rien à montrer.
    group: adw::PreferencesGroup,
    several_methods: bool,
    code_row: adw::EntryRow,
    submit: gtk::Button,
    email_button: gtk::Button,
    key_box: gtk::Box,
    key_spinner: gtk::Spinner,
    key_label: gtk::Label,
    key_button: gtk::Button,
    email_sent: Cell<bool>,
    /// Drapeau d'annulation de l'opération de clé en cours, s'il y en a une.
    key_cancel: RefCell<Option<Arc<AtomicBool>>>,
}

pub fn two_factor_page(
    app: &App,
    session: Session,
    password: String,
    options: TwoFactorOptions,
) -> adw::NavigationPage {
    let methods = options.methods();

    let status = adw::StatusPage::builder()
        .icon_name("security-high-symbolic")
        .title("Connexion en deux étapes")
        .build();
    status.add_css_class("compact");

    let labels: Vec<&str> = methods.iter().map(|m| m.label()).collect();
    let method_row = adw::ComboRow::builder()
        .title("Méthode")
        .model(&gtk::StringList::new(&labels))
        .visible(methods.len() > 1)
        .build();
    let code_row = adw::EntryRow::new();
    let group = adw::PreferencesGroup::new();
    group.add(&method_row);
    group.add(&code_row);

    let submit = pill_button("Valider");
    let email_button = gtk::Button::builder()
        .label("Renvoyer le code par courriel")
        .halign(gtk::Align::Center)
        .build();
    email_button.add_css_class("flat");

    let key_spinner = gtk::Spinner::new();
    let key_label = gtk::Label::builder()
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    let key_button = pill_button(KEY_BUTTON);
    let key_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
    key_box.append(&key_spinner);
    key_box.append(&key_label);
    key_box.append(&key_button);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&status);
    content.append(&group);
    content.append(&submit);
    content.append(&email_button);
    content.append(&key_box);

    let state = Rc::new(Page {
        app: app.clone(),
        session,
        password,
        method: Cell::new(methods[0]),
        status,
        group,
        several_methods: methods.len() > 1,
        code_row,
        submit,
        email_button,
        key_box,
        key_spinner,
        key_label,
        key_button,
        email_sent: Cell::new(false),
        key_cancel: RefCell::default(),
    });

    {
        let state = state.clone();
        method_row.connect_selected_notify(move |row| {
            if let Some(&method) = methods.get(row.selected() as usize) {
                state.select(method);
            }
        });
    }
    {
        let state_ = state.clone();
        state.submit.connect_clicked(move |_| state_.submit_code());
        let state_ = state.clone();
        // La YubiKey termine sa saisie par « Entrée ».
        state
            .code_row
            .connect_entry_activated(move |_| state_.submit_code());
        let state_ = state.clone();
        state
            .email_button
            .connect_clicked(move |_| state_.send_email());
        let state_ = state.clone();
        state
            .key_button
            .connect_clicked(move |_| state_.start_security_key());
    }

    let page = page(
        "Vérification",
        "two-factor",
        &adw::HeaderBar::new(),
        &content,
    );
    {
        let state = state.clone();
        page.connect_shown(move |_| state.select(state.method.get()));
    }
    {
        let state = state.clone();
        page.connect_hidden(move |_| state.cancel_security_key());
    }
    page
}

impl Page {
    fn select(self: &Rc<Self>, method: TwoFactorMethod) {
        self.cancel_security_key();
        self.method.set(method);
        let uses_code = method != TwoFactorMethod::WebAuthn;
        self.code_row.set_visible(uses_code);
        self.group.set_visible(uses_code || self.several_methods);
        self.submit.set_visible(uses_code);
        self.key_box.set_visible(!uses_code);
        self.email_button
            .set_visible(method == TwoFactorMethod::Email);
        self.code_row.set_text("");

        let (description, title, purpose) = match method {
            TwoFactorMethod::Authenticator => (
                "Entrez le code à 6 chiffres de votre application d'authentification.",
                "Code de vérification",
                gtk::InputPurpose::Digits,
            ),
            TwoFactorMethod::Email => (
                "Entrez le code reçu par courriel.",
                "Code de vérification",
                gtk::InputPurpose::Digits,
            ),
            TwoFactorMethod::YubiKey => (
                "Branchez la YubiKey au port USB, puis touchez-la : le code est saisi \
                 automatiquement.",
                "Code YubiKey",
                gtk::InputPurpose::FreeForm,
            ),
            TwoFactorMethod::WebAuthn => (
                "Branchez votre clé de sécurité au port USB ou posez-la sur le lecteur NFC, \
                 puis touchez-la si elle clignote.",
                "",
                gtk::InputPurpose::FreeForm,
            ),
        };
        self.status.set_description(Some(description));
        self.code_row.set_title(title);
        self.code_row.set_input_purpose(purpose);

        match method {
            TwoFactorMethod::WebAuthn => self.start_security_key(),
            TwoFactorMethod::Email if !self.email_sent.get() => self.send_email(),
            _ => {
                self.code_row.grab_focus();
            }
        }
    }

    fn submit_code(&self) {
        let token = self.code_row.text().trim().to_owned();
        if token.is_empty() {
            return;
        }
        set_busy(&self.submit, true, "Valider", "Vérification…");
        let submit = self.submit.clone();
        login(
            &self.app,
            self.session.clone(),
            self.password.clone(),
            Some((self.method.get(), token)),
            move |_| set_busy(&submit, false, "Valider", ""),
        );
    }

    fn send_email(self: &Rc<Self>) {
        self.email_sent.set(true);
        let button = self.email_button.clone();
        set_busy(&button, true, "Renvoyer le code par courriel", "Envoi…");
        let (app, session, password) = (
            self.app.clone(),
            self.session.clone(),
            self.password.clone(),
        );
        let state = self.clone();
        crate::spawn(
            async move { session.send_two_factor_email(password).await },
            move |result| {
                set_busy(&button, false, "Renvoyer le code par courriel", "");
                match result {
                    Ok(()) => app.toast("Code envoyé par courriel"),
                    Err(e) => app.toast(&e.to_string()),
                }
                state.code_row.grab_focus();
            },
        );
    }

    fn set_key_state(&self, busy: bool, message: &str) {
        self.key_spinner.set_spinning(busy);
        self.key_spinner.set_visible(busy);
        self.key_label.set_label(message);
        self.key_button.set_sensitive(!busy);
    }

    fn cancel_security_key(&self) {
        if let Some(cancel) = self.key_cancel.borrow_mut().take() {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Obtient un défi du serveur, attend une clé FIDO2 puis termine la connexion.
    fn start_security_key(self: &Rc<Self>) {
        self.cancel_security_key();
        let cancel = Arc::new(AtomicBool::new(false));
        *self.key_cancel.borrow_mut() = Some(cancel.clone());
        self.set_key_state(true, "Préparation du défi…");

        let origin = match self.session.web_origin() {
            Ok(origin) => origin,
            Err(e) => return self.set_key_state(false, &e.to_string()),
        };
        let (session, password) = (self.session.clone(), self.password.clone());
        let state = self.clone();
        crate::spawn(
            async move { session.webauthn_challenge(&password).await },
            move |result| {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let options = match result
                    .map_err(|e| e.to_string())
                    .and_then(|o| security_key::parse_options(o).map_err(|e| e.to_string()))
                {
                    Ok(options) => options,
                    Err(e) => return state.set_key_state(false, &e),
                };
                state.set_key_state(true, "Recherche d'une clé de sécurité…");
                state.run_security_key(origin, options, cancel);
            },
        );
    }

    fn run_security_key(
        self: &Rc<Self>,
        origin: url::Url,
        options: webauthn_authenticator_rs::prelude::RequestChallengeResponse,
        cancel: Arc<AtomicBool>,
    ) {
        let (events_tx, events_rx) = async_channel::unbounded();
        let (result_tx, result_rx) = async_channel::bounded(1);
        let worker_cancel = cancel.clone();
        std::thread::spawn(move || {
            let result = security_key::authenticate(origin, options, events_tx, worker_cancel);
            let _ = result_tx.send_blocking(result);
        });

        // Affiche la progression et répond aux demandes de NIP.
        let state = self.clone();
        let events_cancel = cancel.clone();
        gtk::glib::spawn_future_local(async move {
            while let Ok(event) = events_rx.recv().await {
                if events_cancel.load(Ordering::Relaxed) {
                    if let KeyEvent::Pin(reply) = event {
                        let _ = reply.send(None);
                    }
                    continue;
                }
                match event {
                    KeyEvent::Waiting => state.set_key_state(
                        true,
                        "Branchez la clé (USB) ou posez-la sur le lecteur NFC…",
                    ),
                    KeyEvent::Touch => state.set_key_state(true, "Touchez votre clé de sécurité."),
                    KeyEvent::Processing => state.set_key_state(true, "Vérification…"),
                    KeyEvent::Pin(reply) => pin_dialog(&state.app, reply),
                }
            }
        });

        let state = self.clone();
        gtk::glib::spawn_future_local(async move {
            let Ok(result) = result_rx.recv().await else {
                return;
            };
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            match result {
                Ok(token) => {
                    state.set_key_state(true, "Connexion…");
                    let state_ = state.clone();
                    login(
                        &state.app,
                        state.session.clone(),
                        state.password.clone(),
                        Some((TwoFactorMethod::WebAuthn, token)),
                        move |ok| {
                            if !ok {
                                state_.set_key_state(
                                    false,
                                    "Échec : touchez le bouton pour réessayer.",
                                );
                            }
                        },
                    );
                }
                Err(e) => state.set_key_state(false, &e.to_string()),
            }
        });
    }
}

/// Demande le NIP de la clé FIDO2; `None` annule l'opération.
fn pin_dialog(app: &App, reply: std::sync::mpsc::Sender<Option<String>>) {
    let pin_row = adw::PasswordEntryRow::builder()
        .title("NIP de la clé")
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&pin_row);

    let dialog = adw::AlertDialog::builder()
        .heading("NIP de la clé de sécurité")
        .body("Cette clé exige son NIP (et non le NIP de Coffre).")
        .extra_child(&list)
        .default_response("ok")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", "Annuler");
    dialog.add_response("ok", "Valider");
    dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    dialog.connect_response(None, move |_, response| {
        let pin = (response == "ok").then(|| pin_row.text().to_string());
        let _ = reply.send(pin.filter(|p| !p.is_empty()));
    });
    dialog.present(Some(&app.window));
}
