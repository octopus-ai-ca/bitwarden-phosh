//! Pages de connexion, de connexion en deux étapes et de déverrouillage.

use adw::prelude::*;

use super::{App, page, pill_button, set_busy};
use crate::backend::{LoginOutcome, Server, Session, TwoFactorMethod, TwoFactorOptions};
use crate::config::Config;

const SERVERS: [&str; 3] = [
    "bitwarden.com",
    "bitwarden.eu",
    "Auto-hébergé (Vaultwarden, etc.)",
];

pub fn login_page(app: &App, config: &Config) -> adw::NavigationPage {
    let server_row = adw::ComboRow::builder()
        .title("Serveur")
        .model(&gtk::StringList::new(&SERVERS))
        .build();
    let url_row = adw::EntryRow::builder()
        .title("Adresse du serveur")
        .input_purpose(gtk::InputPurpose::Url)
        .build();
    let email_row = adw::EntryRow::builder()
        .title("Courriel")
        .input_purpose(gtk::InputPurpose::Email)
        .text(config.email.as_str())
        .build();
    let password_row = adw::PasswordEntryRow::builder()
        .title("Mot de passe maître")
        .build();

    match &config.server {
        Server::BitwardenUs => server_row.set_selected(0),
        Server::BitwardenEu => server_row.set_selected(1),
        Server::SelfHosted(url) => {
            server_row.set_selected(2);
            url_row.set_text(url);
        }
    }
    url_row.set_visible(server_row.selected() == 2);
    let url = url_row.clone();
    server_row.connect_selected_notify(move |row| url.set_visible(row.selected() == 2));

    let server_group = adw::PreferencesGroup::new();
    server_group.add(&server_row);
    server_group.add(&url_row);

    let account_group = adw::PreferencesGroup::builder().title("Compte").build();
    account_group.add(&email_row);
    account_group.add(&password_row);

    let button = pill_button("Se connecter");

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    let status = adw::StatusPage::builder()
        .icon_name("dialog-password-symbolic")
        .title("Coffre")
        .description("Connectez-vous à votre compte Bitwarden")
        .build();
    status.add_css_class("compact");
    content.append(&status);
    content.append(&server_group);
    content.append(&account_group);
    content.append(&button);

    let app_ = app.clone();
    let (email, password) = (email_row.clone(), password_row.clone());
    button.connect_clicked(move |button| {
        let server = match server_row.selected() {
            0 => Server::BitwardenUs,
            1 => Server::BitwardenEu,
            _ => Server::SelfHosted(url_row.text().trim().to_owned()),
        };
        let email = email.text().trim().to_owned();
        let password = password.text().to_string();
        if email.is_empty() || password.is_empty() {
            app_.toast("Entrez votre courriel et votre mot de passe maître.");
            return;
        }
        let session = match Session::new(&server, &app_.device_id(), &email) {
            Ok(session) => session,
            Err(e) => return app_.toast(&e.to_string()),
        };
        app_.remember_account(server, email);
        set_busy(button, true, "Se connecter", "Connexion…");
        login(
            &app_,
            session,
            password,
            None,
            button.clone(),
            "Se connecter",
        );
    });
    let button_ = button.clone();
    password_row.connect_entry_activated(move |_| button_.emit_clicked());

    let header = adw::HeaderBar::new();
    header.pack_end(&about_menu());
    let page = page("Connexion", "login", &header, &content);
    let focus = if email_row.text().is_empty() {
        email_row.upcast::<gtk::Widget>()
    } else {
        password_row.upcast()
    };
    page.connect_shown(move |_| {
        focus.grab_focus();
    });
    page
}

/// Envoie la requête de connexion et oriente vers la 2FA, le coffre ou une erreur.
fn login(
    app: &App,
    session: Session,
    password: String,
    two_factor: Option<(TwoFactorMethod, String)>,
    button: gtk::Button,
    idle_label: &'static str,
) {
    let app = app.clone();
    let session_ = session.clone();
    let password_ = password.clone();
    crate::spawn(
        async move { session_.login(password_, two_factor).await },
        move |result| match result {
            Ok(LoginOutcome::Authenticated) => {
                let label = button.clone();
                app.finish_login(session, password, move |_| {
                    set_busy(&label, false, idle_label, "")
                });
            }
            Ok(LoginOutcome::TwoFactorRequired(options)) => {
                set_busy(&button, false, idle_label, "");
                app.show_two_factor(session, password, options);
            }
            Err(e) => {
                set_busy(&button, false, idle_label, "");
                app.toast(&e.to_string());
            }
        },
    );
}

pub fn two_factor_page(
    app: &App,
    session: Session,
    password: String,
    options: TwoFactorOptions,
) -> adw::NavigationPage {
    // L'application d'authentification a priorité si les deux méthodes sont offertes.
    let method = if options.authenticator {
        TwoFactorMethod::Authenticator
    } else {
        TwoFactorMethod::Email
    };
    let method = std::rc::Rc::new(std::cell::Cell::new(method));

    let status = adw::StatusPage::builder()
        .icon_name("security-high-symbolic")
        .title("Connexion en deux étapes")
        .build();
    status.add_css_class("compact");

    let code_row = adw::EntryRow::builder()
        .title("Code de vérification")
        .input_purpose(gtk::InputPurpose::Digits)
        .build();
    let group = adw::PreferencesGroup::new();
    group.add(&code_row);

    let button = pill_button("Valider");
    let email_button = gtk::Button::builder()
        .label("Recevoir un code par courriel")
        .halign(gtk::Align::Center)
        .visible(options.email)
        .build();
    email_button.add_css_class("flat");

    let describe = {
        let status = status.clone();
        move |m: TwoFactorMethod| {
            status.set_description(Some(match m {
                TwoFactorMethod::Authenticator => {
                    "Entrez le code à 6 chiffres de votre application d'authentification."
                }
                TwoFactorMethod::Email => "Entrez le code reçu par courriel.",
            }));
        }
    };
    describe(method.get());

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&status);
    content.append(&group);
    content.append(&button);
    content.append(&email_button);

    let send_email = {
        let (app, session, password, method) = (
            app.clone(),
            session.clone(),
            password.clone(),
            method.clone(),
        );
        move |button: &gtk::Button| {
            method.set(TwoFactorMethod::Email);
            describe(TwoFactorMethod::Email);
            set_busy(button, true, "Renvoyer le code par courriel", "Envoi…");
            let (app, session, password, button) = (
                app.clone(),
                session.clone(),
                password.clone(),
                button.clone(),
            );
            crate::spawn(
                async move { session.send_two_factor_email(password).await },
                move |result| {
                    set_busy(&button, false, "Renvoyer le code par courriel", "");
                    match result {
                        Ok(()) => app.toast("Code envoyé par courriel"),
                        Err(e) => app.toast(&e.to_string()),
                    }
                },
            );
        }
    };
    email_button.connect_clicked(send_email.clone());
    if !options.authenticator {
        send_email(&email_button);
    }

    let app_ = app.clone();
    let code = code_row.clone();
    button.connect_clicked(move |button| {
        let token = code.text().trim().to_owned();
        if token.is_empty() {
            return;
        }
        set_busy(button, true, "Valider", "Vérification…");
        login(
            &app_,
            session.clone(),
            password.clone(),
            Some((method.get(), token)),
            button.clone(),
            "Valider",
        );
    });
    let button_ = button.clone();
    code_row.connect_entry_activated(move |_| button_.emit_clicked());

    let page = page(
        "Vérification",
        "two-factor",
        &adw::HeaderBar::new(),
        &content,
    );
    page.connect_shown(move |_| {
        code_row.grab_focus();
    });
    page
}

pub fn lock_page(app: &App) -> adw::NavigationPage {
    let email = app
        .session()
        .map(|s| s.email().to_owned())
        .unwrap_or_default();
    let status = adw::StatusPage::builder()
        .icon_name("system-lock-screen-symbolic")
        .title("Coffre verrouillé")
        .description(glib_escape(&email))
        .build();
    status.add_css_class("compact");

    let password_row = adw::PasswordEntryRow::builder()
        .title("Mot de passe maître")
        .build();
    let group = adw::PreferencesGroup::new();
    group.add(&password_row);

    let button = pill_button("Déverrouiller");
    let logout = gtk::Button::builder()
        .label("Se déconnecter")
        .halign(gtk::Align::Center)
        .action_name("win.logout")
        .build();
    logout.add_css_class("flat");

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&status);
    content.append(&group);
    content.append(&button);
    content.append(&logout);

    let app_ = app.clone();
    let password = password_row.clone();
    button.connect_clicked(move |button| {
        let value = password.text().to_string();
        if value.is_empty() {
            return;
        }
        set_busy(button, true, "Déverrouiller", "Déverrouillage…");
        let (button, password) = (button.clone(), password.clone());
        app_.unlock(value, move |ok| {
            set_busy(&button, false, "Déverrouiller", "");
            if !ok {
                password.set_text("");
                password.grab_focus();
            }
        });
    });
    let button_ = button.clone();
    password_row.connect_entry_activated(move |_| button_.emit_clicked());

    let page = page("Verrouillé", "lock", &adw::HeaderBar::new(), &content);
    page.connect_shown(move |_| {
        password_row.grab_focus();
    });
    page
}

fn about_menu() -> gtk::MenuButton {
    let menu = gtk::gio::Menu::new();
    menu.append(Some("À propos de Coffre"), Some("win.about"));
    gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .tooltip_text("Menu principal")
        .menu_model(&menu)
        .build()
}

/// Les descriptions d'`AdwStatusPage` sont interprétées comme du balisage Pango.
fn glib_escape(text: &str) -> String {
    gtk::glib::markup_escape_text(text).to_string()
}
