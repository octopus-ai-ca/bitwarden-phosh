//! Détail d'un élément déchiffré.

use adw::prelude::*;
use bitwarden_vault::{CipherType, CipherView, FieldType};

use crate::backend::{ItemDraft, ItemKind};
use gtk::glib;

use super::{App, icon_button, page};

pub fn detail_page(app: &App, view: CipherView) -> adw::NavigationPage {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);

    if app.config().auto_copy_totp
        && let Some(code) = view
            .login
            .as_ref()
            .and_then(|l| l.totp.as_deref())
            .and_then(crate::backend::totp)
            .map(|(code, _)| code)
    {
        app.copy("Code TOTP", &code);
    }

    if let Some(login) = &view.login {
        let group = adw::PreferencesGroup::builder()
            .title("Identifiants")
            .build();
        if let Some(username) = login.username.as_deref().filter(|u| !u.is_empty()) {
            group.add(&copy_row(app, "Nom d'utilisateur", username, false));
        }
        if let Some(password) = login.password.as_deref().filter(|p| !p.is_empty())
            && view.view_password
        {
            group.add(&copy_row(app, "Mot de passe", password, true));
        }
        if let Some(key) = login.totp.as_deref().filter(|k| !k.is_empty()) {
            group.add(&totp_row(app, key));
        }
        content.append(&group);

        let uris: Vec<_> = login
            .uris
            .iter()
            .flatten()
            .filter_map(|u| u.uri.as_deref())
            .filter(|u| !u.is_empty())
            .collect();
        if !uris.is_empty() {
            let group = adw::PreferencesGroup::builder().title("Sites web").build();
            for uri in uris {
                group.add(&uri_row(app, uri));
            }
            content.append(&group);
        }
    }

    if let Some(card) = &view.card {
        let group = adw::PreferencesGroup::builder().title("Carte").build();
        let expiry = match (card.exp_month.as_deref(), card.exp_year.as_deref()) {
            (Some(m), Some(y)) => Some(format!("{m:0>2}/{y}")),
            _ => None,
        };
        for (label, value, secret) in [
            ("Titulaire", card.cardholder_name.clone(), false),
            ("Numéro", card.number.clone(), true),
            ("Expiration", expiry, false),
            ("Code de sécurité", card.code.clone(), true),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                group.add(&copy_row(app, label, &value, secret));
            }
        }
        content.append(&group);
    }

    let fields: Vec<_> = view
        .fields
        .iter()
        .flatten()
        .filter(|f| f.value.as_deref().is_some_and(|v| !v.is_empty()))
        .collect();
    if !fields.is_empty() {
        let group = adw::PreferencesGroup::builder()
            .title("Champs personnalisés")
            .build();
        for field in fields {
            let name = field.name.as_deref().unwrap_or("Champ");
            let value = field.value.as_deref().unwrap_or_default();
            let secret = matches!(field.r#type, FieldType::Hidden);
            group.add(&copy_row(app, name, value, secret));
        }
        content.append(&group);
    }

    if let Some(notes) = view.notes.as_deref().filter(|n| !n.is_empty()) {
        let group = adw::PreferencesGroup::builder().title("Notes").build();
        let label = gtk::Label::builder()
            .label(notes)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .selectable(true)
            .xalign(0.0)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        let frame = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        frame.add_css_class("boxed-list");
        frame.append(&label);
        group.add(&frame);
        content.append(&group);
    }

    let header = adw::HeaderBar::new();
    let editable = view.edit
        && matches!(view.r#type, CipherType::Login | CipherType::SecureNote)
        && view.id.is_some();
    if editable {
        let edit = icon_button("document-edit-symbolic", "Modifier");
        let kind = if view.r#type == CipherType::Login {
            ItemKind::Login
        } else {
            ItemKind::SecureNote
        };
        let (app, id, draft) = (
            app.clone(),
            view.id.map(|id| id.to_string()),
            ItemDraft::from_view(&view),
        );
        edit.connect_clicked(move |_| app.show_editor(id.clone(), kind, draft.clone()));
        header.pack_end(&edit);
    }
    page(&view.name, "detail", &header, &content)
}

/// Rangée avec bouton de copie; si `secret`, la valeur est masquée et un bouton permet de l'afficher.
fn copy_row(app: &App, title: &str, value: &str, secret: bool) -> adw::ActionRow {
    const MASK: &str = "••••••••";
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(if secret { MASK } else { value })
        .use_markup(false)
        .subtitle_selectable(!secret)
        .build();
    row.add_css_class("property");

    if secret {
        let reveal = gtk::ToggleButton::builder()
            .icon_name("view-reveal-symbolic")
            .tooltip_text("Afficher")
            .valign(gtk::Align::Center)
            .build();
        reveal.add_css_class("flat");
        let (row_, value_) = (row.clone(), value.to_owned());
        reveal.connect_toggled(move |button| {
            let shown = button.is_active();
            row_.set_subtitle(if shown { &value_ } else { MASK });
            row_.set_subtitle_selectable(shown);
            button.set_icon_name(if shown {
                "view-conceal-symbolic"
            } else {
                "view-reveal-symbolic"
            });
        });
        row.add_suffix(&reveal);
    }

    let copy = icon_button("edit-copy-symbolic", "Copier");
    let (app, title, value) = (app.clone(), title.to_owned(), value.to_owned());
    copy.connect_clicked(move |_| app.copy(&title, &value));
    row.add_suffix(&copy);
    row
}

/// Code TOTP rafraîchi chaque seconde tant que la rangée est affichée.
fn totp_row(app: &App, key: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title("Code à usage unique (TOTP)")
        .use_markup(false)
        .build();
    row.add_css_class("property");
    let remaining = gtk::Label::new(None);
    remaining.add_css_class("dim-label");
    remaining.add_css_class("numeric");
    row.add_suffix(&remaining);

    let update = {
        let (row, remaining, key) = (row.clone(), remaining.clone(), key.to_owned());
        move || match crate::backend::totp(&key) {
            Some((code, secs)) => {
                let (a, b) = code.split_at(code.len() / 2);
                row.set_subtitle(&format!("{a} {b}"));
                remaining.set_label(&format!("{secs} s"));
            }
            None => row.set_subtitle("Clé TOTP invalide"),
        }
    };
    update();
    let row_weak = row.downgrade();
    glib::timeout_add_seconds_local(1, move || {
        if row_weak.upgrade().is_none() {
            return glib::ControlFlow::Break;
        }
        update();
        glib::ControlFlow::Continue
    });

    let copy = icon_button("edit-copy-symbolic", "Copier");
    let (app, key) = (app.clone(), key.to_owned());
    copy.connect_clicked(move |_| {
        if let Some((code, _)) = crate::backend::totp(&key) {
            app.copy("Code", &code);
        }
    });
    row.add_suffix(&copy);
    row
}

fn uri_row(app: &App, uri: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(uri)
        .use_markup(false)
        .title_lines(1)
        .build();
    if uri.starts_with("https://") || uri.starts_with("http://") {
        let open = icon_button("coffre-external-link-symbolic", "Ouvrir");
        let (window, uri_) = (app.window.clone(), uri.to_owned());
        open.connect_clicked(move |_| {
            gtk::UriLauncher::new(&uri_).launch(Some(&window), gtk::gio::Cancellable::NONE, |_| {});
        });
        row.add_suffix(&open);
    }
    let copy = icon_button("edit-copy-symbolic", "Copier");
    let (app, uri) = (app.clone(), uri.to_owned());
    copy.connect_clicked(move |_| app.copy("Adresse", &uri));
    row.add_suffix(&copy);
    row
}
