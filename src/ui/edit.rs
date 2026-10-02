//! Création et modification d'un élément (identifiant ou note sécurisée).

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;

use super::{App, icon_button, page, set_busy};
use crate::backend::{FolderInfo, ItemDraft, ItemKind};

const KINDS: [&str; 2] = ["Identifiant", "Note sécurisée"];

pub fn edit_page(
    app: &App,
    id: Option<String>,
    kind: ItemKind,
    draft: ItemDraft,
    folders: Vec<FolderInfo>,
) -> adw::NavigationPage {
    let kind = Rc::new(Cell::new(kind));
    let creating = id.is_none();

    let kind_row = adw::ComboRow::builder()
        .title("Type")
        .model(&gtk::StringList::new(&KINDS))
        .selected(if kind.get() == ItemKind::Login { 0 } else { 1 })
        .visible(creating)
        .build();
    let name_row = adw::EntryRow::builder()
        .title("Nom")
        .text(draft.name.as_str())
        .build();
    let mut folder_labels = vec!["Aucun dossier"];
    folder_labels.extend(folders.iter().map(|f| f.name.as_str()));
    let folder_row = adw::ComboRow::builder()
        .title("Dossier")
        .model(&gtk::StringList::new(&folder_labels))
        .selected(
            draft
                .folder_id
                .as_ref()
                .and_then(|id| folders.iter().position(|f| &f.id == id))
                .map_or(0, |i| i as u32 + 1),
        )
        .build();
    let favorite_row = adw::SwitchRow::builder()
        .title("Favori")
        .active(draft.favorite)
        .build();
    let general = adw::PreferencesGroup::new();
    general.add(&kind_row);
    general.add(&name_row);
    general.add(&folder_row);
    general.add(&favorite_row);

    let username_row = adw::EntryRow::builder()
        .title("Nom d'utilisateur")
        .input_purpose(gtk::InputPurpose::Email)
        .text(draft.username.as_str())
        .build();
    let password_row = adw::PasswordEntryRow::builder()
        .title("Mot de passe")
        .text(draft.password.as_str())
        .build();
    let generate = icon_button("view-refresh-symbolic", "Générer un mot de passe");
    password_row.add_suffix(&generate);
    let uri_row = adw::EntryRow::builder()
        .title("Site web")
        .input_purpose(gtk::InputPurpose::Url)
        .text(draft.uri.as_str())
        .build();
    let totp_row = adw::EntryRow::builder()
        .title("Clé d'authentification (TOTP)")
        .text(draft.totp.as_str())
        .build();
    let login_group = adw::PreferencesGroup::builder()
        .title("Identifiants")
        .visible(kind.get() == ItemKind::Login)
        .build();
    login_group.add(&username_row);
    login_group.add(&password_row);
    login_group.add(&uri_row);
    login_group.add(&totp_row);

    let notes = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .height_request(120)
        .accepts_tab(false)
        .build();
    notes.buffer().set_text(&draft.notes);
    notes.add_css_class("card");
    let notes_group = adw::PreferencesGroup::builder().title("Notes").build();
    notes_group.add(&notes);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&general);
    content.append(&login_group);
    content.append(&notes_group);

    {
        let (kind, login_group) = (kind.clone(), login_group.clone());
        kind_row.connect_selected_notify(move |row| {
            let selected = if row.selected() == 0 {
                ItemKind::Login
            } else {
                ItemKind::SecureNote
            };
            kind.set(selected);
            login_group.set_visible(selected == ItemKind::Login);
        });
    }

    {
        let (app, row) = (app.clone(), password_row.clone());
        generate.connect_clicked(move |_| {
            let Some(session) = app.session() else {
                return;
            };
            match session.generate_password() {
                Ok(password) => row.set_text(&password),
                Err(e) => app.toast(&e.to_string()),
            }
        });
    }

    if let Some(id) = id.clone() {
        let trash = gtk::Button::builder()
            .label("Envoyer à la corbeille")
            .halign(gtk::Align::Center)
            .margin_top(12)
            .build();
        trash.add_css_class("pill");
        trash.add_css_class("destructive-action");
        let app = app.clone();
        trash.connect_clicked(move |_| app.confirm_trash(id.clone()));
        content.append(&trash);
    }

    let save = gtk::Button::builder().label("Enregistrer").build();
    save.add_css_class("suggested-action");
    {
        let app = app.clone();
        save.connect_clicked(move |button| {
            let buffer = notes.buffer();
            let draft = ItemDraft {
                name: name_row.text().to_string(),
                username: username_row.text().to_string(),
                password: password_row.text().to_string(),
                uri: uri_row.text().to_string(),
                totp: totp_row.text().to_string(),
                notes: buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .to_string(),
                folder_id: (folder_row.selected() as usize)
                    .checked_sub(1)
                    .and_then(|i| folders.get(i))
                    .map(|f| f.id.clone()),
                favorite: favorite_row.is_active(),
            };
            if draft.name.trim().is_empty() {
                app.toast("Le nom de l'élément est obligatoire.");
                name_row.grab_focus();
                return;
            }
            set_busy(button, true, "Enregistrer", "Envoi…");
            let button = button.clone();
            app.save_item(id.clone(), kind.get(), draft, move |ok| {
                if !ok {
                    set_busy(&button, false, "Enregistrer", "");
                }
            });
        });
    }

    let header = adw::HeaderBar::new();
    header.pack_end(&save);
    let title = if creating {
        "Nouvel élément"
    } else {
        "Modifier"
    };
    page(title, "edit", &header, &content)
}
