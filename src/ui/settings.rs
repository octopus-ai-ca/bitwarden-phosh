//! Onglet des paramètres et ses sous-pages : compte, sécurité, options du coffre
//! (dossiers, import, export, archive, corbeille), apparence, presse-papier, à propos.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::gio;

use super::{
    App, Reload, card_list, create_button, empty_state, fr_date, fr_datetime, icon_button,
    link_row, nav_row, page, pill_button, scrolled, set_busy, tab,
};
use crate::backend::{ExportKind, FolderInfo, ImportKind, Scope};
use crate::config::{CLIPBOARD_DELAYS, LOCK_TIMEOUTS, Theme, TimeoutAction};

/// Constructeur d'une sous-page.
type PageBuilder = fn(&App) -> adw::NavigationPage;

pub fn settings_tab(app: &App) -> adw::ToolbarView {
    let group = adw::PreferencesGroup::new();
    let rows: [(&str, &str, PageBuilder); 5] = [
        (
            "security-high-symbolic",
            "Sécurité du compte",
            security_page,
        ),
        ("folder-symbolic", "Options du coffre", vault_options_page),
        (
            "preferences-desktop-appearance-symbolic",
            "Apparence",
            appearance_page,
        ),
        ("edit-paste-symbolic", "Presse-papier", clipboard_page),
        ("help-about-symbolic", "À propos", about_page),
    ];
    for (icon, title, build) in rows {
        let row = nav_row(icon, title);
        let app = app.clone();
        row.connect_activated(move |_| app.push(&build(&app)));
        group.add(&row);
    }
    let account = nav_row("system-users-symbolic", "Compte");
    {
        let app = app.clone();
        account.connect_activated(move |_| show_account(&app));
    }
    let account_group = adw::PreferencesGroup::new();
    account_group.add(&account);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&account_group);
    content.append(&group);
    tab("Paramètres", &adw::HeaderBar::new(), &scrolled(&content))
}

/// Combo de choix parmi des valeurs `(valeur, libellé)`.
fn choice_row<T: Copy + PartialEq + 'static>(
    title: &str,
    choices: &'static [(T, &'static str)],
    current: T,
    on_change: impl Fn(T) + 'static,
) -> adw::ComboRow {
    let labels: Vec<&str> = choices.iter().map(|(_, l)| *l).collect();
    let row = adw::ComboRow::builder()
        .title(title)
        .model(&gtk::StringList::new(&labels))
        .selected(choices.iter().position(|(v, _)| *v == current).unwrap_or(0) as u32)
        .build();
    row.connect_selected_notify(move |row| {
        if let Some((value, _)) = choices.get(row.selected() as usize) {
            on_change(*value);
        }
    });
    row
}

// ----- Compte -----

/// Actions du compte : carte du compte, verrouiller, se déconnecter.
pub fn show_account(app: &App) {
    let Some(session) = app.session() else {
        return;
    };
    let email = session.email().to_owned();
    let avatar = adw::Avatar::builder()
        .size(48)
        .text(email.as_str())
        .show_initials(true)
        .build();
    let email_label = gtk::Label::builder()
        .label(email.as_str())
        .xalign(0.0)
        .ellipsize(gtk::pango::EllipsizeMode::Middle)
        .build();
    email_label.add_css_class("heading");
    let server = gtk::Label::builder()
        .label(session.server().label())
        .xalign(0.0)
        .build();
    server.add_css_class("dim-label");
    let status = gtk::Label::builder().label("Actif").xalign(0.0).build();
    status.add_css_class("success");
    status.add_css_class("caption");
    let labels = gtk::Box::new(gtk::Orientation::Vertical, 2);
    labels.append(&email_label);
    labels.append(&server);
    labels.append(&status);
    let card = gtk::Box::builder()
        .spacing(14)
        .margin_top(14)
        .margin_bottom(14)
        .margin_start(14)
        .margin_end(14)
        .build();
    card.append(&avatar);
    card.append(&labels);
    let card_frame = gtk::Box::new(gtk::Orientation::Vertical, 0);
    card_frame.add_css_class("card");
    card_frame.append(&card);

    let lock = nav_row("system-lock-screen-symbolic", "Verrouiller maintenant");
    lock.set_action_name(Some("win.lock"));
    let logout = nav_row("system-log-out-symbolic", "Se déconnecter");
    logout.set_action_name(Some("win.logout"));
    let actions = adw::PreferencesGroup::new();
    actions.add(&lock);
    actions.add(&logout);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&card_frame);
    content.append(&actions);
    app.push(&page(
        "Actions du compte",
        "account",
        &adw::HeaderBar::new(),
        &content,
    ));
}

// ----- Sécurité du compte -----

fn security_page(app: &App) -> adw::NavigationPage {
    let config = app.config();
    let has_pin = app.session().is_some_and(|s| s.has_pin());

    let pin = adw::SwitchRow::builder()
        .title("Déverrouiller avec un NIP")
        .subtitle("Gardé en mémoire seulement, jusqu'à la fermeture de l'application")
        .active(has_pin)
        .build();
    {
        let app = app.clone();
        pin.connect_active_notify(move |row| {
            let has_pin = app.session().is_some_and(|s| s.has_pin());
            if row.is_active() == has_pin {
                return;
            }
            if row.is_active() {
                let row = row.clone();
                super::login::set_pin_dialog(&app, move |ok| {
                    if !ok {
                        row.set_active(false);
                    }
                });
            } else if let Some(session) = app.session() {
                session.clear_pin();
                app.toast("NIP retiré");
            }
        });
    }
    let unlock = adw::PreferencesGroup::builder()
        .title("Options de déverrouillage")
        .build();
    unlock.add(&pin);

    let timeout = {
        let app = app.clone();
        choice_row(
            "Délai d'expiration",
            &LOCK_TIMEOUTS,
            config.lock_minutes,
            move |v| app.update_config(|c| c.lock_minutes = v),
        )
    };
    const ACTIONS: [(TimeoutAction, &str); 2] = [
        (TimeoutAction::Lock, "Verrouiller"),
        (TimeoutAction::Logout, "Se déconnecter"),
    ];
    let action = {
        let app = app.clone();
        choice_row(
            "Action à l'expiration",
            &ACTIONS,
            config.timeout_action,
            move |v| app.update_config(|c| c.timeout_action = v),
        )
    };
    let session_group = adw::PreferencesGroup::builder()
        .title("Expiration de la session")
        .description("Après cette période d'inactivité")
        .build();
    session_group.add(&timeout);
    session_group.add(&action);

    let devices = nav_row("phone-symbolic", "Appareils");
    {
        let app = app.clone();
        devices.connect_activated(move |_| app.push(&devices_page(&app)));
    }
    let fingerprint = nav_row("auth-fingerprint-symbolic", "Phrase d'empreinte du compte");
    {
        let app = app.clone();
        fingerprint.connect_activated(move |_| show_fingerprint(&app));
    }
    let two_factor = link_row("channel-secure-symbolic", "Connexion en deux étapes");
    {
        let app = app.clone();
        two_factor.connect_activated(move |_| open_web(&app, "settings/security/two-factor"));
    }
    let password = link_row(
        "dialog-password-symbolic",
        "Changer le mot de passe principal",
    );
    {
        let app = app.clone();
        password.connect_activated(move |_| open_web(&app, "settings/security/password"));
    }
    let other = adw::PreferencesGroup::builder().title("Autre").build();
    other.add(&devices);
    other.add(&fingerprint);
    other.add(&two_factor);
    other.add(&password);

    let lock = pill_button("Verrouiller maintenant");
    lock.set_action_name(Some("win.lock"));

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&unlock);
    content.append(&session_group);
    content.append(&other);
    content.append(&lock);
    page(
        "Sécurité du compte",
        "security",
        &adw::HeaderBar::new(),
        &content,
    )
}

fn open_web(app: &App, route: &str) {
    match app.session().and_then(|s| s.web_vault_page(route)) {
        Some(url) => app.open_uri(&url),
        None => app.toast("Adresse du coffre web inconnue."),
    }
}

fn show_fingerprint(app: &App) {
    let Some(session) = app.session() else {
        return;
    };
    match session.fingerprint_phrase() {
        Ok(phrase) => {
            let label = gtk::Label::builder()
                .label(phrase.as_str())
                .wrap(true)
                .selectable(true)
                .justify(gtk::Justification::Center)
                .build();
            label.add_css_class("monospace");
            label.add_css_class("title-4");
            let dialog = adw::AlertDialog::builder()
                .heading("Phrase d'empreinte")
                .body("Comparez-la avec celle affichée par le coffre web pour vérifier l'identité du compte.")
                .extra_child(&label)
                .build();
            dialog.add_response("close", "Fermer");
            dialog.present(Some(&app.window));
        }
        Err(e) => app.toast(&e.to_string()),
    }
}

fn devices_page(app: &App) -> adw::NavigationPage {
    let list = card_list();
    let spinner = gtk::Spinner::builder()
        .spinning(true)
        .height_request(48)
        .build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let intro = gtk::Label::builder()
        .label("Appareils connectés à votre compte. Les sessions se gèrent depuis le coffre web.")
        .wrap(true)
        .xalign(0.0)
        .build();
    intro.add_css_class("dim-label");
    content.append(&intro);
    content.append(&spinner);
    content.append(&list);

    app.with_session(
        |s| async move { s.devices().await },
        move |app, result| {
            spinner.set_visible(false);
            match result {
                Ok(devices) => {
                    for device in devices {
                        let subtitle = match device.first_login {
                            Some(date) => format!(
                                "{}\nPremière connexion : {}",
                                device.kind,
                                fr_datetime(date)
                            ),
                            None => device.kind.clone(),
                        };
                        let row = adw::ActionRow::builder()
                            .title(device.name.as_str())
                            .subtitle(subtitle)
                            .subtitle_lines(2)
                            .use_markup(false)
                            .build();
                        let icon = if device.kind.starts_with("Application web")
                            || device.kind.starts_with("Extension")
                        {
                            "web-browser-symbolic"
                        } else if device.kind.starts_with("Application") {
                            "phone-symbolic"
                        } else {
                            "computer-symbolic"
                        };
                        row.add_prefix(&gtk::Image::from_icon_name(icon));
                        if device.current {
                            let badge = gtk::Label::builder()
                                .label("Session en cours")
                                .valign(gtk::Align::Center)
                                .build();
                            badge.add_css_class("pill-badge");
                            row.add_suffix(&badge);
                        }
                        list.append(&row);
                    }
                }
                Err(e) => app.toast(&e.to_string()),
            }
        },
    );
    page("Appareils", "devices", &adw::HeaderBar::new(), &content)
}

// ----- Options du coffre -----

fn vault_options_page(app: &App) -> adw::NavigationPage {
    let group = adw::PreferencesGroup::new();
    let rows: [(&str, &str, PageBuilder); 5] = [
        ("folder-symbolic", "Dossiers", folders_page),
        (
            "document-open-symbolic",
            "Importer des éléments",
            import_page,
        ),
        ("document-save-symbolic", "Exporter le coffre", export_page),
        ("package-x-generic-symbolic", "Archive", archive_page),
        ("user-trash-symbolic", "Corbeille", trash_page),
    ];
    for (icon, title, build) in rows {
        let row = nav_row(icon, title);
        let app = app.clone();
        row.connect_activated(move |_| app.push(&build(&app)));
        group.add(&row);
    }

    let sync = pill_button("Synchroniser maintenant");
    let last = gtk::Label::builder()
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    last.add_css_class("dim-label");
    last.add_css_class("caption");
    let show_last = {
        let last = last.clone();
        move |app: &App| {
            let text = match app.session().and_then(|s| s.last_sync()) {
                Some(date) => format!("Dernière synchronisation : {}", fr_datetime(date)),
                None => "Jamais synchronisé".to_owned(),
            };
            last.set_label(&text);
        }
    };
    show_last(app);
    {
        let app = app.clone();
        sync.connect_clicked(move |button| {
            set_busy(button, true, "Synchroniser maintenant", "Synchronisation…");
            let (button, show_last, app_) = (button.clone(), show_last.clone(), app.clone());
            app.sync(move |_| {
                set_busy(&button, false, "Synchroniser maintenant", "");
                show_last(&app_);
            });
        });
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&group);
    content.append(&sync);
    content.append(&last);
    page(
        "Options du coffre",
        "vault-options",
        &adw::HeaderBar::new(),
        &content,
    )
}

fn archive_page(app: &App) -> adw::NavigationPage {
    super::vault::item_list_page(
        app,
        Scope::Archive,
        "Archive",
        None,
        (
            "package-x-generic-symbolic",
            "Aucun élément dans l'archive",
            "Les éléments archivés apparaissent ici et sont exclus de la liste et de la \
             recherche du coffre.",
        ),
    )
}

fn trash_page(app: &App) -> adw::NavigationPage {
    super::vault::item_list_page(
        app,
        Scope::Trash,
        "Corbeille",
        Some(
            "Les éléments dans la corbeille depuis plus de 30 jours sont supprimés automatiquement.",
        ),
        (
            "user-trash-symbolic",
            "Corbeille vide",
            "Les éléments supprimés apparaissent ici et peuvent être restaurés.",
        ),
    )
}

fn folders_page(app: &App) -> adw::NavigationPage {
    let list = card_list();
    let empty = empty_state(
        "folder-symbolic",
        "Aucun dossier",
        "Les dossiers permettent de classer les éléments du coffre.",
    );
    empty.set_visible(false);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&list);
    content.append(&empty);

    let reload: Rc<RefCell<Option<Reload>>> = Rc::default();
    let reload_fn: Reload = {
        let (app, list, empty, reload) = (
            app.clone(),
            list.downgrade(),
            empty.downgrade(),
            reload.clone(),
        );
        Rc::new(move || {
            let (Some(list), Some(empty)) = (list.upgrade(), empty.upgrade()) else {
                return;
            };
            let reload = reload.clone();
            app.with_session(
                |s| async move { s.folders().await },
                move |app, result| {
                    list.remove_all();
                    let folders = match result {
                        Ok(folders) => folders,
                        Err(e) => return app.toast(&e.to_string()),
                    };
                    empty.set_visible(folders.is_empty());
                    list.set_visible(!folders.is_empty());
                    for folder in folders {
                        let row = adw::ActionRow::builder()
                            .title(folder.name.as_str())
                            .use_markup(false)
                            .build();
                        row.add_prefix(&gtk::Image::from_icon_name("folder-symbolic"));
                        let edit = icon_button("document-edit-symbolic", "Modifier le dossier");
                        let (app, reload) = (app.clone(), reload.clone());
                        edit.connect_clicked(move |_| {
                            folder_dialog(&app, Some(folder.clone()), reload.borrow().clone())
                        });
                        row.add_suffix(&edit);
                        list.append(&row);
                    }
                },
            );
        })
    };
    *reload.borrow_mut() = Some(reload_fn.clone());
    reload_fn();

    let header = adw::HeaderBar::new();
    let create = create_button("Créer");
    {
        let app = app.clone();
        create.connect_clicked(move |_| folder_dialog(&app, None, Some(reload_fn.clone())));
    }
    header.pack_end(&create);
    page("Dossiers", "folders", &header, &content)
}

/// Dialogue de création (`folder` absent) ou de modification d'un dossier.
fn folder_dialog(app: &App, folder: Option<FolderInfo>, reload: Option<Reload>) {
    let name = adw::EntryRow::builder()
        .title("Nom")
        .text(folder.as_ref().map(|f| f.name.as_str()).unwrap_or_default())
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&name);
    let dialog = adw::AlertDialog::builder()
        .heading(if folder.is_some() {
            "Modifier le dossier"
        } else {
            "Nouveau dossier"
        })
        .extra_child(&list)
        .default_response("save")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", "Annuler");
    if folder.is_some() {
        dialog.add_response("delete", "Supprimer");
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    }
    dialog.add_response("save", "Enregistrer");
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let app_ = app.clone();
    dialog.connect_response(None, move |_, response| {
        let app = &app_;
        let id = folder.as_ref().map(|f| f.id.clone());
        let text = name.text().trim().to_owned();
        let reload = reload.clone();
        let done = move |app: &App, r: Result<(), crate::backend::Error>, message: &str| match r {
            Ok(()) => {
                app.toast(message);
                if let Some(reload) = &reload {
                    reload();
                }
            }
            Err(e) => app.toast(&e.to_string()),
        };
        match (response, id) {
            ("save", _) if text.is_empty() => app.toast("Le nom du dossier est obligatoire."),
            ("save", None) => app.mutate(
                move |mut s| async move {
                    s.create_folder(&text).await?;
                    Ok((s, ()))
                },
                move |app, r| done(app, r, "Dossier créé"),
            ),
            ("save", Some(id)) => app.mutate(
                move |mut s| async move {
                    s.rename_folder(&id, &text).await?;
                    Ok((s, ()))
                },
                move |app, r| done(app, r, "Dossier renommé"),
            ),
            ("delete", Some(id)) => app.mutate(
                move |mut s| async move {
                    s.delete_folder(&id).await?;
                    Ok((s, ()))
                },
                move |app, r| done(app, r, "Dossier supprimé ; ses éléments sont conservés"),
            ),
            _ => {}
        }
    });
    dialog.present(Some(&app.window));
}

fn import_page(app: &App) -> adw::NavigationPage {
    let destination = adw::ActionRow::builder()
        .title("Destination")
        .subtitle("Mon coffre")
        .build();
    let folder_ids: Rc<RefCell<Vec<String>>> = Rc::default();
    let folder = adw::ComboRow::builder()
        .title("Dossier")
        .model(&gtk::StringList::new(&["Aucun dossier"]))
        .build();
    const FORMATS: [(ImportKind, &str); 2] = [
        (ImportKind::BitwardenJson, "Bitwarden (json)"),
        (ImportKind::Keepass, "KeePass 2 (kdbx)"),
    ];
    let format = adw::ComboRow::builder()
        .title("Format du fichier")
        .model(&gtk::StringList::new(&FORMATS.map(|(_, l)| l)))
        .build();
    let target = adw::PreferencesGroup::builder()
        .title("Destination")
        .build();
    target.add(&destination);
    target.add(&folder);
    target.add(&format);

    let data: Rc<RefCell<Option<Vec<u8>>>> = Rc::default();
    let file = adw::ActionRow::builder()
        .title("Fichier")
        .subtitle("Aucun fichier choisi")
        .activatable(true)
        .build();
    file.add_suffix(&gtk::Image::from_icon_name("document-open-symbolic"));
    let file_password = adw::PasswordEntryRow::builder()
        .title("Mot de passe du fichier")
        .visible(false)
        .build();
    let source = adw::PreferencesGroup::builder().title("Données").build();
    source.add(&file);
    source.add(&file_password);

    let paste = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::Char)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .height_request(100)
        .monospace(true)
        .build();
    paste.add_css_class("card");
    let paste_group = adw::PreferencesGroup::builder()
        .title("Ou collez le contenu du fichier")
        .build();
    paste_group.add(&paste);

    {
        let (file_password, paste_group) = (file_password.clone(), paste_group.clone());
        format.connect_selected_notify(move |row| {
            let keepass = FORMATS[row.selected() as usize].0 == ImportKind::Keepass;
            file_password.set_visible(keepass);
            paste_group.set_visible(!keepass);
        });
    }
    {
        let (app, data) = (app.clone(), data.clone());
        file.connect_activated(move |row| {
            let dialog = gtk::FileDialog::builder()
                .title("Fichier à importer")
                .build();
            let (app_, data, row) = (app.clone(), data.clone(), row.clone());
            dialog.open(Some(&app.window), gio::Cancellable::NONE, move |result| {
                let Ok(file) = result else { return };
                match file.load_contents(gio::Cancellable::NONE) {
                    Ok((bytes, _)) => {
                        let name = file
                            .basename()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        row.set_subtitle(&name);
                        *data.borrow_mut() = Some(bytes.to_vec());
                    }
                    Err(e) => app_.toast(&format!("Lecture impossible : {e}")),
                }
            });
        });
    }

    // Dossiers de destination.
    {
        let (folder, folder_ids) = (folder.clone(), folder_ids.clone());
        app.with_session(
            |s| async move { s.folders().await },
            move |_, result| {
                let folders = result.unwrap_or_default();
                let mut labels = vec!["Aucun dossier"];
                labels.extend(folders.iter().map(|f| f.name.as_str()));
                folder.set_model(Some(&gtk::StringList::new(&labels)));
                *folder_ids.borrow_mut() = folders.into_iter().map(|f| f.id).collect();
            },
        );
    }

    let import = pill_button("Importer");
    {
        let app = app.clone();
        import.connect_clicked(move |button| {
            let kind = FORMATS[format.selected() as usize].0;
            let pasted = {
                let buffer = paste.buffer();
                buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .to_string()
            };
            let bytes = match data.borrow().clone() {
                Some(bytes) => bytes,
                None if kind == ImportKind::BitwardenJson && !pasted.trim().is_empty() => {
                    pasted.into_bytes()
                }
                None => return app.toast("Choisissez un fichier à importer."),
            };
            let password = Some(file_password.text().to_string()).filter(|p| !p.is_empty());
            let folder_id = (folder.selected() as usize)
                .checked_sub(1)
                .and_then(|i| folder_ids.borrow().get(i).cloned());
            set_busy(button, true, "Importer", "Importation…");
            let button = button.clone();
            app.mutate(
                move |mut s| async move {
                    let count = s.import(kind, bytes, password, folder_id).await?;
                    Ok((s, count))
                },
                move |app, r| {
                    set_busy(&button, false, "Importer", "");
                    match r {
                        Ok(count) => {
                            app.toast(&format!(
                                "{} élément(s) et {} dossier(s) importés",
                                count.items, count.folders
                            ));
                            app.back_home();
                        }
                        Err(e) => app.toast(&e.to_string()),
                    }
                },
            );
        });
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&target);
    content.append(&source);
    content.append(&paste_group);
    content.append(&import);
    page(
        "Importer des éléments",
        "import",
        &adw::HeaderBar::new(),
        &content,
    )
}

fn export_page(app: &App) -> adw::NavigationPage {
    const FORMATS: [(ExportKind, &str); 3] = [
        (ExportKind::Json, ".json"),
        (ExportKind::Csv, ".csv"),
        (
            ExportKind::EncryptedJson,
            ".json (protégé par mot de passe)",
        ),
    ];
    let format = adw::ComboRow::builder()
        .title("Format du fichier")
        .model(&gtk::StringList::new(&FORMATS.map(|(_, l)| l)))
        .build();
    let file_password = adw::PasswordEntryRow::builder()
        .title("Mot de passe du fichier")
        .visible(false)
        .build();
    let confirm = adw::PasswordEntryRow::builder()
        .title("Confirmer le mot de passe du fichier")
        .visible(false)
        .build();
    {
        let (file_password, confirm) = (file_password.clone(), confirm.clone());
        format.connect_selected_notify(move |row| {
            let encrypted = FORMATS[row.selected() as usize].0 == ExportKind::EncryptedJson;
            file_password.set_visible(encrypted);
            confirm.set_visible(encrypted);
        });
    }
    let group = adw::PreferencesGroup::builder()
        .title("Exporter depuis Mon coffre")
        .description(
            "Sauf en format protégé, l'export contient les données du coffre en clair : ne le \
             conservez pas et ne l'envoyez pas par des canaux non sécurisés.",
        )
        .build();
    group.add(&format);
    group.add(&file_password);
    group.add(&confirm);

    let export = pill_button("Exporter");
    {
        let app = app.clone();
        export.connect_clicked(move |_| {
            let kind = FORMATS[format.selected() as usize].0;
            let password = if kind == ExportKind::EncryptedJson {
                let password = file_password.text().to_string();
                if password.is_empty() {
                    return app.toast("Entrez un mot de passe pour le fichier.");
                }
                if password != confirm.text().as_str() {
                    return app.toast("Les mots de passe du fichier ne correspondent pas.");
                }
                Some(password)
            } else {
                None
            };
            confirm_export(&app, kind, password);
        });
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&group);
    content.append(&export);
    page(
        "Exporter le coffre",
        "export",
        &adw::HeaderBar::new(),
        &content,
    )
}

/// Confirme l'identité par le mot de passe maître, exporte, puis enregistre le fichier.
fn confirm_export(app: &App, kind: ExportKind, file_password: Option<String>) {
    let master = adw::PasswordEntryRow::builder()
        .title("Mot de passe maître")
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&master);
    let dialog = adw::AlertDialog::builder()
        .heading("Confirmer l'export")
        .body("Entrez votre mot de passe maître pour exporter le coffre.")
        .extra_child(&list)
        .default_response("export")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", "Annuler");
    dialog.add_response("export", "Exporter");
    dialog.set_response_appearance("export", adw::ResponseAppearance::Suggested);
    let app_ = app.clone();
    dialog.connect_response(Some("export"), move |_, _| {
        let password = master.text().to_string();
        let file_password = file_password.clone();
        app_.with_session(
            move |s| async move {
                s.verify_master_password(&password).await?;
                s.export(kind, file_password).await
            },
            move |app, result| match result {
                Ok(data) => save_export(app, kind, data),
                Err(e) => app.toast(&e.to_string()),
            },
        );
    });
    dialog.present(Some(&app.window));
}

fn save_export(app: &App, kind: ExportKind, data: String) {
    let name = format!(
        "coffre_export_{}.{}",
        chrono::Local::now().format("%Y%m%d%H%M%S"),
        kind.extension()
    );
    let dialog = gtk::FileDialog::builder()
        .title("Enregistrer l'export")
        .initial_name(name.as_str())
        .build();
    let app_ = app.clone();
    dialog.save(Some(&app.window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else {
            return app_.toast("Emplacement non pris en charge.");
        };
        match write_private(&path, data.as_bytes()) {
            Ok(()) => app_.toast("Coffre exporté"),
            Err(e) => app_.toast(&format!("Écriture impossible : {e}")),
        }
    });
}

/// Écrit un fichier lisible par son seul propriétaire (0600).
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

// ----- Apparence et presse-papier -----

fn appearance_page(app: &App) -> adw::NavigationPage {
    let config = app.config();
    const THEMES: [(Theme, &str); 3] = [
        (Theme::System, "Par défaut du système"),
        (Theme::Light, "Clair"),
        (Theme::Dark, "Sombre"),
    ];
    let theme = {
        let app = app.clone();
        choice_row("Thème", &THEMES, config.theme, move |v| {
            app.update_config(|c| c.theme = v);
            super::style::apply(&app.config());
        })
    };
    let compact = adw::SwitchRow::builder()
        .title("Mode compact")
        .active(config.compact)
        .build();
    {
        let app = app.clone();
        compact.connect_active_notify(move |row| {
            app.update_config(|c| c.compact = row.is_active());
            app.apply_density();
        });
    }
    let icons = adw::SwitchRow::builder()
        .title("Afficher les icônes des sites web")
        .subtitle("Téléchargées depuis le service d'icônes du serveur")
        .active(config.show_icons)
        .build();
    {
        let app = app.clone();
        icons.connect_active_notify(move |row| {
            app.update_config(|c| c.show_icons = row.is_active());
            app.refresh();
        });
    }
    let quick_copy = adw::SwitchRow::builder()
        .title("Afficher les actions de copie rapide")
        .subtitle("Bouton de copie dans la liste du coffre")
        .active(config.quick_copy)
        .build();
    {
        let app = app.clone();
        quick_copy.connect_active_notify(move |row| {
            app.update_config(|c| c.quick_copy = row.is_active());
            app.refresh();
        });
    }
    let group = adw::PreferencesGroup::new();
    group.add(&theme);
    group.add(&compact);
    group.add(&icons);
    group.add(&quick_copy);
    page("Apparence", "appearance", &adw::HeaderBar::new(), &group)
}

fn clipboard_page(app: &App) -> adw::NavigationPage {
    let config = app.config();
    let delay = {
        let app = app.clone();
        choice_row(
            "Effacer le presse-papier",
            &CLIPBOARD_DELAYS,
            config.clipboard_seconds,
            move |v| app.update_config(|c| c.clipboard_seconds = v),
        )
    };
    let totp = adw::SwitchRow::builder()
        .title("Copier automatiquement le code TOTP")
        .subtitle("À l'ouverture d'un identifiant qui en a un")
        .active(config.auto_copy_totp)
        .build();
    {
        let app = app.clone();
        totp.connect_active_notify(move |row| {
            app.update_config(|c| c.auto_copy_totp = row.is_active())
        });
    }
    let group = adw::PreferencesGroup::new();
    group.add(&delay);
    group.add(&totp);
    page("Presse-papier", "clipboard", &adw::HeaderBar::new(), &group)
}

// ----- À propos -----

fn info_row(title: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(value)
        .subtitle_selectable(true)
        .use_markup(false)
        .build();
    row.add_css_class("property");
    row
}

fn about_page(app: &App) -> adw::NavigationPage {
    let session = app.session();
    let server = session
        .as_ref()
        .map(|s| s.server().label())
        .unwrap_or_else(|| app.config().server.label());
    let pcscd = std::path::Path::new("/run/pcscd/pcscd.comm").exists();
    let nci = crate::nfc_nci::socket_path();
    let last_sync = session
        .as_ref()
        .and_then(|s| s.last_sync())
        .map(fr_date)
        .unwrap_or_else(|| "jamais".into());

    let diagnostics = adw::PreferencesGroup::builder()
        .title("Résolution de problèmes")
        .build();
    diagnostics.add(&info_row("Version", env!("CARGO_PKG_VERSION")));
    diagnostics.add(&info_row("Serveur", &server));
    diagnostics.add(&info_row("Dernière synchronisation", &last_sync));
    diagnostics.add(&info_row(
        "Lecteur NFC (pcscd)",
        if pcscd { "actif" } else { "inactif" },
    ));
    diagnostics.add(&info_row(
        "Puce NFC intégrée (démon NCI)",
        &if nci.exists() {
            format!("disponible ({})", nci.display())
        } else {
            format!("absente ({})", nci.display())
        },
    ));

    let about = nav_row("help-about-symbolic", "À propos de Coffre");
    about.set_action_name(Some("win.about"));
    let help = link_row("help-browser-symbolic", "Centre d'aide Bitwarden");
    {
        let app = app.clone();
        help.connect_activated(move |_| app.open_uri("https://bitwarden.com/fr-fr/help/"));
    }
    let web = link_row("web-browser-symbolic", "Application web");
    {
        let app = app.clone();
        web.connect_activated(
            move |_| match app.session().and_then(|s| s.web_origin().ok()) {
                Some(url) => app.open_uri(url.as_str()),
                None => app.toast("Adresse du coffre web inconnue."),
            },
        );
    }
    let links = adw::PreferencesGroup::new();
    links.add(&about);
    links.add(&help);
    links.add(&web);

    let logo = super::style::logo(96);
    logo.set_margin_top(12);
    let name = gtk::Label::new(Some("Coffre"));
    name.add_css_class("title-2");

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&logo);
    content.append(&name);
    content.append(&links);
    content.append(&diagnostics);
    page("À propos", "about", &adw::HeaderBar::new(), &content)
}
