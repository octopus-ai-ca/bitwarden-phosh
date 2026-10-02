//! Onglet du coffre : recherche, filtres (dossier, type), sections Favoris et
//! Tous les éléments, rangées en cartes avec icône du site et actions rapides.
//! Aussi utilisé pour l'archive et la corbeille (`item_list_page`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use adw::prelude::*;
use bitwarden_vault::{CipherListView, CipherListViewType};
use gtk::{gdk, gio, glib};

use super::{
    App, card_list, create_button, empty_state, icon_button, page, scrolled, section_header, style,
    tab,
};
use crate::backend::{FolderInfo, ItemDraft, ItemKind, Scope, host_of};

/// Types proposés dans le filtre (libellé, prédicat).
const TYPES: [&str; 6] = [
    "Tous les types",
    "Identifiant",
    "Carte",
    "Identité",
    "Note sécurisée",
    "Clé SSH",
];

fn type_index(kind: &CipherListViewType) -> u32 {
    match kind {
        CipherListViewType::Login(_) => 1,
        CipherListViewType::Card(_) | CipherListViewType::BankAccount(_) => 2,
        CipherListViewType::Identity
        | CipherListViewType::Passport
        | CipherListViewType::DriversLicense => 3,
        CipherListViewType::SecureNote => 4,
        CipherListViewType::SshKey => 5,
    }
}

/// Champ copiable signalé par le SDK (`CopyableCipherFields` n'est pas exporté :
/// on compare son nom).
fn has_field(item: &CipherListView, name: &str) -> bool {
    item.copyable_fields
        .iter()
        .any(|field| format!("{field:?}") == name)
}

thread_local! {
    /// Icônes des sites déjà téléchargées (`None` : le service n'en a pas).
    static ICONS: RefCell<HashMap<String, Option<gdk::Texture>>> = RefCell::default();
}

/// Rangée affichée avec ses critères de filtrage.
struct Entry {
    row: adw::ActionRow,
    favorite: bool,
    folder: Option<String>,
    kind: u32,
    key: String,
}

pub fn vault_tab(app: &App) -> adw::ToolbarView {
    let header = adw::HeaderBar::new();

    // « + Créer » : choix du type d'élément.
    let create = create_button("Créer");
    {
        let app = app.clone();
        create.connect_clicked(move |button| create_menu(&app, button));
    }
    header.pack_start(&create);

    let email = app
        .session()
        .map(|s| s.email().to_owned())
        .unwrap_or_default();
    let avatar = adw::Avatar::builder()
        .size(32)
        .text(email.as_str())
        .show_initials(true)
        .build();
    let account = gtk::Button::builder()
        .child(&avatar)
        .tooltip_text("Compte")
        .build();
    account.add_css_class("flat");
    account.add_css_class("circular");
    {
        let app = app.clone();
        account.connect_clicked(move |_| super::settings::show_account(&app));
    }
    header.pack_end(&account);

    let search = gtk::SearchEntry::builder()
        .placeholder_text("Rechercher")
        .hexpand(true)
        .build();
    let folder_filter = gtk::DropDown::from_strings(&["Tous les dossiers"]);
    folder_filter.set_hexpand(true);
    let type_filter = gtk::DropDown::from_strings(&TYPES);
    type_filter.set_hexpand(true);
    let filters = gtk::Box::builder().spacing(8).homogeneous(true).build();
    filters.append(&folder_filter);
    filters.append(&type_filter);

    let (fav_header, fav_count) = section_header("Favoris");
    let favorites = card_list();
    let fav_section = gtk::Box::new(gtk::Orientation::Vertical, 0);
    fav_section.append(&fav_header);
    fav_section.append(&favorites);

    let (all_header, all_count) = section_header("Tous les éléments");
    let all = card_list();
    let all_section = gtk::Box::new(gtk::Orientation::Vertical, 0);
    all_section.append(&all_header);
    all_section.append(&all);

    let no_match = empty_state(
        "system-search-symbolic",
        "Aucun résultat",
        "Essayez une autre recherche ou d'autres filtres.",
    );
    no_match.set_visible(false);

    let list_box = gtk::Box::new(gtk::Orientation::Vertical, 18);
    list_box.append(&search);
    list_box.append(&filters);
    list_box.append(&fav_section);
    list_box.append(&all_section);
    list_box.append(&no_match);

    // État vide : logo, explication et bouton de création.
    let empty = adw::StatusPage::builder()
        .title("Chargement…")
        .vexpand(true)
        .build();
    empty.set_paintable(style::logo_texture().as_ref());
    let empty_create = super::pill_button("Nouvel élément");
    empty_create.set_visible(false);
    {
        let app = app.clone();
        empty_create
            .connect_clicked(move |_| app.show_editor(None, ItemKind::Login, ItemDraft::default()));
    }
    empty.set_child(Some(&empty_create));

    let stack = gtk::Stack::new();
    stack.add_named(&empty, Some("empty"));
    stack.add_named(&scrolled(&list_box), Some("list"));
    let stack_ = stack.clone();

    let entries: Rc<RefCell<Vec<Entry>>> = Rc::default();
    let folder_ids: Rc<RefCell<Vec<Option<String>>>> = Rc::default();

    let apply = {
        let (entries, folder_ids) = (entries.clone(), folder_ids.clone());
        let (search, folder_filter, type_filter) =
            (search.clone(), folder_filter.clone(), type_filter.clone());
        let (fav_section, fav_count, all_section, all_count, no_match) = (
            fav_section.clone(),
            fav_count.clone(),
            all_section.clone(),
            all_count.clone(),
            no_match.clone(),
        );
        Rc::new(move || {
            let query = search.text().to_lowercase();
            // Index 0 : tous les dossiers ; ensuite « Aucun dossier » puis les dossiers.
            let folder = folder_filter.selected() as usize;
            let wanted_folder = folder
                .checked_sub(1)
                .and_then(|i| folder_ids.borrow().get(i).cloned());
            let kind = type_filter.selected();
            let (mut favs, mut others) = (0, 0);
            for entry in entries.borrow().iter() {
                let visible = (query.is_empty() || entry.key.contains(&query))
                    && (folder == 0 || wanted_folder.as_ref() == Some(&entry.folder))
                    && (kind == 0 || entry.kind == kind);
                entry.row.set_visible(visible);
                if visible {
                    if entry.favorite {
                        favs += 1;
                    } else {
                        others += 1;
                    }
                }
            }
            fav_count.set_label(&favs.to_string());
            all_count.set_label(&others.to_string());
            fav_section.set_visible(favs > 0);
            all_section.set_visible(others > 0);
            no_match.set_visible(favs + others == 0);
        })
    };
    {
        let apply = apply.clone();
        search.connect_search_changed(move |_| apply());
    }
    {
        let apply = apply.clone();
        folder_filter.connect_selected_notify(move |_| apply());
    }
    {
        let apply = apply.clone();
        type_filter.connect_selected_notify(move |_| apply());
    }

    let reload = {
        let app = app.clone();
        Rc::new(move || {
            let (entries, folder_ids, apply) = (entries.clone(), folder_ids.clone(), apply.clone());
            let (favorites, all, stack, empty, empty_create, folder_filter) = (
                favorites.clone(),
                all.clone(),
                stack.clone(),
                empty.clone(),
                empty_create.clone(),
                folder_filter.clone(),
            );
            app.with_session(
                |session| async move {
                    let items = session.list_scope(Scope::Vault).await?;
                    let folders = session.folders().await.unwrap_or_default();
                    Ok((items, folders))
                },
                move |app, result| {
                    let (items, folders) = match result {
                        Ok(value) => value,
                        Err(e) => {
                            empty.set_title("Erreur");
                            empty.set_description(Some(&glib::markup_escape_text(&e.to_string())));
                            return;
                        }
                    };
                    fill_folders(&folder_filter, &folder_ids, &folders);
                    favorites.remove_all();
                    all.remove_all();
                    entries.borrow_mut().clear();
                    if items.is_empty() {
                        empty.set_title("Coffre vide");
                        empty.set_description(Some(
                            "Enregistrez vos identifiants, notes et cartes en toute sécurité.",
                        ));
                        empty_create.set_visible(true);
                        stack.set_visible_child_name("empty");
                        return;
                    }
                    for item in items {
                        let row = item_row(app, &item, Scope::Vault);
                        if item.favorite {
                            favorites.append(&row);
                        } else {
                            all.append(&row);
                        }
                        entries.borrow_mut().push(Entry {
                            row,
                            favorite: item.favorite,
                            folder: item.folder_id.map(|id| id.to_string()),
                            kind: type_index(&item.r#type),
                            key: format!("{} {}", item.name, item.subtitle).to_lowercase(),
                        });
                    }
                    apply();
                    stack.set_visible_child_name("list");
                },
            );
        })
    };
    reload();
    {
        let reload = reload.clone();
        app.register_reload(move || reload());
    }

    tab("Mon coffre", &header, &stack_)
}

/// Remplit le filtre de dossiers en conservant la sélection. `ids[i]` est le
/// dossier de l'entrée `i + 1` (l'entrée 0 regroupe tous les dossiers).
fn fill_folders(
    dropdown: &gtk::DropDown,
    ids: &Rc<RefCell<Vec<Option<String>>>>,
    folders: &[FolderInfo],
) {
    let selected = dropdown.selected() as usize;
    let previous = selected
        .checked_sub(1)
        .and_then(|i| ids.borrow().get(i).cloned());
    let mut labels = vec!["Tous les dossiers", "Aucun dossier"];
    let mut new_ids = vec![None];
    for folder in folders {
        labels.push(&folder.name);
        new_ids.push(Some(folder.id.clone()));
    }
    let selected = previous
        .and_then(|prev| new_ids.iter().position(|id| *id == prev))
        .map_or(0, |i| i + 1);
    *ids.borrow_mut() = new_ids;
    dropdown.set_model(Some(&gtk::StringList::new(&labels)));
    dropdown.set_selected(selected as u32);
}

/// Menu du bouton « + Créer ».
fn create_menu(app: &App, anchor: &gtk::Button) {
    let popover = gtk::Popover::new();
    let list = gtk::Box::new(gtk::Orientation::Vertical, 0);
    for (label, icon, kind) in [
        ("Identifiant", "dialog-password-symbolic", ItemKind::Login),
        (
            "Note sécurisée",
            "text-x-generic-symbolic",
            ItemKind::SecureNote,
        ),
    ] {
        let content = adw::ButtonContent::builder()
            .icon_name(icon)
            .label(label)
            .halign(gtk::Align::Start)
            .build();
        let button = gtk::Button::builder().child(&content).build();
        button.add_css_class("flat");
        let (app, popover_) = (app.clone(), popover.clone());
        button.connect_clicked(move |_| {
            popover_.popdown();
            app.show_editor(None, kind, ItemDraft::default());
        });
        list.append(&button);
    }
    popover.set_child(Some(&list));
    popover.set_parent(anchor);
    popover.connect_closed(|p| p.unparent());
    popover.popup();
}

/// Rangée d'élément : icône, nom, sous-titre, ouvrir le site, copier et menu ⋮.
pub(super) fn item_row(app: &App, item: &CipherListView, scope: Scope) -> adw::ActionRow {
    let config = app.config();
    let row = adw::ActionRow::builder()
        .title(item.name.as_str())
        .subtitle(item.subtitle.as_str())
        .use_markup(false)
        .activatable(true)
        .build();
    let icon = gtk::Image::builder()
        .icon_name(icon_for(&item.r#type))
        .pixel_size(24)
        .build();
    icon.add_css_class("site-icon");
    row.add_prefix(&icon);

    let Some(id) = item.id.map(|id| id.to_string()) else {
        return row;
    };
    let uri = match &item.r#type {
        CipherListViewType::Login(login) => login
            .uris
            .iter()
            .flatten()
            .filter_map(|u| u.uri.clone())
            .find(|u| host_of(u).is_some()),
        _ => None,
    };
    if config.show_icons
        && let Some(host) = uri.as_deref().and_then(host_of)
    {
        load_icon(app, &icon, host);
    }

    if scope == Scope::Vault {
        if let Some(uri) = uri.clone() {
            let open = icon_button("coffre-external-link-symbolic", "Ouvrir le site");
            let app = app.clone();
            open.connect_clicked(move |_| app.open_uri(&uri));
            row.add_suffix(&open);
        }
        if config.quick_copy {
            let field = if has_field(item, "LoginPassword") && item.view_password {
                Some(("Mot de passe", "password"))
            } else if has_field(item, "LoginUsername") {
                Some(("Nom d'utilisateur", "username"))
            } else {
                None
            };
            if let Some((label, what)) = field {
                let copy = icon_button("edit-copy-symbolic", &format!("Copier : {label}"));
                let (app, id) = (app.clone(), id.clone());
                copy.connect_clicked(move |_| copy_field(&app, id.clone(), what));
                row.add_suffix(&copy);
            }
        }
    }

    row.add_suffix(&item_menu(app, item, &id, scope));

    let app = app.clone();
    row.connect_activated(move |_| app.show_detail(id.clone()));
    row
}

/// Menu ⋮ d'un élément, selon la liste où il apparaît.
fn item_menu(app: &App, item: &CipherListView, id: &str, scope: Scope) -> gtk::MenuButton {
    let actions = gio::SimpleActionGroup::new();
    let menu = gio::Menu::new();
    let add = |name: &str, label: &str, run: Rc<dyn Fn()>| {
        let action = gio::SimpleAction::new(name, None);
        action.connect_activate(move |_, _| run());
        actions.add_action(&action);
        menu.append(Some(label), Some(&format!("item.{name}")));
    };
    match scope {
        Scope::Vault => {
            let copies = [
                ("LoginUsername", "username", "Copier le nom d'utilisateur"),
                ("LoginPassword", "password", "Copier le mot de passe"),
                ("LoginTotp", "totp", "Copier le code TOTP"),
            ];
            for (field, what, label) in copies {
                if has_field(item, field) && (what != "password" || item.view_password) {
                    let (app, id) = (app.clone(), id.to_owned());
                    add(
                        &format!("copy-{what}"),
                        label,
                        Rc::new(move || copy_field(&app, id.clone(), what)),
                    );
                }
            }
            let editable = matches!(
                item.r#type,
                CipherListViewType::Login(_) | CipherListViewType::SecureNote
            );
            if item.edit && editable {
                let (app_, id_) = (app.clone(), id.to_owned());
                add(
                    "edit",
                    "Modifier",
                    Rc::new(move || edit_item(&app_, id_.clone())),
                );
            }
            let favorite = !item.favorite;
            let (app_, id_) = (app.clone(), id.to_owned());
            add(
                "favorite",
                if favorite {
                    "Ajouter aux favoris"
                } else {
                    "Retirer des favoris"
                },
                Rc::new(move || {
                    let id = id_.clone();
                    app_.mutate(
                        move |mut s| async move {
                            s.set_favorite(&id, favorite).await?;
                            Ok((s, ()))
                        },
                        |app, r| {
                            if let Err(e) = r {
                                app.toast(&e.to_string());
                            }
                        },
                    );
                }),
            );
            if item.organization_id.is_none() {
                let (app_, id_) = (app.clone(), id.to_owned());
                add(
                    "archive",
                    "Archiver",
                    Rc::new(move || set_archived(&app_, id_.clone(), true)),
                );
            }
            if item.edit {
                let (app_, id_) = (app.clone(), id.to_owned());
                add(
                    "trash",
                    "Supprimer",
                    Rc::new(move || app_.confirm_trash(id_.clone())),
                );
            }
        }
        Scope::Archive => {
            let (app_, id_) = (app.clone(), id.to_owned());
            add(
                "unarchive",
                "Désarchiver",
                Rc::new(move || set_archived(&app_, id_.clone(), false)),
            );
            let (app_, id_) = (app.clone(), id.to_owned());
            add(
                "trash",
                "Supprimer",
                Rc::new(move || app_.confirm_trash(id_.clone())),
            );
        }
        Scope::Trash => {
            let (app_, id_) = (app.clone(), id.to_owned());
            add(
                "restore",
                "Restaurer",
                Rc::new(move || {
                    let id = id_.clone();
                    app_.mutate(
                        move |mut s| async move {
                            s.restore_item(&id).await?;
                            s.sync().await?;
                            Ok((s, ()))
                        },
                        |app, r| match r {
                            Ok(()) => app.toast("Élément restauré"),
                            Err(e) => app.toast(&e.to_string()),
                        },
                    );
                }),
            );
            let (app_, id_) = (app.clone(), id.to_owned());
            add(
                "delete",
                "Supprimer définitivement",
                Rc::new(move || confirm_delete(&app_, id_.clone())),
            );
        }
    }
    let button = gtk::MenuButton::builder()
        .icon_name("view-more-symbolic")
        .tooltip_text("Options")
        .menu_model(&menu)
        .valign(gtk::Align::Center)
        .build();
    button.add_css_class("flat");
    button.insert_action_group("item", Some(&actions));
    button
}

fn set_archived(app: &App, id: String, archived: bool) {
    app.mutate(
        move |mut s| async move {
            s.set_archived(&id, archived).await?;
            Ok((s, ()))
        },
        move |app, r| match r {
            Ok(()) => app.toast(if archived {
                "Élément archivé"
            } else {
                "Élément désarchivé"
            }),
            Err(e) => app.toast(&e.to_string()),
        },
    );
}

fn confirm_delete(app: &App, id: String) {
    let dialog = adw::AlertDialog::builder()
        .heading("Supprimer définitivement ?")
        .body("Cette action est irréversible.")
        .default_response("cancel")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", "Annuler");
    dialog.add_response("delete", "Supprimer");
    dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    let app_ = app.clone();
    dialog.connect_response(Some("delete"), move |_, _| {
        let id = id.clone();
        app_.mutate(
            move |mut s| async move {
                s.delete_permanently(&id).await?;
                s.sync().await?;
                Ok((s, ()))
            },
            |app, r| match r {
                Ok(()) => app.toast("Élément supprimé définitivement"),
                Err(e) => app.toast(&e.to_string()),
            },
        );
    });
    dialog.present(Some(&app.window));
}

fn edit_item(app: &App, id: String) {
    app.with_session(
        move |s| async move { s.get(&id).await },
        |app, r| match r {
            Ok(view) => {
                let kind = if view.r#type == bitwarden_vault::CipherType::SecureNote {
                    ItemKind::SecureNote
                } else {
                    ItemKind::Login
                };
                let id = view.id.map(|id| id.to_string());
                app.show_editor(id, kind, ItemDraft::from_view(&view));
            }
            Err(e) => app.toast(&e.to_string()),
        },
    );
}

/// Copie un champ (`username`, `password` ou `totp`) d'un élément.
pub(super) fn copy_field(app: &App, id: String, what: &'static str) {
    app.with_session(
        move |s| async move { s.get(&id).await },
        move |app, result| {
            let login = match result {
                Ok(view) => view.login,
                Err(e) => return app.toast(&e.to_string()),
            };
            let Some(login) = login else {
                return app.toast("Cet élément n'est pas un identifiant.");
            };
            match what {
                "username" => match login.username.filter(|u| !u.is_empty()) {
                    Some(value) => app.copy("Nom d'utilisateur", &value),
                    None => app.toast("Cet élément n'a pas de nom d'utilisateur."),
                },
                "password" => match login.password.filter(|p| !p.is_empty()) {
                    Some(value) => app.copy("Mot de passe", &value),
                    None => app.toast("Cet élément n'a pas de mot de passe."),
                },
                _ => match login.totp.as_deref().and_then(crate::backend::totp) {
                    Some((code, _)) => app.copy("Code TOTP", &code),
                    None => app.toast("Cet élément n'a pas de code TOTP."),
                },
            }
        },
    );
}

/// Remplace l'icône générique par celle du site, téléchargée une seule fois.
fn load_icon(app: &App, image: &gtk::Image, host: String) {
    let cached = ICONS.with(|icons| icons.borrow().get(&host).cloned());
    match cached {
        Some(Some(texture)) => {
            image.set_paintable(Some(&texture));
            return;
        }
        Some(None) => return,
        None => {}
    }
    let image = image.downgrade();
    app.with_session(
        move |s| async move { Ok((s.fetch_icon(&host).await, host)) },
        move |_, result| {
            let Ok((bytes, host)) = result else { return };
            let texture =
                bytes.and_then(|b| gdk::Texture::from_bytes(&glib::Bytes::from_owned(b)).ok());
            ICONS.with(|icons| icons.borrow_mut().insert(host, texture.clone()));
            if let (Some(texture), Some(image)) = (texture, image.upgrade()) {
                image.set_paintable(Some(&texture));
            }
        },
    );
}

pub(super) fn icon_for(kind: &CipherListViewType) -> &'static str {
    match kind {
        CipherListViewType::Login(_) => "web-browser-symbolic",
        CipherListViewType::SecureNote => "text-x-generic-symbolic",
        CipherListViewType::Card(_) | CipherListViewType::BankAccount(_) => {
            "document-properties-symbolic"
        }
        CipherListViewType::Identity
        | CipherListViewType::Passport
        | CipherListViewType::DriversLicense => "x-office-address-book-symbolic",
        CipherListViewType::SshKey => "network-server-symbolic",
    }
}

/// Page de liste simple (archive ou corbeille) avec un état vide.
pub(super) fn item_list_page(
    app: &App,
    scope: Scope,
    title: &str,
    banner: Option<&str>,
    empty: (&str, &str, &str),
) -> adw::NavigationPage {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    if let Some(text) = banner {
        let label = gtk::Label::builder()
            .label(text)
            .wrap(true)
            .xalign(0.0)
            .build();
        let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
        let banner = gtk::Box::builder().spacing(10).build();
        banner.add_css_class("warning-banner");
        banner.append(&icon);
        banner.append(&label);
        content.append(&banner);
    }
    let list = card_list();
    let status = empty_state(empty.0, empty.1, empty.2);
    status.set_visible(false);
    content.append(&list);
    content.append(&status);

    let reload = {
        let (app, list, status) = (app.clone(), list.downgrade(), status.downgrade());
        move || {
            let (Some(list), Some(status)) = (list.upgrade(), status.upgrade()) else {
                return;
            };
            app.with_session(
                move |s| async move { s.list_scope(scope).await },
                move |app, result| {
                    list.remove_all();
                    match result {
                        Ok(items) => {
                            status.set_visible(items.is_empty());
                            list.set_visible(!items.is_empty());
                            for item in &items {
                                list.append(&item_row(app, item, scope));
                            }
                        }
                        Err(e) => app.toast(&e.to_string()),
                    }
                },
            );
        }
    };
    reload();
    app.register_reload(reload);

    page(title, "items", &adw::HeaderBar::new(), &content)
}
