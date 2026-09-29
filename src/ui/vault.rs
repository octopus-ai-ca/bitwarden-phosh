//! Liste des éléments du coffre, avec recherche.

use adw::prelude::*;
use bitwarden_vault::{CipherListView, CipherListViewType};

use super::{App, icon_button};

pub fn vault_page(app: &App) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();

    let sync_button = icon_button("view-refresh-symbolic", "Synchroniser");
    header.pack_start(&sync_button);
    let add_button = icon_button("list-add-symbolic", "Nouvel élément");
    add_button.set_action_name(Some("win.new-item"));
    header.pack_start(&add_button);

    let menu = gtk::gio::Menu::new();
    menu.append(Some("Verrouiller"), Some("win.lock"));
    if app.session().is_some_and(|s| s.has_pin()) {
        menu.append(Some("Retirer le NIP"), Some("win.clear-pin"));
    } else {
        menu.append(Some("Définir un NIP…"), Some("win.set-pin"));
    }
    menu.append(Some("Se déconnecter"), Some("win.logout"));
    menu.append(Some("À propos de Coffre"), Some("win.about"));
    header.pack_end(
        &gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .tooltip_text("Menu principal")
            .menu_model(&menu)
            .build(),
    );

    let search_button = gtk::ToggleButton::builder()
        .icon_name("system-search-symbolic")
        .tooltip_text("Rechercher")
        .build();
    header.pack_end(&search_button);

    let search_entry = gtk::SearchEntry::builder()
        .placeholder_text("Rechercher dans le coffre")
        .hexpand(true)
        .build();
    let search_bar = gtk::SearchBar::builder()
        .child(
            &adw::Clamp::builder()
                .maximum_size(600)
                .child(&search_entry)
                .build(),
        )
        .build();
    search_bar.connect_entry(&search_entry);
    search_button
        .bind_property("active", &search_bar, "search-mode-enabled")
        .bidirectional()
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .valign(gtk::Align::Start)
        .build();
    list.add_css_class("boxed-list");

    let empty = adw::StatusPage::builder()
        .icon_name("dialog-password-symbolic")
        .title("Chargement…")
        .vexpand(true)
        .build();

    let stack = gtk::Stack::new();
    stack.add_named(&empty, Some("empty"));
    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .child(&list)
        .build();
    stack.add_named(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build(),
        Some("list"),
    );

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.add_top_bar(&search_bar);
    toolbar.set_content(Some(&stack));

    // Rangées et clé de recherche en minuscules, pour le filtrage.
    let rows: std::rc::Rc<std::cell::RefCell<Vec<(adw::ActionRow, String)>>> = Default::default();

    let rows_ = rows.clone();
    search_entry.connect_search_changed(move |entry| {
        let query = entry.text().to_lowercase();
        for (row, key) in rows_.borrow().iter() {
            row.set_visible(query.is_empty() || key.contains(&query));
        }
    });

    let app_ = app.clone();
    sync_button.connect_clicked(move |button| {
        button.set_sensitive(false);
        let button = button.clone();
        app_.sync(move || button.set_sensitive(true));
    });

    // Chargement asynchrone de la liste déchiffrée.
    if let Some(session) = app.session() {
        let app = app.clone();
        crate::spawn(async move { session.list().await }, move |result| {
            let items = match result {
                Ok(items) => items,
                Err(e) => {
                    empty.set_title("Erreur");
                    empty.set_description(Some(&gtk::glib::markup_escape_text(&e.to_string())));
                    return;
                }
            };
            if items.is_empty() {
                empty.set_title("Coffre vide");
                empty.set_description(Some("Touchez + pour ajouter un premier élément."));
                return;
            }
            let mut rows = rows.borrow_mut();
            for item in items {
                let row = item_row(&app, &item);
                let key = format!("{} {}", item.name, item.subtitle).to_lowercase();
                list.append(&row);
                rows.push((row, key));
            }
            stack.set_visible_child_name("list");
        });
    }

    let page = adw::NavigationPage::builder()
        .title("Coffre")
        .tag("vault")
        .child(&toolbar)
        .build();
    // Taper au clavier (physique) ouvre directement la recherche.
    search_bar.set_key_capture_widget(Some(&page));
    page
}

fn item_row(app: &App, item: &CipherListView) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(item.name.as_str())
        .subtitle(item.subtitle.as_str())
        .use_markup(false)
        .activatable(true)
        .build();
    row.add_prefix(&gtk::Image::from_icon_name(icon_for(&item.r#type)));

    let Some(id) = item.id.map(|id| id.to_string()) else {
        return row;
    };

    if matches!(item.r#type, CipherListViewType::Login(_)) && item.view_password {
        let copy = icon_button("edit-copy-symbolic", "Copier le mot de passe");
        let (app_, id_) = (app.clone(), id.clone());
        copy.connect_clicked(move |_| copy_password(&app_, id_.clone()));
        row.add_suffix(&copy);
    }
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

    let app = app.clone();
    row.connect_activated(move |_| app.show_detail(id.clone()));
    row
}

fn copy_password(app: &App, id: String) {
    let Some(session) = app.session() else { return };
    let app = app.clone();
    crate::spawn(
        async move { session.get(&id).await },
        move |result| match result {
            Ok(view) => match view.login.and_then(|l| l.password) {
                Some(password) => app.copy("Mot de passe", &password),
                None => app.toast("Cet élément n'a pas de mot de passe."),
            },
            Err(e) => app.toast(&e.to_string()),
        },
    );
}

fn icon_for(kind: &CipherListViewType) -> &'static str {
    match kind {
        CipherListViewType::Login(_) => "dialog-password-symbolic",
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
