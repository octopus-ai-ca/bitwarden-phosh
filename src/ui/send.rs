//! Onglet Send : partage chiffré de textes par lien, avec date de suppression.

use adw::prelude::*;
use gtk::gio;

use super::{
    App, card_list, create_button, empty_state, fr_date, icon_button, page, pill_button, scrolled,
    set_busy, tab,
};
use crate::backend::{SendDraft, SendInfo};

/// Durées de conservation proposées, en jours.
const DAYS: [(u32, &str); 6] = [
    (1, "1 jour"),
    (2, "2 jours"),
    (3, "3 jours"),
    (7, "7 jours"),
    (14, "14 jours"),
    (30, "30 jours"),
];

pub fn send_tab(app: &App) -> adw::ToolbarView {
    let header = adw::HeaderBar::new();
    let create = create_button("Créer");
    {
        let app = app.clone();
        create.connect_clicked(move |_| app.push(&new_send_page(&app)));
    }
    header.pack_start(&create);

    let list = card_list();
    let empty = empty_state(
        "coffre-send-symbolic",
        "Aucun Send actif",
        "Utilisez Send pour partager des informations chiffrées avec n'importe qui, en toute \
         sécurité.",
    );
    let new_send = pill_button("Nouveau Send");
    {
        let app = app.clone();
        new_send.connect_clicked(move |_| app.push(&new_send_page(&app)));
    }
    empty.set_child(Some(&new_send));

    let stack = gtk::Stack::new();
    stack.add_named(&empty, Some("empty"));
    stack.add_named(&scrolled(&list), Some("list"));

    let reload = {
        let (app, list, stack) = (app.clone(), list.clone(), stack.clone());
        move || {
            let (list, stack) = (list.clone(), stack.clone());
            app.with_session(
                |s| async move { s.sends().await },
                move |app, result| {
                    list.remove_all();
                    match result {
                        Ok(sends) if !sends.is_empty() => {
                            for send in &sends {
                                list.append(&send_row(app, send));
                            }
                            stack.set_visible_child_name("list");
                        }
                        Ok(_) => stack.set_visible_child_name("empty"),
                        Err(e) => app.toast(&e.to_string()),
                    }
                },
            );
        }
    };
    reload();
    app.register_reload(reload);

    tab("Send", &header, &stack)
}

fn send_row(app: &App, send: &SendInfo) -> adw::ActionRow {
    let mut subtitle = format!("Suppression le {}", fr_date(send.deletion_date));
    match send.max_access_count {
        Some(max) => subtitle.push_str(&format!(" · {}/{max} accès", send.access_count)),
        None if send.access_count > 0 => {
            subtitle.push_str(&format!(" · {} accès", send.access_count))
        }
        None => {}
    }
    let row = adw::ActionRow::builder()
        .title(send.name.as_str())
        .subtitle(subtitle)
        .use_markup(false)
        .build();
    let icon = if send.has_password {
        "channel-secure-symbolic"
    } else {
        "text-x-generic-symbolic"
    };
    row.add_prefix(&gtk::Image::from_icon_name(icon));

    if let Some(url) = send.url.clone() {
        let copy = icon_button("edit-copy-symbolic", "Copier le lien");
        let app = app.clone();
        copy.connect_clicked(move |_| app.copy("Lien du Send", &url));
        row.add_suffix(&copy);
    }

    let actions = gio::SimpleActionGroup::new();
    let menu = gio::Menu::new();
    if let Some(url) = send.url.clone() {
        let open = gio::SimpleAction::new("open", None);
        let app_ = app.clone();
        open.connect_activate(move |_, _| app_.open_uri(&url));
        actions.add_action(&open);
        menu.append(Some("Ouvrir le lien"), Some("send.open"));
    }
    let delete = gio::SimpleAction::new("delete", None);
    let (app_, id, name) = (app.clone(), send.id.clone(), send.name.clone());
    delete.connect_activate(move |_, _| confirm_delete(&app_, id.clone(), &name));
    actions.add_action(&delete);
    menu.append(Some("Supprimer"), Some("send.delete"));
    let more = gtk::MenuButton::builder()
        .icon_name("view-more-symbolic")
        .tooltip_text("Options")
        .menu_model(&menu)
        .valign(gtk::Align::Center)
        .build();
    more.add_css_class("flat");
    more.insert_action_group("send", Some(&actions));
    row.add_suffix(&more);
    row
}

fn confirm_delete(app: &App, id: String, name: &str) {
    let dialog = adw::AlertDialog::builder()
        .heading("Supprimer le Send ?")
        .body(format!("« {name} » ne sera plus accessible par son lien."))
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
                s.delete_send(&id).await?;
                s.sync().await?;
                Ok((s, ()))
            },
            |app, r| match r {
                Ok(()) => app.toast("Send supprimé"),
                Err(e) => app.toast(&e.to_string()),
            },
        );
    });
    dialog.present(Some(&app.window));
}

fn new_send_page(app: &App) -> adw::NavigationPage {
    let name = adw::EntryRow::builder().title("Nom").build();
    let text = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .height_request(120)
        .accepts_tab(false)
        .build();
    text.add_css_class("card");
    let hide = adw::SwitchRow::builder()
        .title("Masquer le texte par défaut")
        .build();
    let general = adw::PreferencesGroup::new();
    general.add(&name);
    let text_group = adw::PreferencesGroup::builder()
        .title("Texte à partager")
        .build();
    text_group.add(&text);
    let hide_group = adw::PreferencesGroup::new();
    hide_group.add(&hide);

    let labels: Vec<&str> = DAYS.iter().map(|(_, l)| *l).collect();
    let days = adw::ComboRow::builder()
        .title("Date de suppression")
        .subtitle("Le Send sera définitivement supprimé à cette date")
        .model(&gtk::StringList::new(&labels))
        .selected(3)
        .build();
    let max_access = adw::SpinRow::with_range(0.0, 1000.0, 1.0);
    max_access.set_title("Nombre maximal d'accès");
    max_access.set_subtitle("0 : illimité");
    let password = adw::PasswordEntryRow::builder()
        .title("Mot de passe (facultatif)")
        .build();
    let options = adw::PreferencesGroup::builder().title("Options").build();
    options.add(&days);
    options.add(&max_access);
    options.add(&password);

    let save = pill_button("Créer le Send");
    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&general);
    content.append(&text_group);
    content.append(&hide_group);
    content.append(&options);
    content.append(&save);

    let app = app.clone();
    save.connect_clicked(move |button| {
        let buffer = text.buffer();
        let draft = SendDraft {
            name: name.text().to_string(),
            text: buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string(),
            days: DAYS[days.selected() as usize].0,
            max_access_count: Some(max_access.value() as u32).filter(|n| *n > 0),
            password: Some(password.text().to_string()).filter(|p| !p.is_empty()),
            hide_text: hide.is_active(),
        };
        if draft.name.trim().is_empty() || draft.text.trim().is_empty() {
            app.toast("Le nom et le texte sont obligatoires.");
            return;
        }
        set_busy(button, true, "Créer le Send", "Création…");
        let button = button.clone();
        app.mutate(
            move |mut s| async move {
                let url = s.create_send(draft).await?;
                s.sync().await?;
                Ok((s, url))
            },
            move |app, r| match r {
                Ok(url) => {
                    app.nav.pop();
                    match url {
                        Some(url) => app.copy("Lien du Send", &url),
                        None => app.toast("Send créé"),
                    }
                }
                Err(e) => {
                    set_busy(&button, false, "Créer le Send", "");
                    app.toast(&e.to_string());
                }
            },
        );
    });

    page("Nouveau Send", "new-send", &adw::HeaderBar::new(), &content)
}
