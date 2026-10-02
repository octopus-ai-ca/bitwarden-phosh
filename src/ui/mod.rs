//! Interface GTK4/libadwaita. Une seule fenêtre contenant un `AdwNavigationView` :
//! connexion → (2FA) → accueil à onglets (Coffre, Générateur, Send, Paramètres),
//! puis les sous-pages empilées par-dessus, et une page de verrouillage.

mod detail;
mod edit;
mod generator;
mod login;
mod send;
mod settings;
mod style;
mod two_factor;
mod vault;

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use gtk::{gio, glib};

use crate::backend::{Error, FolderInfo, ItemDraft, ItemKind, Session};
use crate::config::{Config, TimeoutAction};

struct State {
    config: Config,
    session: Option<Session>,
    last_activity: Instant,
}

/// Fonction de rechargement d'un onglet de l'accueil.
type Reload = Rc<dyn Fn()>;

/// Poignée partagée (bon marché à cloner) vers la fenêtre et l'état de l'application.
#[derive(Clone)]
pub struct App(Rc<Inner>);

pub struct Inner {
    window: adw::ApplicationWindow,
    nav: adw::NavigationView,
    toasts: adw::ToastOverlay,
    state: RefCell<State>,
    /// Onglets de l'accueil à recharger après une modification du coffre.
    reloads: RefCell<Vec<Reload>>,
}

impl std::ops::Deref for App {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl App {
    pub fn new(app: &adw::Application) -> Self {
        style::install();
        let nav = adw::NavigationView::new();
        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&nav));

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Coffre")
            .default_width(400)
            .default_height(760)
            .width_request(360)
            .height_request(294)
            .content(&toasts)
            .build();

        let config = Config::load();
        style::apply(&config);
        let this = Self(Rc::new(Inner {
            window,
            nav,
            toasts,
            state: RefCell::new(State {
                config,
                session: None,
                last_activity: Instant::now(),
            }),
            reloads: RefCell::default(),
        }));
        this.apply_density();
        this.setup_actions();
        this.setup_auto_lock();
        this.restore_session();
        this
    }

    /// Au démarrage : restaure la session précédente (verrouillée) ou affiche la connexion.
    fn restore_session(&self) {
        let loading = adw::StatusPage::builder().title("Coffre").build();
        loading.set_paintable(style::logo_texture().as_ref());
        self.nav.replace(&[adw::NavigationPage::builder()
            .title("Coffre")
            .child(&loading)
            .build()]);
        let device_id = self.device_id();
        let app = self.clone();
        crate::spawn(
            async move { Session::restore(&device_id).await },
            move |result| match result {
                Some(Ok(session)) => {
                    app.set_session(Some(session));
                    app.show_lock();
                }
                Some(Err(e)) => {
                    app.toast(&e.to_string());
                    app.show_login();
                }
                None => app.show_login(),
            },
        );
    }

    pub fn present(&self) {
        self.window.present();
    }

    /// Affiche un message; il passe à la ligne au lieu d'être tronqué sur un
    /// écran de téléphone.
    pub fn toast(&self, message: &str) {
        let label = gtk::Label::builder()
            .label(message)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .justify(gtk::Justification::Center)
            .width_chars(28)
            .max_width_chars(40)
            .build();
        let toast = adw::Toast::builder()
            .custom_title(&label)
            .timeout(if message.len() > 40 { 8 } else { 5 })
            .build();
        self.toasts.add_toast(toast);
    }

    fn setup_actions(&self) {
        let logout = gio::SimpleAction::new("logout", None);
        let app = self.clone();
        logout.connect_activate(move |_, _| app.confirm_logout());
        self.window.add_action(&logout);

        let lock = gio::SimpleAction::new("lock", None);
        let app = self.clone();
        lock.connect_activate(move |_, _| app.lock());
        self.window.add_action(&lock);

        let about = gio::SimpleAction::new("about", None);
        let app = self.clone();
        about.connect_activate(move |_, _| app.show_about());
        self.window.add_action(&about);
    }

    fn show_about(&self) {
        adw::AboutDialog::builder()
            .application_name("Coffre")
            .application_icon(crate::APP_ID)
            .version(env!("CARGO_PKG_VERSION"))
            .comments("Client Bitwarden adaptatif pour Phosh, bâti sur le SDK officiel Bitwarden.")
            .license_type(gtk::License::Gpl30Only)
            .developer_name("Octopus AI")
            .website("https://github.com/octopus-ai-ca/bitwarden-phosh")
            .issue_url("https://github.com/octopus-ai-ca/bitwarden-phosh/issues")
            .build()
            .present(Some(&self.window));
    }

    /// Expire la session (verrouillage ou déconnexion) après le délai choisi sans
    /// interaction (tactile ou clavier).
    fn setup_auto_lock(&self) {
        let touch = gtk::GestureClick::new();
        touch.set_propagation_phase(gtk::PropagationPhase::Capture);
        let app = self.clone();
        touch.connect_pressed(move |_, _, _, _| app.touch_activity());
        self.window.add_controller(touch);

        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        let app = self.clone();
        keys.connect_key_pressed(move |_, _, _, _| {
            app.touch_activity();
            glib::Propagation::Proceed
        });
        self.window.add_controller(keys);

        let weak = Rc::downgrade(&self.0);
        glib::timeout_add_seconds_local(10, move || {
            let Some(inner) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let app = App(inner);
            let action = {
                let state = app.state.borrow();
                let minutes = state.config.lock_minutes;
                let expired = minutes > 0
                    && state.last_activity.elapsed()
                        >= Duration::from_secs(u64::from(minutes) * 60)
                    && state.session.as_ref().is_some_and(Session::is_unlocked);
                expired.then_some(state.config.timeout_action)
            };
            match action {
                Some(TimeoutAction::Lock) => {
                    app.lock();
                    app.toast("Coffre verrouillé après inactivité");
                }
                Some(TimeoutAction::Logout) => {
                    app.logout();
                    app.toast("Session expirée : vous avez été déconnecté");
                }
                None => {}
            }
            glib::ControlFlow::Continue
        });
    }

    fn touch_activity(&self) {
        self.state.borrow_mut().last_activity = Instant::now();
    }

    pub fn session(&self) -> Option<Session> {
        self.state.borrow().session.clone()
    }

    fn set_session(&self, session: Option<Session>) {
        self.state.borrow_mut().session = session;
    }

    pub fn config(&self) -> Config {
        self.state.borrow().config.clone()
    }

    /// Modifie puis enregistre la configuration.
    pub fn update_config(&self, change: impl FnOnce(&mut Config)) {
        let mut state = self.state.borrow_mut();
        change(&mut state.config);
        state.config.save();
    }

    /// Mode compact : classe CSS sur la fenêtre.
    fn apply_density(&self) {
        if self.config().compact {
            self.window.add_css_class("compact");
        } else {
            self.window.remove_css_class("compact");
        }
    }

    // ----- Navigation -----

    pub fn show_login(&self) {
        let config = self.config();
        self.reloads.borrow_mut().clear();
        self.nav.replace(&[login::login_page(self, &config)]);
    }

    fn show_two_factor(
        &self,
        session: Session,
        password: String,
        options: crate::backend::TwoFactorOptions,
    ) {
        self.nav.push(&two_factor::two_factor_page(
            self, session, password, options,
        ));
    }

    /// Accueil sur l'onglet du coffre.
    fn show_vault(&self) {
        self.show_home("vault");
    }

    /// Accueil à onglets avec la barre de navigation du bas.
    fn show_home(&self, tab: &str) {
        self.reloads.borrow_mut().clear();
        let stack = adw::ViewStack::new();
        stack.add_titled_with_icon(
            &vault::vault_tab(self),
            Some("vault"),
            "Coffre",
            "dialog-password-symbolic",
        );
        stack.add_titled_with_icon(
            &generator::generator_tab(self),
            Some("generator"),
            "Générateur",
            "coffre-generator-symbolic",
        );
        stack.add_titled_with_icon(
            &send::send_tab(self),
            Some("send"),
            "Send",
            "coffre-send-symbolic",
        );
        stack.add_titled_with_icon(
            &settings::settings_tab(self),
            Some("settings"),
            "Paramètres",
            "emblem-system-symbolic",
        );
        stack.set_visible_child_name(tab);

        let bar = adw::ViewSwitcherBar::builder()
            .stack(&stack)
            .reveal(true)
            .build();
        let toolbar = adw::ToolbarView::new();
        toolbar.set_content(Some(&stack));
        toolbar.add_bottom_bar(&bar);
        self.nav.replace(&[adw::NavigationPage::builder()
            .title("Coffre")
            .tag("home")
            .child(&toolbar)
            .build()]);
    }

    /// Recharge les onglets de l'accueil (après une modification du coffre).
    pub fn refresh(&self) {
        let reloads = self.reloads.borrow().clone();
        for reload in reloads {
            reload();
        }
    }

    fn register_reload(&self, reload: impl Fn() + 'static) {
        self.reloads.borrow_mut().push(Rc::new(reload));
    }

    /// Retour à l'accueil (dépile les sous-pages), puis recharge.
    pub fn back_home(&self) {
        self.nav.pop_to_tag("home");
        self.refresh();
    }

    fn show_lock(&self) {
        self.reloads.borrow_mut().clear();
        self.nav.replace(&[login::lock_page(self)]);
    }

    pub fn push(&self, page: &adw::NavigationPage) {
        self.nav.push(page);
    }

    /// Page de modification (`id` fourni) ou de création (`id` absent).
    pub fn show_editor(&self, id: Option<String>, kind: ItemKind, draft: ItemDraft) {
        let Some(session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move { session.folders().await },
            move |folders: Result<Vec<FolderInfo>, Error>| {
                let folders = folders.unwrap_or_default();
                app.nav
                    .push(&edit::edit_page(&app, id, kind, draft, folders));
            },
        );
    }

    pub fn show_detail(&self, id: String) {
        let Some(session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move { session.get(&id).await },
            move |result| match result {
                Ok(view) => app.nav.push(&detail::detail_page(&app, view)),
                Err(e) => app.toast(&e.to_string()),
            },
        );
    }

    // ----- Flux de session -----

    /// Connexion réussie (avec ou sans 2FA) : synchronise puis déverrouille.
    fn finish_login(
        &self,
        mut session: Session,
        password: String,
        done: impl FnOnce(bool) + 'static,
    ) {
        let app = self.clone();
        crate::spawn(
            async move {
                session.sync().await?;
                session.unlock(password).await?;
                Ok::<_, Error>(session)
            },
            move |result| match result {
                Ok(session) => {
                    app.set_session(Some(session));
                    app.touch_activity();
                    app.show_vault();
                    done(true);
                }
                Err(e) => {
                    app.toast(&e.to_string());
                    done(false);
                }
            },
        );
    }

    fn remember_account(&self, server: crate::backend::Server, email: String) {
        self.update_config(|config| {
            config.server = server;
            config.email = email;
        });
    }

    fn device_id(&self) -> String {
        self.state.borrow().config.device_id.clone()
    }

    pub fn lock(&self) {
        if let Some(session) = self.session() {
            session.lock();
            self.show_lock();
        }
    }

    /// Déverrouille avec le mot de passe maître (`pin == false`) ou le NIP.
    fn unlock(&self, secret: String, pin: bool, done: impl FnOnce(bool) + 'static) {
        let Some(session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move {
                if pin {
                    session.unlock_with_pin(secret).await
                } else {
                    session.unlock(secret).await
                }
            },
            move |result| match result {
                Ok(()) => {
                    app.touch_activity();
                    app.show_vault();
                    app.sync_quietly();
                    done(true);
                }
                Err(e) => {
                    app.toast(&e.to_string());
                    done(false);
                }
            },
        );
    }

    /// Synchronise, recharge les onglets, puis appelle `done(succès)`.
    pub fn sync(&self, done: impl FnOnce(bool) + 'static) {
        self.mutate(
            |mut session| async move {
                session.sync().await?;
                Ok((session, ()))
            },
            move |app, result| {
                match &result {
                    Ok(()) => app.toast("Coffre synchronisé"),
                    Err(e) => app.toast(&e.to_string()),
                }
                done(result.is_ok());
            },
        );
    }

    /// Synchronisation en arrière-plan après un déverrouillage; le coffre local
    /// reste utilisable hors ligne en cas d'échec.
    fn sync_quietly(&self) {
        self.mutate(
            |mut session| async move {
                session.sync().await?;
                Ok((session, ()))
            },
            |app, result| match result {
                Ok(()) => {}
                Err(Error::SessionExpired) => app.toast(
                    "Session expirée : déconnectez-vous puis reconnectez-vous pour synchroniser.",
                ),
                Err(e) => eprintln!("synchronisation en arrière-plan : {e}"),
            },
        );
    }

    /// Exécute une opération qui modifie la session (synchronisation, dossiers…),
    /// conserve la session mise à jour, recharge les onglets, puis appelle `done`.
    pub fn mutate<T, F, Fut>(&self, op: F, done: impl FnOnce(&App, Result<T, Error>) + 'static)
    where
        T: Send + 'static,
        F: FnOnce(Session) -> Fut,
        Fut: Future<Output = Result<(Session, T), Error>> + Send + 'static,
    {
        let Some(session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(op(session), move |result| {
            let result = result.map(|(session, value)| {
                // Ne pas ressusciter une session fermée entre-temps.
                if app.session().is_some() {
                    app.set_session(Some(session));
                }
                value
            });
            if result.is_ok() {
                app.refresh();
            }
            done(&app, result);
        });
    }

    /// Exécute une opération en lecture seule sur la session.
    pub fn with_session<T, F, Fut>(
        &self,
        op: F,
        done: impl FnOnce(&App, Result<T, Error>) + 'static,
    ) where
        T: Send + 'static,
        F: FnOnce(Session) -> Fut,
        Fut: Future<Output = Result<T, Error>> + Send + 'static,
    {
        let Some(session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(op(session), move |result| done(&app, result));
    }

    /// Enregistre un élément (création si `id` est absent), puis revient à l'accueil.
    fn save_item(
        &self,
        id: Option<String>,
        kind: ItemKind,
        draft: ItemDraft,
        done: impl FnOnce(bool) + 'static,
    ) {
        self.mutate(
            |mut session| async move {
                match id {
                    Some(id) => session.edit_item(&id, draft).await?,
                    None => session.create_item(kind, draft).await?,
                }
                Ok((session, ()))
            },
            move |app, result| match result {
                Ok(()) => {
                    app.back_home();
                    app.toast("Élément enregistré");
                    done(true);
                }
                Err(e) => {
                    app.toast(&e.to_string());
                    done(false);
                }
            },
        );
    }

    /// Envoie un élément à la corbeille.
    fn trash_item(&self, id: String) {
        self.mutate(
            |mut session| async move {
                session.trash(&id).await?;
                session.sync().await?;
                Ok((session, ()))
            },
            |app, result| match result {
                Ok(()) => {
                    app.back_home();
                    app.toast("Élément envoyé à la corbeille");
                }
                Err(e) => app.toast(&e.to_string()),
            },
        );
    }

    /// Demande une confirmation avant d'envoyer un élément à la corbeille.
    pub fn confirm_trash(&self, id: String) {
        let dialog = adw::AlertDialog::builder()
            .heading("Envoyer à la corbeille ?")
            .body("L'élément pourra être restauré depuis la corbeille pendant 30 jours.")
            .default_response("cancel")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", "Annuler");
        dialog.add_response("trash", "Corbeille");
        dialog.set_response_appearance("trash", adw::ResponseAppearance::Destructive);
        let app = self.clone();
        dialog.connect_response(Some("trash"), move |_, _| app.trash_item(id.clone()));
        dialog.present(Some(&self.window));
    }

    fn confirm_logout(&self) {
        let dialog = adw::AlertDialog::builder()
            .heading("Se déconnecter ?")
            .body("Les données locales du coffre seront effacées de cet appareil.")
            .default_response("cancel")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", "Annuler");
        dialog.add_response("logout", "Se déconnecter");
        dialog.set_response_appearance("logout", adw::ResponseAppearance::Destructive);
        let app = self.clone();
        dialog.connect_response(Some("logout"), move |_, _| app.logout());
        dialog.present(Some(&self.window));
    }

    /// Déconnexion : efface les clés, le NIP et toutes les données locales.
    pub fn logout(&self) {
        if let Some(session) = self.state.borrow_mut().session.take() {
            session.logout();
        } else {
            crate::backend::wipe_local_data();
        }
        self.show_login();
    }

    /// Copie `value` puis efface le presse-papier après le délai choisi s'il
    /// contient toujours notre valeur.
    pub fn copy(&self, label: &str, value: &str) {
        let clipboard = self.window.clipboard();
        clipboard.set_text(value);
        let seconds = self.config().clipboard_seconds;
        if seconds == 0 {
            self.toast(&format!("{label} copié"));
            return;
        }
        self.toast(&format!("{label} copié — effacé dans {seconds} s"));
        glib::timeout_add_seconds_local_once(seconds, move || {
            if clipboard.is_local() {
                clipboard.set_text("");
            }
        });
    }

    /// Ouvre une adresse dans le navigateur.
    pub fn open_uri(&self, uri: &str) {
        let uri = if uri.contains("://") {
            uri.to_owned()
        } else {
            format!("https://{uri}")
        };
        let app = self.clone();
        gtk::UriLauncher::new(&uri).launch(
            Some(&self.window),
            gio::Cancellable::NONE,
            move |result| {
                if let Err(e) = result {
                    app.toast(&format!("Impossible d'ouvrir le lien : {e}"));
                }
            },
        );
    }
}

// ----- Petits utilitaires de construction de widgets -----

/// Page de navigation standard : barre d'en-tête + contenu défilant et centré.
fn page(
    title: &str,
    tag: &str,
    header: &adw::HeaderBar,
    content: &impl IsA<gtk::Widget>,
) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(header);
    toolbar.set_content(Some(&scrolled(content)));
    adw::NavigationPage::builder()
        .title(title)
        .tag(tag)
        .child(&toolbar)
        .build()
}

/// Contenu défilant, centré et limité en largeur.
fn scrolled(content: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .child(content)
        .build();
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build()
}

/// Onglet de l'accueil : barre d'en-tête (titre `title`) et contenu.
fn tab(title: &str, header: &adw::HeaderBar, content: &impl IsA<gtk::Widget>) -> adw::ToolbarView {
    header.set_title_widget(Some(&adw::WindowTitle::new(title, "")));
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(header);
    toolbar.set_content(Some(content));
    toolbar
}

fn pill_button(label: &str) -> gtk::Button {
    let button = gtk::Button::builder()
        .label(label)
        .halign(gtk::Align::Center)
        .margin_top(12)
        .build();
    button.add_css_class("pill");
    button.add_css_class("suggested-action");
    button
}

/// Bouton « + Créer » des en-têtes.
fn create_button(label: &str) -> gtk::Button {
    let content = adw::ButtonContent::builder()
        .icon_name("list-add-symbolic")
        .label(label)
        .build();
    let button = gtk::Button::builder().child(&content).build();
    button.add_css_class("create");
    button.add_css_class("suggested-action");
    button
}

/// Désactive un bouton pendant une opération réseau et affiche un libellé d'attente.
fn set_busy(button: &gtk::Button, busy: bool, idle_label: &str, busy_label: &str) {
    button.set_sensitive(!busy);
    button.set_label(if busy { busy_label } else { idle_label });
}

fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::builder()
        .icon_name(icon)
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .build();
    button.add_css_class("flat");
    button
}

/// Liste en cartes séparées (style de l'extension).
fn card_list() -> gtk::ListBox {
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .valign(gtk::Align::Start)
        .build();
    list.add_css_class("cards");
    list
}

/// Rangée de navigation (icône, titre, chevron).
fn nav_row(icon: &str, title: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .activatable(true)
        .build();
    row.add_prefix(&gtk::Image::from_icon_name(icon));
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    row
}

/// Rangée qui ouvre un lien externe.
fn link_row(icon: &str, title: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .activatable(true)
        .build();
    row.add_prefix(&gtk::Image::from_icon_name(icon));
    row.add_suffix(&gtk::Image::from_icon_name("coffre-external-link-symbolic"));
    row
}

/// État vide : titre, description et action facultative.
fn empty_state(icon: &str, title: &str, description: &str) -> adw::StatusPage {
    let status = adw::StatusPage::builder()
        .icon_name(icon)
        .title(title)
        .description(glib::markup_escape_text(description).as_str())
        .vexpand(true)
        .build();
    status.add_css_class("compact");
    status
}

/// En-tête de section « Titre  N ».
fn section_header(title: &str) -> (gtk::Box, gtk::Label) {
    let label = gtk::Label::builder().label(title).xalign(0.0).build();
    label.add_css_class("section-title");
    let count = gtk::Label::new(None);
    count.add_css_class("section-count");
    let header = gtk::Box::builder()
        .spacing(8)
        .margin_start(4)
        .margin_bottom(6)
        .build();
    header.append(&label);
    header.append(&count);
    (header, count)
}

const MONTHS: [&str; 12] = [
    "janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.",
    "déc.",
];

/// Date et heure locales en français : « 2 oct. 2026, 14 h 05 ».
fn fr_datetime(date: DateTime<Utc>) -> String {
    let local = date.with_timezone(&Local);
    format!(
        "{} {} {}, {} h {:02}",
        local.day(),
        MONTHS[local.month0() as usize],
        local.year(),
        local.hour(),
        local.minute()
    )
}

/// Date locale en français : « 2 oct. 2026 ».
fn fr_date(date: DateTime<Utc>) -> String {
    let local = date.with_timezone(&Local);
    format!(
        "{} {} {}",
        local.day(),
        MONTHS[local.month0() as usize],
        local.year()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_en_francais() {
        let date = DateTime::parse_from_rfc3339("2026-08-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(fr_date(date).ends_with("août 2026"));
        assert!(fr_datetime(date).contains("août 2026, "));
    }
}
