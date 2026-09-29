//! Interface GTK4/libadwaita. Une seule fenêtre contenant un `AdwNavigationView` :
//! connexion → (2FA) → coffre → détail → modification, et une page de verrouillage.

mod detail;
mod edit;
mod login;
mod vault;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gio, glib};

use crate::backend::{ItemDraft, ItemKind, Session};
use crate::config::Config;

/// Délai d'inactivité avant le verrouillage automatique.
const AUTO_LOCK_AFTER: Duration = Duration::from_secs(5 * 60);
/// Délai avant l'effacement du presse-papier.
const CLIPBOARD_CLEAR_SECS: u32 = 30;

struct State {
    config: Config,
    session: Option<Session>,
    last_activity: Instant,
}

/// Poignée partagée (bon marché à cloner) vers la fenêtre et l'état de l'application.
#[derive(Clone)]
pub struct App(Rc<Inner>);

pub struct Inner {
    window: adw::ApplicationWindow,
    nav: adw::NavigationView,
    toasts: adw::ToastOverlay,
    state: RefCell<State>,
}

impl std::ops::Deref for App {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl App {
    pub fn new(app: &adw::Application) -> Self {
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

        let this = Self(Rc::new(Inner {
            window,
            nav,
            toasts,
            state: RefCell::new(State {
                config: Config::load(),
                session: None,
                last_activity: Instant::now(),
            }),
        }));
        this.setup_actions();
        this.setup_auto_lock();
        this.restore_session();
        this
    }

    /// Au démarrage : restaure la session précédente (verrouillée) ou affiche la connexion.
    fn restore_session(&self) {
        let loading = adw::StatusPage::builder()
            .icon_name("dialog-password-symbolic")
            .title("Coffre")
            .build();
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

    pub fn toast(&self, message: &str) {
        self.toasts.add_toast(adw::Toast::new(message));
    }

    fn setup_actions(&self) {
        let logout = gio::SimpleAction::new("logout", None);
        let app = self.clone();
        logout.connect_activate(move |_, _| app.logout());
        self.window.add_action(&logout);

        let lock = gio::SimpleAction::new("lock", None);
        let app = self.clone();
        lock.connect_activate(move |_, _| app.lock());
        self.window.add_action(&lock);

        let about = gio::SimpleAction::new("about", None);
        let app = self.clone();
        about.connect_activate(move |_, _| {
            adw::AboutDialog::builder()
                .application_name("Coffre")
                .application_icon(crate::APP_ID)
                .version(env!("CARGO_PKG_VERSION"))
                .comments(
                    "Client Bitwarden adaptatif pour Phosh, bâti sur le SDK officiel Bitwarden.",
                )
                .license_type(gtk::License::Gpl30Only)
                .developer_name("Octopus AI")
                .build()
                .present(Some(&app.window));
        });
        self.window.add_action(&about);

        let new_item = gio::SimpleAction::new("new-item", None);
        let app = self.clone();
        new_item.connect_activate(move |_, _| {
            app.show_editor(None, ItemKind::Login, ItemDraft::default())
        });
        self.window.add_action(&new_item);

        let set_pin = gio::SimpleAction::new("set-pin", None);
        let app = self.clone();
        set_pin.connect_activate(move |_, _| login::set_pin_dialog(&app));
        self.window.add_action(&set_pin);

        let clear_pin = gio::SimpleAction::new("clear-pin", None);
        let app = self.clone();
        clear_pin.connect_activate(move |_, _| {
            if let Some(session) = app.session() {
                session.clear_pin();
                app.toast("NIP retiré");
                app.show_vault();
            }
        });
        self.window.add_action(&clear_pin);
    }

    /// Verrouille après `AUTO_LOCK_AFTER` sans interaction (tactile ou clavier).
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
            let expired = {
                let state = app.state.borrow();
                state.last_activity.elapsed() >= AUTO_LOCK_AFTER
                    && state.session.as_ref().is_some_and(Session::is_unlocked)
            };
            if expired {
                app.lock();
                app.toast("Coffre verrouillé après inactivité");
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

    // ----- Navigation -----

    pub fn show_login(&self) {
        let config = self.state.borrow().config.clone();
        self.nav.replace(&[login::login_page(self, &config)]);
    }

    fn show_two_factor(
        &self,
        session: Session,
        password: String,
        options: crate::backend::TwoFactorOptions,
    ) {
        self.nav
            .push(&login::two_factor_page(self, session, password, options));
    }

    fn show_vault(&self) {
        self.nav.replace(&[vault::vault_page(self)]);
    }

    fn show_lock(&self) {
        self.nav.replace(&[login::lock_page(self)]);
    }

    /// Page de modification (`id` fourni) ou de création (`id` absent).
    pub fn show_editor(&self, id: Option<String>, kind: ItemKind, draft: ItemDraft) {
        self.nav.push(&edit::edit_page(self, id, kind, draft));
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
                Ok::<_, crate::backend::Error>(session)
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
        let mut state = self.state.borrow_mut();
        state.config.server = server;
        state.config.email = email;
        state.config.save();
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

    pub fn sync(&self, done: impl FnOnce() + 'static) {
        let Some(mut session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move {
                session.sync().await?;
                Ok::<_, crate::backend::Error>(session)
            },
            move |result| {
                match result {
                    Ok(session) => {
                        app.set_session(Some(session));
                        app.show_vault();
                        app.toast("Coffre synchronisé");
                    }
                    Err(e) => app.toast(&e.to_string()),
                }
                done();
            },
        );
    }

    /// Synchronisation en arrière-plan après un déverrouillage; le coffre local
    /// reste utilisable hors ligne en cas d'échec.
    fn sync_quietly(&self) {
        let Some(mut session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move {
                session.sync().await?;
                Ok::<_, crate::backend::Error>(session)
            },
            move |result| match result {
                Ok(session) => {
                    let on_vault = app
                        .nav
                        .visible_page()
                        .and_then(|p| p.tag())
                        .is_some_and(|t| t == "vault");
                    app.set_session(Some(session));
                    if on_vault {
                        app.show_vault();
                    }
                }
                Err(crate::backend::Error::SessionExpired) => {
                    app.toast("Session expirée : déconnectez-vous puis reconnectez-vous pour synchroniser.");
                }
                Err(e) => eprintln!("synchronisation en arrière-plan : {e}"),
            },
        );
    }

    /// Enregistre un élément (création si `id` est absent), puis revient au coffre.
    fn save_item(
        &self,
        id: Option<String>,
        kind: ItemKind,
        draft: ItemDraft,
        done: impl FnOnce(bool) + 'static,
    ) {
        let Some(mut session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move {
                match id {
                    Some(id) => session.edit_item(&id, draft).await?,
                    None => session.create_item(kind, draft).await?,
                }
                Ok::<_, crate::backend::Error>(session)
            },
            move |result| match result {
                Ok(session) => {
                    app.set_session(Some(session));
                    app.show_vault();
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

    /// Envoie un élément à la corbeille, puis revient au coffre.
    fn trash_item(&self, id: String) {
        let Some(session) = self.session() else {
            return;
        };
        let app = self.clone();
        crate::spawn(
            async move { session.trash(&id).await },
            move |result| match result {
                Ok(()) => {
                    app.show_vault();
                    app.toast("Élément envoyé à la corbeille");
                }
                Err(e) => app.toast(&e.to_string()),
            },
        );
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

    /// Copie `value` puis efface le presse-papier après `CLIPBOARD_CLEAR_SECS`
    /// s'il contient toujours notre valeur.
    pub fn copy(&self, label: &str, value: &str) {
        let clipboard = self.window.clipboard();
        clipboard.set_text(value);
        self.toast(&format!(
            "{label} copié — effacé dans {CLIPBOARD_CLEAR_SECS} s"
        ));
        glib::timeout_add_seconds_local_once(CLIPBOARD_CLEAR_SECS, move || {
            if clipboard.is_local() {
                clipboard.set_text("");
            }
        });
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
    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .child(content)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(header);
    toolbar.set_content(Some(&scrolled));
    adw::NavigationPage::builder()
        .title(title)
        .tag(tag)
        .child(&toolbar)
        .build()
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
