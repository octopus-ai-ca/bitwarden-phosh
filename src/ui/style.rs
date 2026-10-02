//! Thème visuel : palette bleu marine (mode sombre) inspirée de l'extension
//! Bitwarden, accent orange repris du logo de Coffre, listes en cartes séparées.

use adw::prelude::*;

use crate::config::{Config, Theme};

/// Règles communes aux deux modes.
const BASE_CSS: &str = r#"
/* Listes en cartes séparées, bordées, comme l'extension. */
list.cards {
    background: none;
}
list.cards > row {
    background-color: @card_bg_color;
    border: 1px solid @coffre_border;
    border-radius: 12px;
    margin-bottom: 8px;
}
list.cards > row:last-child {
    margin-bottom: 0;
}
list.cards > row.activatable:hover {
    background-color: mix(@card_bg_color, @window_fg_color, 0.04);
}
.compact list.cards > row {
    margin-bottom: 4px;
}
.compact list.cards > row > box.header {
    min-height: 40px;
    padding-top: 2px;
    padding-bottom: 2px;
}

/* Zones de texte (notes, Send, import) : bordées comme les cartes. */
textview.card {
    background-color: @card_bg_color;
    border: 1px solid @coffre_border;
    border-radius: 12px;
}
textview.card > text {
    background: none;
}

/* En-têtes de section : « Favoris  2 ». */
.section-title {
    font-weight: bold;
    font-size: 0.95em;
}
.section-count {
    opacity: 0.6;
}

/* Bouton d'action principal « + Créer ». */
button.create {
    border-radius: 999px;
    padding: 4px 14px;
    font-weight: bold;
}

/* Bandeau d'avertissement (corbeille). */
.warning-banner {
    border-radius: 12px;
    padding: 12px 14px;
    background-color: alpha(@warning_bg_color, 0.25);
    border: 1px solid alpha(@warning_bg_color, 0.6);
}

/* Mot de passe généré, chiffres et symboles colorés. */
.generated {
    font-family: monospace;
    font-size: 1.25em;
}

/* Pastille « Session en cours ». */
.pill-badge {
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 0.85em;
    background-color: alpha(@accent_bg_color, 0.2);
    color: @accent_color;
    border: 1px solid alpha(@accent_bg_color, 0.5);
}

/* Icônes de site dans les rangées. */
.site-icon {
    border-radius: 6px;
}
"#;

/// Palette sombre bleu marine.
const DARK_CSS: &str = r#"
@define-color window_bg_color #020a1c;
@define-color view_bg_color #020a1c;
@define-color headerbar_bg_color #0b1528;
@define-color headerbar_backdrop_color #0b1528;
@define-color sidebar_bg_color #0b1528;
@define-color card_bg_color #0d1830;
@define-color popover_bg_color #111d36;
@define-color dialog_bg_color #111d36;
@define-color thumbnail_bg_color #111d36;
@define-color coffre_border #1f2c47;
@define-color accent_bg_color #ff8c1a;
@define-color accent_fg_color #241000;
@define-color accent_color #ffa94d;
@define-color warning_bg_color #c2410c;
"#;

/// Palette claire.
const LIGHT_CSS: &str = r#"
@define-color coffre_border #d7dbe3;
@define-color accent_bg_color #e86a00;
@define-color accent_fg_color #ffffff;
@define-color accent_color #b85400;
"#;

thread_local! {
    static PROVIDERS: (gtk::CssProvider, gtk::CssProvider) = {
        let base = gtk::CssProvider::new();
        base.load_from_string(BASE_CSS);
        let palette = gtk::CssProvider::new();
        (base, palette)
    };
}

/// Installe les icônes intégrées et les feuilles de style, puis suit les
/// changements clair/sombre.
pub fn install() {
    let Some(display) = gtk::gdk::Display::default() else {
        return;
    };
    gtk::gio::resources_register_include!("coffre.gresource").expect("ressources intégrées");
    gtk::IconTheme::for_display(&display).add_resource_path("/ca/octopusai/Coffre/icons");
    PROVIDERS.with(|(base, palette)| {
        gtk::style_context_add_provider_for_display(
            &display,
            base,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        gtk::style_context_add_provider_for_display(
            &display,
            palette,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    });
    let manager = adw::StyleManager::default();
    update_palette(&manager);
    manager.connect_dark_notify(update_palette);
}

fn update_palette(manager: &adw::StyleManager) {
    let css = if manager.is_dark() {
        DARK_CSS
    } else {
        LIGHT_CSS
    };
    PROVIDERS.with(|(_, palette)| palette.load_from_string(css));
}

/// Applique le thème choisi.
pub fn apply(config: &Config) {
    adw::StyleManager::default().set_color_scheme(match config.theme {
        Theme::System => adw::ColorScheme::Default,
        Theme::Light => adw::ColorScheme::ForceLight,
        Theme::Dark => adw::ColorScheme::ForceDark,
    });
}

/// Logo de Coffre (losange orange), intégré au binaire.
pub fn logo_texture() -> Option<gtk::gdk::Texture> {
    let bytes = gtk::glib::Bytes::from_static(include_bytes!("../../data/logo.png"));
    gtk::gdk::Texture::from_bytes(&bytes).ok()
}

/// Image du logo, de `size` pixels de côté.
pub fn logo(size: i32) -> gtk::Picture {
    let picture = gtk::Picture::new();
    picture.set_paintable(logo_texture().as_ref());
    picture.set_can_shrink(true);
    picture.set_content_fit(gtk::ContentFit::Contain);
    picture.set_size_request(size, size);
    picture.set_halign(gtk::Align::Center);
    picture
}
