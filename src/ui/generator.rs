//! Onglet du générateur : mot de passe, phrase de passe ou nom d'utilisateur,
//! avec les chiffres et les symboles mis en couleur.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use super::{App, icon_button, scrolled, tab};
use crate::backend::{PassphraseOptions, PasswordOptions, UsernameOptions};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Password,
    Passphrase,
    Username,
}

/// Balisage Pango : chiffres en bleu, symboles en rouge orangé.
fn colorize(value: &str, dark: bool) -> String {
    let (digit, symbol) = if dark {
        ("#6cb4ff", "#ff7b72")
    } else {
        ("#0b62c4", "#c4321b")
    };
    let mut out = String::new();
    for c in value.chars() {
        let escaped = glib::markup_escape_text(&c.to_string()).to_string();
        if c.is_ascii_digit() {
            out.push_str(&format!("<span foreground=\"{digit}\">{escaped}</span>"));
        } else if !c.is_alphanumeric() {
            out.push_str(&format!("<span foreground=\"{symbol}\">{escaped}</span>"));
        } else {
            out.push_str(&escaped);
        }
    }
    out
}

fn switch_row(title: &str, active: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .use_markup(false)
        .active(active)
        .build()
}

fn spin_row(title: &str, min: f64, max: f64, value: f64) -> adw::SpinRow {
    let row = adw::SpinRow::with_range(min, max, 1.0);
    row.set_title(title);
    row.set_value(value);
    row
}

pub fn generator_tab(app: &App) -> adw::ToolbarView {
    let mode = Rc::new(RefCell::new(Mode::Password));
    let value = Rc::new(RefCell::new(String::new()));

    // Sélecteur de mode (boutons liés).
    // Non homogène : la largeur minimale reste celle du plus long mot de chaque bouton.
    let modes = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    modes.add_css_class("linked");
    let password_mode = gtk::ToggleButton::with_label("Mot de passe");
    let passphrase_mode = gtk::ToggleButton::with_label("Phrase de passe");
    let username_mode = gtk::ToggleButton::with_label("Nom d'utilisateur");
    passphrase_mode.set_group(Some(&password_mode));
    username_mode.set_group(Some(&password_mode));
    password_mode.set_active(true);
    for button in [&password_mode, &passphrase_mode, &username_mode] {
        if let Some(label) = button.child().and_downcast::<gtk::Label>() {
            // Passe à la ligne plutôt que d'être tronqué sur un écran étroit.
            label.set_wrap(true);
            label.set_justify(gtk::Justification::Center);
        }
        button.set_hexpand(true);
        modes.append(button);
    }

    // Valeur générée, avec régénérer et copier.
    let output = gtk::Label::builder()
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::Char)
        .selectable(true)
        .xalign(0.0)
        .hexpand(true)
        .build();
    output.add_css_class("generated");
    let regenerate = icon_button("view-refresh-symbolic", "Régénérer");
    let copy = icon_button("edit-copy-symbolic", "Copier");
    let output_box = gtk::Box::builder()
        .spacing(6)
        .margin_top(14)
        .margin_bottom(14)
        .margin_start(14)
        .margin_end(8)
        .build();
    output_box.append(&output);
    output_box.append(&regenerate);
    output_box.append(&copy);
    let output_card = gtk::Box::new(gtk::Orientation::Vertical, 0);
    output_card.add_css_class("card");
    output_card.append(&output_box);

    // Options du mot de passe.
    let defaults = PasswordOptions::default();
    let length = spin_row("Longueur", 5.0, 128.0, f64::from(defaults.length));
    length.set_subtitle("De 5 à 128 caractères");
    let upper = switch_row("Majuscules (A-Z)", defaults.uppercase);
    let lower = switch_row("Minuscules (a-z)", defaults.lowercase);
    let numbers = switch_row("Chiffres (0-9)", defaults.numbers);
    let special = switch_row("Caractères spéciaux (!@#$%^&*)", defaults.special);
    let min_numbers = spin_row(
        "Minimum de chiffres",
        0.0,
        9.0,
        f64::from(defaults.min_numbers),
    );
    let min_special = spin_row(
        "Minimum de caractères spéciaux",
        0.0,
        9.0,
        f64::from(defaults.min_special),
    );
    let ambiguous = switch_row("Éviter les caractères ambigus", defaults.avoid_ambiguous);
    let password_group = adw::PreferencesGroup::builder().title("Options").build();
    for row in [
        length.upcast_ref::<gtk::Widget>(),
        upper.upcast_ref(),
        lower.upcast_ref(),
        numbers.upcast_ref(),
        special.upcast_ref(),
        min_numbers.upcast_ref(),
        min_special.upcast_ref(),
        ambiguous.upcast_ref(),
    ] {
        password_group.add(row);
    }

    // Options de la phrase de passe.
    let phrase_defaults = PassphraseOptions::default();
    let words = spin_row(
        "Nombre de mots",
        3.0,
        20.0,
        f64::from(phrase_defaults.words),
    );
    let separator = adw::EntryRow::builder()
        .title("Séparateur de mots")
        .text(phrase_defaults.separator.as_str())
        .build();
    let capitalize = switch_row("Majuscule initiale", phrase_defaults.capitalize);
    let phrase_number = switch_row("Inclure un chiffre", phrase_defaults.include_number);
    let passphrase_group = adw::PreferencesGroup::builder()
        .title("Options")
        .visible(false)
        .build();
    passphrase_group.add(&words);
    passphrase_group.add(&separator);
    passphrase_group.add(&capitalize);
    passphrase_group.add(&phrase_number);

    // Options du nom d'utilisateur (mot aléatoire).
    let user_capitalize = switch_row("Majuscule initiale", false);
    let user_number = switch_row("Inclure un chiffre", false);
    let username_group = adw::PreferencesGroup::builder()
        .title("Mot aléatoire")
        .visible(false)
        .build();
    username_group.add(&user_capitalize);
    username_group.add(&user_number);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
    content.append(&modes);
    content.append(&output_card);
    content.append(&password_group);
    content.append(&passphrase_group);
    content.append(&username_group);

    let show = {
        let (output, value) = (output.clone(), value.clone());
        Rc::new(move |generated: String| {
            let dark = adw::StyleManager::default().is_dark();
            output.set_markup(&colorize(&generated, dark));
            *value.borrow_mut() = generated;
        })
    };

    let generate: Rc<dyn Fn()> = {
        let app = app.clone();
        let mode = mode.clone();
        let show = show.clone();
        let (length, upper, lower, numbers, special, min_numbers, min_special, ambiguous) = (
            length.clone(),
            upper.clone(),
            lower.clone(),
            numbers.clone(),
            special.clone(),
            min_numbers.clone(),
            min_special.clone(),
            ambiguous.clone(),
        );
        let (words, separator, capitalize, phrase_number) = (
            words.clone(),
            separator.clone(),
            capitalize.clone(),
            phrase_number.clone(),
        );
        let (user_capitalize, user_number) = (user_capitalize.clone(), user_number.clone());
        Rc::new(move || {
            let Some(session) = app.session() else {
                return;
            };
            let result = match *mode.borrow() {
                Mode::Password => {
                    // Au moins un jeu de caractères doit rester actif.
                    if !(upper.is_active()
                        || lower.is_active()
                        || numbers.is_active()
                        || special.is_active())
                    {
                        lower.set_active(true);
                    }
                    session.generate_with(&PasswordOptions {
                        length: length.value() as u8,
                        uppercase: upper.is_active(),
                        lowercase: lower.is_active(),
                        numbers: numbers.is_active(),
                        special: special.is_active(),
                        min_numbers: min_numbers.value() as u8,
                        min_special: min_special.value() as u8,
                        avoid_ambiguous: ambiguous.is_active(),
                    })
                }
                Mode::Passphrase => session.generate_passphrase(&PassphraseOptions {
                    words: words.value() as u8,
                    separator: separator.text().chars().take(1).collect(),
                    capitalize: capitalize.is_active(),
                    include_number: phrase_number.is_active(),
                }),
                Mode::Username => {
                    let options = UsernameOptions {
                        capitalize: user_capitalize.is_active(),
                        include_number: user_number.is_active(),
                    };
                    let show = show.clone();
                    app.with_session(
                        move |s| async move { s.generate_username(&options).await },
                        move |app, r| match r {
                            Ok(v) => show(v),
                            Err(e) => app.toast(&e.to_string()),
                        },
                    );
                    return;
                }
            };
            match result {
                Ok(v) => show(v),
                Err(e) => app.toast(&e.to_string()),
            }
        })
    };

    // Changement de mode.
    for (button, which) in [
        (&password_mode, Mode::Password),
        (&passphrase_mode, Mode::Passphrase),
        (&username_mode, Mode::Username),
    ] {
        let (mode, generate) = (mode.clone(), generate.clone());
        let groups = (
            password_group.clone(),
            passphrase_group.clone(),
            username_group.clone(),
        );
        button.connect_toggled(move |button| {
            if !button.is_active() {
                return;
            }
            *mode.borrow_mut() = which;
            groups.0.set_visible(which == Mode::Password);
            groups.1.set_visible(which == Mode::Passphrase);
            groups.2.set_visible(which == Mode::Username);
            generate();
        });
    }

    // Toute modification d'option régénère.
    for row in [&length, &min_numbers, &min_special, &words] {
        let generate = generate.clone();
        row.connect_value_notify(move |_| generate());
    }
    for row in [
        &upper,
        &lower,
        &numbers,
        &special,
        &ambiguous,
        &capitalize,
        &phrase_number,
        &user_capitalize,
        &user_number,
    ] {
        let generate = generate.clone();
        row.connect_active_notify(move |_| generate());
    }
    {
        let generate = generate.clone();
        separator.connect_changed(move |_| generate());
    }
    {
        let generate = generate.clone();
        regenerate.connect_clicked(move |_| generate());
    }
    {
        let (app, value, mode) = (app.clone(), value.clone(), mode.clone());
        copy.connect_clicked(move |_| {
            let label = match *mode.borrow() {
                Mode::Password => "Mot de passe",
                Mode::Passphrase => "Phrase de passe",
                Mode::Username => "Nom d'utilisateur",
            };
            app.copy(label, &value.borrow());
        });
    }
    generate();

    tab("Générateur", &adw::HeaderBar::new(), &scrolled(&content))
}

#[cfg(test)]
mod tests {
    use super::colorize;

    #[test]
    fn couleurs_des_chiffres_et_symboles() {
        let markup = colorize("a1&", true);
        assert!(markup.starts_with('a'));
        assert!(markup.contains(">1</span>"));
        assert!(markup.contains(">&amp;</span>"));
    }
}
