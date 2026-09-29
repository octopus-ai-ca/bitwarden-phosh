# Coffre

Client Bitwarden adaptatif pour **Phosh** (téléphones Linux) et GNOME, écrit en Rust avec
GTK4 et libadwaita. Compatible avec **bitwarden.com**, **bitwarden.eu** et les serveurs
**auto-hébergés** (Bitwarden, Vaultwarden).

> Projet non officiel, sans lien avec Bitwarden Inc.

## Architecture

| Couche | Technologie |
|---|---|
| Interface | GTK4 4.14+, libadwaita 1.5+ (`AdwNavigationView`, pages adaptatives dès 360 px) |
| Authentification, synchro, crypto | [SDK officiel Bitwarden](https://github.com/bitwarden/sdk-internal) (`bitwarden-core`, `bitwarden-vault`, `bitwarden-crypto`) |
| Réseau asynchrone | Tokio (le SDK utilise reqwest) |

L'UX s'inspire de l'application Android officielle
([bitwarden/android](https://github.com/bitwarden/android), Kotlin/Compose).

### Licence du SDK

Les crates de `sdk-internal/crates/` sont sous double licence
`GPL-3.0-only OR LicenseRef-Bitwarden-SDK`. Coffre les utilise **sous l'option GPL-3.0** et est
donc lui-même distribué sous **GPL-3.0-only**. Les crates de `bitwarden_license/` (licence SDK
seule) ne sont pas utilisées. Le SDK n'étant pas publié sur crates.io, il est tiré du dépôt Git
à un commit fixé dans `Cargo.toml`.

### Sécurité

- Seules des données **chiffrées** (éléments, clés protégées) restent en mémoire après la
  synchro ; les clés déchiffrées vivent dans le `KeyStore` du SDK.
- Verrouillage automatique après 5 minutes d'inactivité (efface les clés) ; le
  déverrouillage se fait localement, sans réseau.
- Le presse-papier est vidé 30 secondes après une copie.
- Rien de sensible n'est écrit sur disque : `~/.config/coffre/config.json` ne contient que le
  serveur, le courriel et l'identifiant d'appareil.

## Premier jalon (v0.1)

- [x] Connexion par mot de passe maître (bitwarden.com, .eu, auto-hébergé)
- [x] 2FA : application d'authentification ou courriel
- [x] Synchronisation et liste du coffre (recherche)
- [x] Détail : identifiant, mot de passe, TOTP, sites, carte, champs, notes
- [x] Copie avec effacement automatique du presse-papier
- [x] Verrouillage automatique et manuel

Limites connues : la session n'est pas conservée entre les lancements (connexion, et 2FA,
à chaque démarrage) ; consultation en lecture seule ; pas de SSO, WebAuthn, YubiKey ni Duo.

## Compilation

Dépendances (Debian/Mobian/Ubuntu) :

```sh
sudo apt install build-essential pkg-config libgtk-4-dev libadwaita-1-dev
```

Rust 1.88 ou plus récent est requis (exigence du SDK).

```sh
cargo run            # développement
cargo test           # tests unitaires
cargo test -- --ignored   # test réseau réel contre bitwarden.com
```

### Flatpak (x86_64 et aarch64)

```sh
flatpak-builder --user --install --force-clean build-dir build-aux/ca.octopusai.Coffre.json
flatpak run ca.octopusai.Coffre
```

Après toute modification de `Cargo.lock`, régénérer les sources hors ligne :

```sh
python3 flatpak-cargo-generator.py Cargo.lock -o build-aux/cargo-sources.json
```

(script disponible dans [flatpak-builder-tools](https://github.com/flatpak/flatpak-builder-tools/tree/master/cargo)).

Le fichier `.desktop` déclare `X-Purism-FormFactor=Workstation;Mobile;` pour que Phosh
affiche l'application en mode téléphone.

## Structure

```
src/
├── main.rs        Point d'entrée, pont Tokio ↔ boucle GLib
├── backend.rs     Session SDK : connexion, 2FA, synchro, (dé)verrouillage, déchiffrement
├── config.rs      Préférences non sensibles
└── ui/
    ├── mod.rs     Fenêtre, navigation, verrouillage auto, presse-papier
    ├── login.rs   Connexion, 2FA, déverrouillage
    ├── vault.rs   Liste et recherche
    └── detail.rs  Détail d'un élément
data/              .desktop, metainfo, icône
build-aux/         Manifeste Flatpak et sources Cargo
```
