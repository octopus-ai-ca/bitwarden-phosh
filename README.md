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

- Les éléments du coffre sont stockés **chiffrés** dans la base SQLite du SDK
  (`~/.local/share/coffre/vault.sqlite`, dossier en droits 0700) ; les clés déchiffrées
  ne vivent qu'en mémoire, dans le `KeyStore` du SDK.
- Cette base contient aussi les jetons d'accès et de rafraîchissement (comme le CLI
  officiel) : ils permettent de synchroniser, mais pas de déchiffrer le coffre sans le
  mot de passe maître.
- Verrouillage automatique après 5 minutes d'inactivité ; au redémarrage, l'application
  s'ouvre verrouillée et se déverrouille localement, sans réseau.
- Le NIP n'est gardé qu'en mémoire (oublié à la fermeture) et désactivé après 5 essais
  infructueux, comme l'option par défaut des clients officiels.
- Le presse-papier est vidé 30 secondes après une copie.
- La déconnexion efface toutes les données locales.

## Fonctionnalités (v0.2)

- [x] Connexion par mot de passe maître (bitwarden.com, .eu, auto-hébergé)
- [x] 2FA : application d'authentification ou courriel
- [x] Session conservée et coffre consultable hors ligne
- [x] Déverrouillage par NIP
- [x] Liste, recherche et détail (identifiant, mot de passe, TOTP, sites, carte, champs, notes)
- [x] Création et modification d'identifiants et de notes sécurisées
- [x] Générateur de mots de passe, historique des mots de passe, corbeille
- [x] Copie avec effacement automatique du presse-papier
- [x] Verrouillage automatique et manuel

Limites connues : pas de SSO, WebAuthn, YubiKey ni Duo ; l'option « se souvenir de cet
appareil » de la 2FA n'est pas exposée par le SDK (la 2FA n'est toutefois demandée qu'à
la première connexion) ; seuls les identifiants et les notes sécurisées sont modifiables ;
pas de pièces jointes ni de dossiers.

## Installation

Depuis la [page des publications](https://github.com/octopus-ai-ca/bitwarden-phosh/releases) :

```sh
# Flatpak (recommandé ; remplacer aarch64 par x86_64 selon l'appareil)
flatpak install --user coffre-aarch64.flatpak

# ou archive binaire (requiert GTK 4.14+ et libadwaita 1.5+)
tar xzf coffre-v0.2.0-linux-aarch64.tar.gz && ./coffre-v0.2.0-linux-aarch64/install.sh
```

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
# parcours complet contre un Vaultwarden local :
COFFRE_E2E_SERVER=http://127.0.0.1:8000 cargo test e2e -- --ignored
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
    ├── login.rs   Connexion, 2FA, déverrouillage (mot de passe ou NIP)
    ├── vault.rs   Liste et recherche
    ├── detail.rs  Détail d'un élément
    └── edit.rs    Création et modification
data/              .desktop, metainfo, icône
build-aux/         Manifeste Flatpak et sources Cargo
.github/workflows/ CI et publication (binaires + Flatpak, x86_64 et aarch64)
```
