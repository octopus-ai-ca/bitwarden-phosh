# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet
respecte le [versionnage sémantique](https://semver.org/lang/fr/).

## [0.2.1] - 2026-09-29

### Ajouté
- Paquet natif postmarketOS (`.apk` pour Alpine 3.24 / postmarketOS v26.06, aarch64 et
  x86_64) et son APKBUILD.

### Retiré
- Paquet Flatpak.

### Modifié
- Les messages d'information passent à la ligne au lieu d'être tronqués sur un écran de
  téléphone.
- Les archives binaires sont renommées `linux-glibc` : elles visent Debian, Ubuntu ou
  Fedora et ne fonctionnent pas sur postmarketOS (musl).

## [0.2.0] - 2026-09-29

Première version publiée.

### Ajouté
- Connexion par mot de passe maître à bitwarden.com, bitwarden.eu ou à un serveur
  auto-hébergé (Bitwarden, Vaultwarden), avec connexion en deux étapes par application
  d'authentification ou par courriel.
- Session conservée entre les lancements : l'application redémarre verrouillée et se
  déverrouille hors ligne ; la synchronisation reprend avec le jeton enregistré.
- Coffre hors ligne : les éléments restent chiffrés dans la base SQLite du SDK.
- Déverrouillage par NIP (4 à 12 chiffres), gardé en mémoire seulement et désactivé
  après 5 essais infructueux.
- Liste et recherche ; détail avec identifiant, mot de passe, code TOTP, sites, carte,
  champs personnalisés et notes.
- Création et modification d'identifiants et de notes sécurisées, générateur de mots de
  passe, historique des anciens mots de passe, envoi à la corbeille.
- Verrouillage automatique après 5 minutes d'inactivité ; presse-papier vidé après 30 s.
- Interface adaptative GTK4/libadwaita pour Phosh et GNOME ; paquet Flatpak et
  binaires x86_64 et aarch64.

[0.2.1]: https://github.com/octopus-ai-ca/bitwarden-phosh/releases/tag/v0.2.1
[0.2.0]: https://github.com/octopus-ai-ca/bitwarden-phosh/releases/tag/v0.2.0
