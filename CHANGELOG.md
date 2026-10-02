# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet
respecte le [versionnage sémantique](https://semver.org/lang/fr/).

## [0.5.0] - 2026-10-02

### Ajouté
- Nouvelle interface inspirée de l'extension Bitwarden : barre de navigation du bas
  (Coffre, Générateur, Send, Paramètres), listes en cartes, palette bleu marine en mode
  sombre et accent orange.
- Logo de Coffre (écrans de connexion, de verrouillage et d'à propos, icônes PNG).
- Coffre : bouton « + Créer », avatar du compte, recherche, filtres par dossier et par
  type, sections Favoris et Tous les éléments avec compteurs, icônes des sites, ouverture
  du site, copie rapide et menu ⋮ (copier, modifier, favori, archiver, supprimer).
- Générateur : mot de passe (5 à 128 caractères, jeux de caractères, minimums), phrase
  de passe et nom d'utilisateur, avec chiffres et symboles en couleur.
- Send : création de Send texte (durée, nombre d'accès, mot de passe), copie du lien,
  suppression.
- Paramètres : sécurité du compte (NIP, délai et action d'expiration, appareils, phrase
  d'empreinte, liens 2FA et mot de passe maître), options du coffre (dossiers, import
  Bitwarden JSON ou KeePass, export JSON/CSV/JSON protégé, archive, corbeille avec
  restauration et suppression définitive, synchronisation), apparence (thème, mode
  compact, icônes, copie rapide), presse-papier (délai d'effacement, copie automatique
  du TOTP), à propos et diagnostics NFC.
- Éditeur : choix du dossier et favori.

### Modifié
- Clé de sécurité : si la clé quitte le champ NFC après la saisie de son NIP, Coffre
  réessaie chaque seconde pendant 5 secondes sans redemander le NIP. Un NIP refusé n'est
  jamais réessayé, pour préserver les essais de la clé.

## [0.4.0] - 2026-09-30

### Ajouté
- Clé FIDO2 par la **puce NFC intégrée** du téléphone, en repli automatique lorsque
  `pcscd` est absent : Coffre dialogue en NCI (activation ISO-DEP, fragmentation,
  crédits) avec le démon NFC par un socket Unix, puis en CTAP-sur-NFC avec la clé.
- `contrib/nci-bridge/` : relais NCI en C à intégrer au démon qui détient le contrôleur
  (liste blanche des commandes, un client à la fois), avec guide pour le Galaxy A5 2017
  (`a5y17lte-nfcd`, HAL Samsung `sec-nfc`).

## [0.3.0] - 2026-09-29

### Ajouté
- Connexion en deux étapes par **clé de sécurité FIDO2 / WebAuthn**, par USB (hidraw) ou
  par NFC (lecteurs PC/SC), avec demande du NIP de la clé au besoin.
- Connexion en deux étapes par **YubiKey OTP** (la clé saisit le code par USB).
- Choix de la méthode lorsque le compte en propose plusieurs.
- Le paquet postmarketOS dépend de `libfido2-udev` (accès aux clés USB).

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

[0.4.0]: https://github.com/octopus-ai-ca/bitwarden-phosh/releases/tag/v0.4.0
[0.3.0]: https://github.com/octopus-ai-ca/bitwarden-phosh/releases/tag/v0.3.0
[0.2.1]: https://github.com/octopus-ai-ca/bitwarden-phosh/releases/tag/v0.2.1
[0.2.0]: https://github.com/octopus-ai-ca/bitwarden-phosh/releases/tag/v0.2.0
