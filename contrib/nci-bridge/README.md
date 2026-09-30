# nci-bridge — puce NFC intégrée pour Coffre

Relais NCI minimal, à intégrer au démon qui détient le contrôleur NFC du téléphone.
Coffre s'en sert pour dialoguer avec une clé FIDO2 posée sur la puce NFC intégrée,
**en repli automatique quand `pcscd` n'est pas disponible**.

Cible de référence : Samsung Galaxy A5 2017 (`a5y17lte`), contrôleur S3NRN81, pilote
`sec-nfc`, HAL Samsung porté pour musl (`a5y17lte-nfc-hal`), démon `a5y17lte-nfcd`.

## Pourquoi un relais

Le pilote `sec-nfc` n'accepte **qu'un seul client** sur `/dev/sec-nfc`, et le démon
l'occupe déjà. Plutôt que de l'arrêter (droits root), le démon expose un socket Unix
qui relaie les trames NCI brutes. Toute la logique CTAP (activation ISO-DEP, APDU,
CBOR) reste dans Coffre ; le démon ne fait que relayer et filtrer.

## Protocole

- Socket : `/run/a5y17lte-nfc/nci.sock` (flux Unix), droits `0660`, groupe `nfc`.
  Coffre accepte un autre chemin via la variable `COFFRE_NCI_SOCKET`.
- Contenu : paquets NCI bruts dans les deux sens (en-tête de 3 octets, le 3ᵉ donnant
  la longueur de la charge utile). Aucun encadrement supplémentaire.
- **Un seul client à la fois.** Les connexions suivantes attendent leur tour.
- Pendant qu'un client est connecté :
  - chaque paquet reçu du HAL (réponses, notifications, données) lui est relayé, et
    le démon ne le traite pas ;
  - le démon n'envoie plus ses propres commandes ;
  - les paquets du client sont transmis au HAL **après filtrage** : seuls passent les
    paquets de données sur la connexion RF statique (0) et les commandes
    `RF_DISCOVER_MAP`, `RF_DISCOVER`, `RF_DISCOVER_SELECT` et `RF_DEACTIVATE`. Tout
    autre paquet (`CORE_RESET`, commandes propriétaires, micrologiciel…) entraîne la
    déconnexion du client sans rien transmettre.
- À la déconnexion, le démon remet le RF au repos puis relance sa propre découverte.

Le contrôleur est supposé déjà initialisé par le démon (`CORE_RESET`/`CORE_INIT`,
`nfc_hal_core_initialized`, `nfc_hal_pre_discover`) ; le client ne le réinitialise
jamais.

### Ce que fait Coffre

1. `RF_DEACTIVATE` (repos) ;
2. `RF_DISCOVER_MAP` : protocole ISO-DEP en mode lecteur → interface ISO-DEP ;
3. `RF_DISCOVER` : NFC-A, lecteur passif ;
4. attend `RF_INTF_ACTIVATED_NTF` avec l'interface ISO-DEP (une étiquette simple est
   ignorée et la découverte reprend ; avec plusieurs cartes, `RF_DISCOVER_SELECT` de la
   première ISO-DEP) ;
5. échange les APDU CTAP-sur-NFC en paquets de données sur la connexion 0, en
   respectant la taille maximale et les crédits annoncés (`CORE_CONN_CREDITS_NTF`) ;
6. ferme le socket.

## Intégration dans `a5y17lte-nfcd`

Ajouter `nci_bridge.c` et `nci_bridge.h` aux sources du démon (C ou C++), lier avec
`-pthread`, puis :

```cpp
#include <grp.h>
#include <atomic>
#include "nci_bridge.h"

static std::atomic<bool> bridge_active{false};

// Appelé par le pont (depuis son propre fil).
static void on_bridge_client(int connected, void *) {
    bridge_active = connected;
    if (!connected) {
        // Remettre le RF au repos puis relancer la découverte habituelle du démon.
        static const uint8_t deactivate_idle[] = {0x21, 0x06, 0x01, 0x00};
        nfc_hal_write(sizeof(deactivate_idle), deactivate_idle);
        restart_discovery();  // la séquence RF_DISCOVER_MAP / RF_DISCOVER existante
    }
}

// Rappel de données du HAL (nfc_stack_data_callback_t).
static void hal_data_callback(uint16_t len, uint8_t *data) {
    if (nci_bridge_on_hal_data(len, data))
        return;  // relayé à Coffre
    // … traitement existant (UID du tag, trames affichées) …
}

// Après l'ouverture du HAL, CORE_INIT et le lancement de la découverte :
struct group *nfc = getgrnam("nfc");
if (nci_bridge_start("/run/a5y17lte-nfc/nci.sock", nfc ? nfc->gr_gid : (gid_t)-1,
                     nfc_hal_write, on_bridge_client, nullptr) != 0)
    perror("nci_bridge_start");
// … à l'arrêt : nci_bridge_stop();
```

`nfc_hal_write(uint16_t, const uint8_t *)` a exactement la signature attendue. Tant que
`bridge_active` est vrai, le démon ne doit plus envoyer ses propres commandes NCI.

Selon la façon dont la réponse du HAL est livrée : le pont suppose **un paquet NCI par
appel** du rappel de données (comportement du HAL Samsung). Si le démon reçoit des
fragments, il doit les rassembler avant d'appeler `nci_bridge_on_hal_data`.

### Service OpenRC

Créer le dossier du socket au démarrage du service, par exemple dans `start_pre` :

```sh
checkpath -d -m 0750 -o root:nfc /run/a5y17lte-nfc
```

L'utilisateur de Coffre doit être membre du groupe `nfc` :

```sh
doas adduser "$USER" nfc   # puis se reconnecter
```

## Tests

```sh
make -C contrib/nci-bridge check          # liste blanche, relais, déconnexions
# Parcours complet Coffre → pont C → contrôleur simulé → clé FIDO simulée :
make -C contrib/nci-bridge test_nci_bridge
COFFRE_NCI_BRIDGE=contrib/nci-bridge/test_nci_bridge cargo test pont_c -- --ignored
```

Sur le téléphone, une fois le démon mis à jour :

```sh
ls -l /run/a5y17lte-nfc/nci.sock          # srw-rw---- root nfc
# Arrêter pcscd s'il tourne (le repli ne s'active que sans lui), puis dans Coffre :
# 2FA → « Clé de sécurité » → poser la clé FIDO2 au dos du téléphone.
```

## Points à vérifier sur le matériel

Rien de ceci n'a pu être essayé sur le Galaxy A5 : le code a été validé contre un
contrôleur NCI simulé et à travers ce relais.

- Que le S3NRN81 et la configuration RF du HAL (`sec_s3nrn81_rfreg.bin`) acceptent
  l'activation **ISO-DEP** en mode lecteur (le bring-up actuel lit l'UID des tags
  Type A ; une clé FIDO2 exige ISO 14443-4).
- La taille maximale des paquets et les crédits annoncés dans
  `RF_INTF_ACTIVATED_NTF` (Coffre s'y adapte).
- Le délai de l'échange CTAP : une assertion prend de 100 à 500 ms sur une clé NFC ;
  la clé doit rester posée jusqu'à la fin.
