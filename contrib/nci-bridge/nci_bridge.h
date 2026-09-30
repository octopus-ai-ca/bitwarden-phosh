/*
 * nci_bridge — relais NCI sur socket Unix pour un démon NFC qui détient le
 * contrôleur (p. ex. a5y17lte-nfcd, pilote Samsung sec-nfc à client unique).
 *
 * Un seul client à la fois (Coffre). Pendant qu'il est connecté :
 *   - chaque paquet NCI reçu du HAL lui est relayé tel quel ;
 *   - ses paquets sont transmis au HAL après filtrage (liste blanche :
 *     données sur la connexion RF statique et commandes RF_DISCOVER_MAP,
 *     RF_DISCOVER, RF_DISCOVER_SELECT, RF_DEACTIVATE).
 * À la déconnexion, le démon est prévenu pour relancer sa propre découverte.
 *
 * Protocole : flux d'octets de paquets NCI bruts (en-tête de 3 octets, le
 * troisième donnant la longueur de la charge utile), dans les deux sens.
 *
 * SPDX-License-Identifier: GPL-3.0-only OR Apache-2.0
 */
#ifndef NCI_BRIDGE_H
#define NCI_BRIDGE_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Écrit un paquet NCI vers le contrôleur (typiquement nfc_hal_write). */
typedef int (*nci_bridge_write_fn)(uint16_t len, const uint8_t *data);

/*
 * Appelé (depuis le fil du pont) quand un client se connecte (connected = 1)
 * ou se déconnecte (connected = 0). À la connexion, le démon doit cesser
 * d'envoyer ses propres commandes ; à la déconnexion, remettre le RF au
 * repos (RF_DEACTIVATE) puis relancer sa découverte habituelle.
 */
typedef void (*nci_bridge_client_fn)(int connected, void *ctx);

/*
 * Crée le socket `path` (droits 0660, groupe `group` si différent de
 * (gid_t)-1) et lance le fil d'écoute. Retourne 0, ou -1 (errno positionné).
 */
int nci_bridge_start(const char *path, gid_t group, nci_bridge_write_fn hal_write,
                     nci_bridge_client_fn on_client, void *ctx);

/*
 * À appeler depuis le rappel de données du HAL pour chaque paquet NCI reçu.
 * Retourne 1 si le paquet a été relayé au client (le démon ne doit alors pas
 * le traiter), 0 si aucun client n'est connecté.
 */
int nci_bridge_on_hal_data(uint16_t len, const uint8_t *data);

/* Vrai si un client est connecté. */
int nci_bridge_client_connected(void);

/* Ferme le client et le socket, attend la fin du fil d'écoute. */
void nci_bridge_stop(void);

/* Exposé pour les tests : 1 si le paquet client est autorisé. */
int nci_bridge_packet_allowed(const uint8_t *packet, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NCI_BRIDGE_H */
