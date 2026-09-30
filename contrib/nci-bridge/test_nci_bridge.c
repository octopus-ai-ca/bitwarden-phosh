/*
 * Tests du relais NCI, avec un HAL factice.
 *
 *   ./test_nci_bridge                         tests unitaires
 *   ./test_nci_bridge relay CLIENT CONTROLEUR  relais réel : le « HAL » est un
 *       contrôleur NCI simulé joignable sur le socket CONTROLEUR (utilisé par
 *       le test Rust `repli_nfc_via_pont_c` de Coffre).
 *
 * SPDX-License-Identifier: GPL-3.0-only OR Apache-2.0
 */
#define _GNU_SOURCE
#include "nci_bridge.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "%s:%d: échec : %s\n", __FILE__, __LINE__, #cond);     \
            exit(1);                                                               \
        }                                                                          \
    } while (0)

static int connect_unix(const char *path)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    return fd;
}

static int read_packet(int fd, uint8_t *buf)
{
    size_t got = 0, want = 3;
    while (got < want) {
        ssize_t n = read(fd, buf + got, want - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
        if (got == 3)
            want = 3 + buf[2];
    }
    return (int)want;
}

/* ----- Tests unitaires : HAL factice qui répond lui-même ----- */

static int connections, disconnections;
static uint8_t last_written[258];
static size_t last_written_len;

static void on_client(int connected, void *ctx)
{
    (void)ctx;
    if (connected)
        connections++;
    else
        disconnections++;
}

/* Répond OK à toute commande ; renvoie les données en écho. */
static int fake_hal_write(uint16_t len, const uint8_t *data)
{
    memcpy(last_written, data, len);
    last_written_len = len;
    if ((data[0] >> 5) == 1) {
        uint8_t rsp[4] = {(uint8_t)(0x40 | (data[0] & 0x0F)), data[1], 1, 0x00};
        nci_bridge_on_hal_data(sizeof(rsp), rsp);
    } else {
        nci_bridge_on_hal_data(len, data);
    }
    return 0;
}

static void wait_for(int *counter, int value)
{
    for (int i = 0; i < 200 && *counter < value; i++)
        usleep(10000);
    CHECK(*counter >= value);
}

static void unit_tests(void)
{
    /* Liste blanche. */
    const uint8_t discover[] = {0x21, 0x03, 0x03, 0x01, 0x00, 0x01};
    const uint8_t deactivate[] = {0x21, 0x06, 0x01, 0x00};
    const uint8_t data[] = {0x00, 0x00, 0x02, 0x90, 0x00};
    const uint8_t core_reset[] = {0x20, 0x00, 0x01, 0x00};
    const uint8_t proprietary[] = {0x2F, 0x01, 0x00};
    const uint8_t data_other_conn[] = {0x01, 0x00, 0x01, 0xAA};
    const uint8_t bad_length[] = {0x21, 0x06, 0x05, 0x00};
    CHECK(nci_bridge_packet_allowed(discover, sizeof(discover)));
    CHECK(nci_bridge_packet_allowed(deactivate, sizeof(deactivate)));
    CHECK(nci_bridge_packet_allowed(data, sizeof(data)));
    CHECK(!nci_bridge_packet_allowed(core_reset, sizeof(core_reset)));
    CHECK(!nci_bridge_packet_allowed(proprietary, sizeof(proprietary)));
    CHECK(!nci_bridge_packet_allowed(data_other_conn, sizeof(data_other_conn)));
    CHECK(!nci_bridge_packet_allowed(bad_length, sizeof(bad_length)));

    char path[] = "/tmp/nci-bridge-test-XXXXXX";
    CHECK(mkdtemp(path));
    char sock[128];
    snprintf(sock, sizeof(sock), "%s/nci.sock", path);
    CHECK(nci_bridge_start(sock, (gid_t)-1, fake_hal_write, on_client, NULL) == 0);

    struct stat st;
    CHECK(stat(sock, &st) == 0 && (st.st_mode & 0777) == 0660);

    /* Sans client, les paquets du HAL restent au démon. */
    CHECK(!nci_bridge_on_hal_data(sizeof(data), data));

    int fd = connect_unix(sock);
    CHECK(fd >= 0);
    wait_for(&connections, 1);
    CHECK(nci_bridge_client_connected());

    /* Commande autorisée → transmise au HAL → réponse relayée. */
    uint8_t buf[258];
    CHECK(write(fd, discover, sizeof(discover)) == sizeof(discover));
    CHECK(read_packet(fd, buf) == 4);
    CHECK(buf[0] == 0x41 && buf[1] == 0x03 && buf[3] == 0x00);
    CHECK(last_written_len == sizeof(discover));

    /* Données fragmentées en deux écritures → reçues d'un bloc. */
    CHECK(write(fd, data, 2) == 2);
    usleep(20000);
    CHECK(write(fd, data + 2, sizeof(data) - 2) == (ssize_t)sizeof(data) - 2);
    CHECK(read_packet(fd, buf) == (int)sizeof(data));
    CHECK(memcmp(buf, data, sizeof(data)) == 0);

    /* Paquet interdit → non transmis, client déconnecté, démon prévenu. */
    last_written_len = 0;
    CHECK(write(fd, core_reset, sizeof(core_reset)) == sizeof(core_reset));
    CHECK(read_packet(fd, buf) < 0);
    wait_for(&disconnections, 1);
    CHECK(last_written_len == 0);
    CHECK(!nci_bridge_client_connected());
    close(fd);

    /* Un nouveau client peut ensuite se connecter. */
    fd = connect_unix(sock);
    CHECK(fd >= 0);
    wait_for(&connections, 2);
    close(fd);
    wait_for(&disconnections, 2);

    nci_bridge_stop();
    CHECK(access(sock, F_OK) != 0);
    rmdir(path);
    printf("nci_bridge : tests unitaires réussis\n");
}

/* ----- Mode relais : le HAL est un contrôleur simulé sur un socket ----- */

static int controller_fd = -1;

/* En mode relais, la fin de la session de Coffre termine le programme. */
static void relay_on_client(int connected, void *ctx)
{
    (void)ctx;
    if (!connected)
        shutdown(controller_fd, SHUT_RDWR);
}

static int relay_hal_write(uint16_t len, const uint8_t *data)
{
    ssize_t n = send(controller_fd, data, len, MSG_NOSIGNAL);
    return n == len ? 0 : -1;
}

static void *controller_reader(void *arg)
{
    (void)arg;
    uint8_t buf[258];
    int len;
    while ((len = read_packet(controller_fd, buf)) > 0) {
        if (!nci_bridge_on_hal_data((uint16_t)len, buf))
            fprintf(stderr, "relais : paquet du contrôleur sans client\n");
    }
    return NULL;
}

static int relay(const char *client_sock, const char *controller_sock)
{
    for (int i = 0; i < 100 && controller_fd < 0; i++) {
        controller_fd = connect_unix(controller_sock);
        if (controller_fd < 0)
            usleep(50000);
    }
    CHECK(controller_fd >= 0);
    CHECK(nci_bridge_start(client_sock, (gid_t)-1, relay_hal_write, relay_on_client, NULL) == 0);
    printf("relais prêt\n");
    fflush(stdout);
    pthread_t reader;
    CHECK(pthread_create(&reader, NULL, controller_reader, NULL) == 0);
    pthread_join(reader, NULL); /* jusqu'à la déconnexion de Coffre */
    nci_bridge_stop();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "relay") == 0)
        return relay(argv[2], argv[3]);
    unit_tests();
    return 0;
}
