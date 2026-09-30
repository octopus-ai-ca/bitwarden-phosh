/*
 * nci_bridge — relais NCI sur socket Unix. Voir nci_bridge.h.
 *
 * SPDX-License-Identifier: GPL-3.0-only OR Apache-2.0
 */
#define _GNU_SOURCE
#include "nci_bridge.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

/* Types de message et identifiants NCI. */
#define NCI_MT_DATA 0
#define NCI_MT_CMD 1
#define NCI_GID_RF 1
#define NCI_OID_RF_DISCOVER_MAP 0x00
#define NCI_OID_RF_DISCOVER 0x03
#define NCI_OID_RF_DISCOVER_SELECT 0x04
#define NCI_OID_RF_DEACTIVATE 0x06
#define NCI_STATIC_RF_CONN 0
#define NCI_HEADER_LEN 3

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t thread;
static int thread_started;
static int listen_fd = -1;
static int client_fd = -1;
static volatile int stopping;
static char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static nci_bridge_write_fn write_fn;
static nci_bridge_client_fn client_fn;
static void *client_ctx;

int nci_bridge_packet_allowed(const uint8_t *packet, size_t len)
{
    if (len < NCI_HEADER_LEN || len != (size_t)NCI_HEADER_LEN + packet[2])
        return 0;
    uint8_t mt = packet[0] >> 5;
    uint8_t gid = packet[0] & 0x0F;
    uint8_t oid = packet[1] & 0x3F;
    if (mt == NCI_MT_DATA)
        return gid == NCI_STATIC_RF_CONN;
    if (mt == NCI_MT_CMD && gid == NCI_GID_RF)
        return oid == NCI_OID_RF_DISCOVER_MAP || oid == NCI_OID_RF_DISCOVER ||
               oid == NCI_OID_RF_DISCOVER_SELECT || oid == NCI_OID_RF_DEACTIVATE;
    /* Tout le reste (CORE_RESET, commandes propriétaires, micrologiciel…) est refusé. */
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = read(fd, buf, len);
        if (n == 0)
            return -1; /* fin de flux */
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_full(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

int nci_bridge_on_hal_data(uint16_t len, const uint8_t *data)
{
    int forwarded = 0;
    pthread_mutex_lock(&lock);
    if (client_fd >= 0) {
        forwarded = 1;
        if (send_full(client_fd, data, len) < 0) {
            /* Client disparu : le fil d'écoute le constatera à la lecture. */
            shutdown(client_fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&lock);
    return forwarded;
}

int nci_bridge_client_connected(void)
{
    pthread_mutex_lock(&lock);
    int connected = client_fd >= 0;
    pthread_mutex_unlock(&lock);
    return connected;
}

/* Relaie les paquets du client vers le HAL jusqu'à la déconnexion. */
static void serve_client(int fd)
{
    uint8_t packet[NCI_HEADER_LEN + 255];
    for (;;) {
        if (read_full(fd, packet, NCI_HEADER_LEN) < 0)
            break;
        size_t len = NCI_HEADER_LEN + packet[2];
        if (read_full(fd, packet + NCI_HEADER_LEN, packet[2]) < 0)
            break;
        if (!nci_bridge_packet_allowed(packet, len)) {
            fprintf(stderr, "nci_bridge: paquet refusé %02x %02x, client déconnecté\n",
                    packet[0], packet[1]);
            break;
        }
        if (write_fn((uint16_t)len, packet) != 0) {
            fprintf(stderr, "nci_bridge: échec d'écriture vers le HAL\n");
            break;
        }
    }
}

static void *listen_thread(void *arg)
{
    (void)arg;
    while (!stopping) {
        int fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            break; /* socket fermé par nci_bridge_stop */
        }
        /* Un client qui ne lit plus ne doit pas bloquer le rappel du HAL. */
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        /* Un seul client : les connexions suivantes attendent dans la file. */
        pthread_mutex_lock(&lock);
        client_fd = fd;
        pthread_mutex_unlock(&lock);
        if (client_fn)
            client_fn(1, client_ctx);

        serve_client(fd);

        pthread_mutex_lock(&lock);
        client_fd = -1;
        close(fd);
        pthread_mutex_unlock(&lock);
        if (client_fn)
            client_fn(0, client_ctx);
    }
    return NULL;
}

int nci_bridge_start(const char *path, gid_t group, nci_bridge_write_fn hal_write,
                     nci_bridge_client_fn on_client, void *ctx)
{
    struct sockaddr_un addr;
    if (!path || !hal_write || strlen(path) >= sizeof(addr.sun_path) || thread_started) {
        errno = EINVAL;
        return -1;
    }
    write_fn = hal_write;
    client_fn = on_client;
    client_ctx = ctx;
    stopping = 0;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    strcpy(socket_path, path);

    listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0)
        return -1;
    unlink(path);
    /* Droits restreints dès la création, puis 0660 + groupe. */
    mode_t old_mask = umask(0177);
    int rc = bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_mask);
    if (rc < 0 || (group != (gid_t)-1 && chown(path, (uid_t)-1, group) < 0) ||
        chmod(path, 0660) < 0 || listen(listen_fd, 1) < 0) {
        int saved = errno;
        close(listen_fd);
        listen_fd = -1;
        unlink(path);
        errno = saved;
        return -1;
    }
    if (pthread_create(&thread, NULL, listen_thread, NULL) != 0) {
        close(listen_fd);
        listen_fd = -1;
        unlink(path);
        errno = EAGAIN;
        return -1;
    }
    thread_started = 1;
    return 0;
}

void nci_bridge_stop(void)
{
    if (!thread_started)
        return;
    stopping = 1;
    shutdown(listen_fd, SHUT_RDWR);
    pthread_mutex_lock(&lock);
    if (client_fd >= 0)
        shutdown(client_fd, SHUT_RDWR);
    pthread_mutex_unlock(&lock);
    pthread_join(thread, NULL);
    close(listen_fd);
    listen_fd = -1;
    unlink(socket_path);
    thread_started = 0;
}
