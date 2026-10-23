/*
 * HTTP Server for PS5 WebKit Remote Loader Installer ELF.
 *
 * Serves the embedded files from the generated file registry and handles
 * the /install route which registers the homescreen app once caching completes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <microhttpd.h>

#include "wkrli.h"
#include "http_server.h"
#include "file_registry.h"
#include "inflate.h"
#include "app_installer.h"
#include "webkit_cleaner.h"

#define CORS_ORIGIN "*"

atomic_int http_keep_running = 1;
atomic_int install_completed = 0;
atomic_int webkit_data_cleared = 0;

static void add_cors_headers(struct MHD_Response *resp) {
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", CORS_ORIGIN);
}

static const FileEntry *registry_lookup(const char *url) {
    if (strcmp(url, ROUTE_INDEX) == 0)
        return file_registry_find(ROUTE_INDEX_HTML);
    return file_registry_find(url);
}

enum MHD_Result http_on_request(void *cls, struct MHD_Connection *conn,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;

    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp =
            MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(resp);
        MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (*con_cls == NULL) {
        *con_cls = (void *)1;
        return MHD_YES;
    }

    struct MHD_Response *resp = NULL;
    int http_status = MHD_HTTP_OK;

    if (strcmp(url, ROUTE_INSTALL) == 0) {
        int err = installer_install_app_if_needed();
        if (err == 0) {
            installer_log("[WKRLI] App installed. Stopping server...\n");
            resp = MHD_create_response_from_buffer(strlen("OK"), (void *)"OK",
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_OK;
            atomic_store(&install_completed, 1);
            atomic_store(&http_keep_running, 0);
        } else {
            installer_log("[WKRLI] App install failed (%d).\n", err);
            const char *fail = "Install failed";
            resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail,
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else if (strcmp(url, ROUTE_EXIT) == 0) {
        installer_log("[WKRLI] Exit requested.\n");
        resp = MHD_create_response_from_buffer(2, (void *)"OK", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        http_status = MHD_HTTP_OK;
        atomic_store(&http_keep_running, 0);
    } else if (strcmp(url, ROUTE_VERSION) == 0) {
        resp = MHD_create_response_from_buffer(strlen(WKRLI_FULL_VERSION),
                                               (void *)WKRLI_FULL_VERSION,
                                               MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        extern int sceUserServiceGetForegroundUser(int *);
        int uid = -1;
        if (sceUserServiceGetForegroundUser(&uid) == 0 && uid > 0) {
            char uid_hdr[32];
            snprintf(uid_hdr, sizeof(uid_hdr), "%08x", (unsigned int)uid);
            MHD_add_response_header(resp, "X-User-Id", uid_hdr);
        }
    } else if (strcmp(url, "/logs") == 0) {
        const char *pos_str = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "pos");
        size_t pos = 0;
        if (pos_str) pos = (size_t)strtoull(pos_str, NULL, 10);

        char *logs = malloc(16384 + 64);
        if (logs) {
            size_t copied = installer_wait_logs(&pos, logs, 16384);
            resp = MHD_create_response_from_buffer(copied, (void *)logs, MHD_RESPMEM_MUST_FREE);
            char pos_hdr[64];
            snprintf(pos_hdr, sizeof(pos_hdr), "%zu", pos);
            MHD_add_response_header(resp, "X-Log-Pos", pos_hdr);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
        } else {
            const char *oom = "500 Internal Server Error\n";
            resp = MHD_create_response_from_buffer(strlen(oom), (void *)oom, MHD_RESPMEM_PERSISTENT);
        }
    } else if (strcmp(url, ROUTE_CLEAR_WEBKIT_DATA) == 0) {
        int err = installer_clear_webkit_data();
        if (err == 0) {
            installer_log("[WKRLI] WebKit data cleared successfully.\n");
            resp = MHD_create_response_from_buffer(2, (void *)"OK", MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_OK;
            atomic_store(&webkit_data_cleared, 1);
        } else {
            installer_log("[WKRLI] WebKit data clear failed.\n");
            const char *fail = "Clear failed";
            resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        const FileEntry *entry = registry_lookup(url);
        if (entry) {
            void *payload = (void *)entry->data;
            size_t payload_size = entry->size;
            enum MHD_ResponseMemoryMode mem_mode = MHD_RESPMEM_PERSISTENT;
            unsigned char *decompressed = NULL;

            if (entry->compressed) {
                if (entry->orig_size > WKRLI_MAX_DECOMPRESSED_SIZE) {
                    const char *too_large = "500 Decompressed Size Too Large\n";
                    resp = MHD_create_response_from_buffer(strlen(too_large), (void *)too_large, MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    add_cors_headers(resp);
                    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                decompressed = malloc(entry->orig_size + 1);
                if (!decompressed) {
                    const char *oom = "503 Out of Memory\n";
                    resp = MHD_create_response_from_buffer(strlen(oom), (void *)oom, MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    add_cors_headers(resp);
                    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_SERVICE_UNAVAILABLE, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                unsigned long destlen = entry->orig_size;
                unsigned long sourcelen = entry->size;
                int err = puff(decompressed, &destlen, entry->data, &sourcelen);
                if (err != 0) {
                    free(decompressed);
                    const char *bad = "500 Inflate Error\n";
                    resp = MHD_create_response_from_buffer(strlen(bad), (void *)bad, MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    add_cors_headers(resp);
                    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                decompressed[destlen] = '\0';
                payload = decompressed;
                payload_size = destlen;
                mem_mode = MHD_RESPMEM_MUST_FREE;
            }

            resp = MHD_create_response_from_buffer(payload_size, payload, mem_mode);
            MHD_add_response_header(resp, "Content-Type", entry->content_type);
            if (strcmp(url, ROUTE_CACHE_MANIFEST) == 0 ||
                strstr(entry->content_type, "text/html") != NULL) {
                MHD_add_response_header(resp, "Cache-Control", "no-cache, must-revalidate");
            }
        } else {
            const char *not_found = "404 Not Found\n";
            resp = MHD_create_response_from_buffer(strlen(not_found), (void *)not_found, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_NOT_FOUND;
        }
    }

    if (!resp) return MHD_NO;

    add_cors_headers(resp);
    enum MHD_Result ret = MHD_queue_response(conn, http_status, resp);
    MHD_destroy_response(resp);
    return ret;
}
