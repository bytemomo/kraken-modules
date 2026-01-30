#define KRAKEN_MODULE_BUILD

#include <kraken_module_abi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/select.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION = KRAKEN_ABI_VERSION;

#ifndef TLS1_VERSION
#define TLS1_VERSION 0
#endif
#ifndef TLS1_1_VERSION
#define TLS1_1_VERSION 0
#endif
#ifndef TLS1_2_VERSION
#define TLS1_2_VERSION 0
#endif
#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0
#endif


static int parse_tls_version(const char *vstr) {
    if (!vstr)
        return -1;
    char buf[16];
    size_t n = strlen(vstr);
    if (n >= sizeof(buf))
        return -1;
    for (size_t i = 0; i < n; i++)
        buf[i] = (char)tolower((unsigned char)vstr[i]);
    buf[n] = '\0';

    if (strcmp(buf, "tls1.0") == 0 || strcmp(buf, "1.0") == 0)
        return TLS1_VERSION;
    if (strcmp(buf, "tls1.1") == 0 || strcmp(buf, "1.1") == 0)
        return TLS1_1_VERSION;
    if (strcmp(buf, "tls1.2") == 0 || strcmp(buf, "1.2") == 0)
        return TLS1_2_VERSION;
    if (strcmp(buf, "tls1.3") == 0 || strcmp(buf, "1.3") == 0)
        return TLS1_3_VERSION;
    return -1;
}

static int try_tls_version(const char *host, uint16_t port, const char *sni, int version, uint32_t timeout_ms) {
    if (version == 0) {
        return -1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return 0;

   
    SSL_CTX_set_min_proto_version(ctx, version);
    SSL_CTX_set_max_proto_version(ctx, version);

    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        SSL_CTX_free(ctx);
        return 0;
    }

    char target[256];
    snprintf(target, sizeof(target), "%s:%u", host, port);
    BIO_set_conn_hostname(bio, target);

   
    BIO_set_nbio(bio, 1);

    SSL *ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    if (ssl) {
       
        SSL_set_tlsext_host_name(ssl, sni ? sni : (char *)host);
    }

   
    long timeout_sec = timeout_ms > 0 ? (long)((timeout_ms + 999) / 1000) : 10;
    time_t start = time(NULL);
    int ok = 0;

    while (1) {
        int ret = BIO_do_connect(bio);
        if (ret == 1) {
            ok = 1;
            break;
        }
        if (!BIO_should_retry(bio)) {
            break;
        }
        if (time(NULL) - start >= timeout_sec) {
            break;
        }
        struct timeval tv = {0, 100000};
        select(0, NULL, NULL, NULL, &tv);
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return ok ? 1 : 0;
}

static const char *status_str(int v) {
    if (v == -1)
        return "not_available";
    if (v == -2)
        return "skipped";
    return v ? "supported" : "not_supported";
}


KRAKEN_API int kraken_run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

   
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

   
    char *min_version_str = json_extract_string(params_json, "min_version");
    char *max_version_str = json_extract_string(params_json, "max_version");
    char *sni_override = json_extract_string(params_json, "sni");
    int min_version = parse_tls_version(min_version_str);
    int max_version = parse_tls_version(max_version_str);

   
    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(host);
    result->target.port = (uint16_t)port;

   
    const int versions_to_check[] = {TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION};
    const char *version_names[] = {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"};
    const char *version_keys[] = {"tls1.0", "tls1.1", "tls1.2", "tls1.3"};
    int results[4];

    uint32_t op_timeout = timeout_ms > 0 ? timeout_ms : 10000;

    for (int i = 0; i < 4; ++i) {
        int ver = versions_to_check[i];
        if (ver == 0) {
            results[i] = -1;
        } else if (min_version > 0 && ver < min_version) {
            results[i] = -2;
        } else if (max_version > 0 && ver > max_version) {
            results[i] = -2;
        } else {
            results[i] = try_tls_version(host, (uint16_t)port, sni_override ? sni_override : host, ver, op_timeout);
        }
        char log_buf[160];
        snprintf(log_buf, sizeof(log_buf), "Check %s: %s", version_names[i], status_str(results[i]));
        add_log(result, log_buf);
    }

   
    result->findings_count = 1;
    result->findings = (KrakenFinding *)calloc(1, sizeof(KrakenFinding));
    KrakenFinding *f = &result->findings[0];

    f->id = mystrdup("TLS-SUPPORT-OVERVIEW");
    f->module_id = mystrdup("tls_version_check");
    f->success = true;
    f->title = mystrdup("TLS Protocol Support Summary");
    int weak = (results[0] == 1 || results[1] == 1) ? 1 : 0;
    f->severity = mystrdup(weak ? "medium" : "info");
    f->description = mystrdup(weak ? "Weak TLS protocol versions accepted (1.0/1.1). Review hardening." : "TLS protocol support summary.");
    f->timestamp = time(NULL);
    f->target.host = mystrdup(host);
    f->target.port = (uint16_t)port;

   
    f->evidence.count = 4;
    f->evidence.items = (KrakenKeyValue *)malloc(4 * sizeof(KrakenKeyValue));
    for (int i = 0; i < 4; ++i) {
        f->evidence.items[i].key = mystrdup(version_keys[i]);
        f->evidence.items[i].value = mystrdup(status_str(results[i]));
    }

   
    f->tags.count = 2;
    f->tags.strings = (const char **)malloc(2 * sizeof(char *));
    f->tags.strings[0] = mystrdup("tls");
    f->tags.strings[1] = mystrdup("ssl");

   
    free(min_version_str);
    free(max_version_str);
    free(sni_override);
    *out_result = result;

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}


KRAKEN_API void kraken_free(void *p) {
    if (!p)
        return;

    KrakenRunResult *result = (KrakenRunResult *)p;

    free((void *)result->target.host);

    for (size_t i = 0; i < result->findings_count; i++) {
        KrakenFinding *f = &result->findings[i];
        free((void *)f->id);
        free((void *)f->module_id);
        free((void *)f->title);
        free((void *)f->severity);
        free((void *)f->description);
        free((void *)f->target.host);

        for (size_t j = 0; j < f->evidence.count; j++) {
            free((void *)f->evidence.items[j].key);
            free((void *)f->evidence.items[j].value);
        }
        free(f->evidence.items);

        for (size_t j = 0; j < f->tags.count; j++) {
            free((void *)f->tags.strings[j]);
        }
        free((void *)f->tags.strings);
    }
    free(result->findings);

    for (size_t i = 0; i < result->logs.count; i++) {
        free((void *)result->logs.strings[i]);
    }
    free((void *)result->logs.strings);

    free(result);
}
