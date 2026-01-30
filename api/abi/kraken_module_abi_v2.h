#ifndef KRAKEN_MODULE_ABI_V2_H
#define KRAKEN_MODULE_ABI_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kraken_module_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#if defined(KRAKEN_MODULE_BUILD)
#define KRAKEN_API __declspec(dllexport)
#else
#define KRAKEN_API __declspec(dllimport)
#endif
#else
#define KRAKEN_API __attribute__((visibility("default")))
#endif

#define KRAKEN_ABI_VERSION_V2 2u

typedef void *KrakenConnectionHandle;

typedef enum {
    KRAKEN_CONN_TYPE_STREAM = 1,
    KRAKEN_CONN_TYPE_DATAGRAM = 2,
    KRAKEN_CONN_TYPE_FRAME = 3,
} KrakenConnectionType;

typedef enum {
    KRAKEN_TARGET_KIND_NETWORK = 1,
    KRAKEN_TARGET_KIND_ETHERCAT = 2,
} KrakenTargetKind;

typedef struct {
    const char *iface;       /* Network interface name (e.g., "eth0") */
    const char *mac_address; /* Master's MAC address */
    uint32_t slave_count;    /* Number of slaves observed */
    uint16_t *slaves;        /* Array of slave station addresses */
    size_t slaves_len;       /* Length of slaves array */
} KrakenEtherCATTarget;

typedef struct {
    KrakenTargetKind kind;
    union {
        KrakenHostPort network;
        KrakenEtherCATTarget ethercat;
    } u;
} KrakenTarget;

typedef struct {
    KrakenConnectionType type;
    const char *local_addr;
    const char *remote_addr;
    const char **stack_layers;
    size_t stack_layers_count;
} KrakenConnectionInfo;

/* Send data over a connection (stream or datagram)
   - conn: connection handle
   - data: pointer to data buffer to send
   - len: length of data in bytes
   - timeout_ms: operation timeout in milliseconds (0 = no timeout)
   Returns: number of bytes sent, or -1 on error */
typedef int64_t (*KrakenSendFn)(KrakenConnectionHandle conn, const uint8_t *data, size_t len, uint32_t timeout_ms);

/* Receive data from a connection (stream or datagram)
   - conn: connection handle
   - buffer: pointer to buffer to store received data
   - buffer_size: size of the buffer
   - timeout_ms: operation timeout in milliseconds (0 = no timeout)
   Returns: number of bytes received, 0 on EOF, or -1 on error */
typedef int64_t (*KrakenRecvFn)(KrakenConnectionHandle conn, uint8_t *buffer, size_t buffer_size, uint32_t timeout_ms);

/* Get information about the connection
   - conn: connection handle
   Returns: pointer to connection info struct (valid until conn is closed) */
typedef const KrakenConnectionInfo *(*KrakenGetConnectionInfoFn)(KrakenConnectionHandle conn);

/* Open a new connection using the same conduit configuration as the provided handle.
   - conn: existing connection handle (used to pick configuration)
   - timeout_ms: dial timeout in milliseconds (0 = default)
   Returns: new connection handle or NULL on error */
typedef KrakenConnectionHandle (*KrakenOpenFn)(KrakenConnectionHandle conn, uint32_t timeout_ms);

/* Close a connection previously obtained via KrakenOpenFn.
   - conn: connection handle to close
*/
typedef void (*KrakenCloseFn)(KrakenConnectionHandle conn);

typedef struct {
    KrakenSendFn send;
    KrakenRecvFn recv;
    KrakenGetConnectionInfoFn get_info;
    KrakenOpenFn open;   /* optional, may be NULL */
    KrakenCloseFn close; /* optional, may be NULL */
} KrakenConnectionOps;

/* V2 Finding - uses KrakenTarget instead of KrakenHostPort */
typedef struct {
    const char *id;
    const char *module_id;
    bool success;
    const char *title;
    const char *severity;
    const char *description;
    KrakenEvidence evidence;
    KrakenStringList tags;
    int64_t timestamp;
    KrakenTarget target;
} KrakenFindingV2;

/* V2 Run Result - uses KrakenTarget and KrakenFindingV2 */
typedef struct {
    KrakenTarget target;
    KrakenFindingV2 *findings;
    size_t findings_count;
    KrakenStringList logs;
} KrakenRunResultV2;

/* Main entrypoint: run the module with a connected conduit handle

   Parameters:
   - conn: Opaque handle to the connected conduit (Stream, Datagram, or Frame)
   - ops: Function pointers for I/O operations on the connection
   - target: Target info (network or EtherCAT) - check target->kind to determine type
   - timeout_ms: Execution timeout in milliseconds
   - params_json: UTF-8 JSON string with module-specific parameters (may be NULL)
   - out_result: Pointer to a pointer to KrakenRunResultV2. Module allocates memory.

   Returns: 0 on success, nonzero on error.
*/
typedef int (*KrakenRunV2Fn)(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenTarget *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResultV2 **out_result);

/* Deallocator for buffers returned by kraken_run_v2 (same as V1) */
typedef void (*KrakenFreeV2Fn)(void *p);

/* Optional: Module initialization/cleanup functions */
typedef int (*KrakenInitFn)(void);
typedef void (*KrakenCleanupFn)(void);

KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenTarget *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResultV2 **out_result);
KRAKEN_API void kraken_free_v2(void *p);

KRAKEN_API int kraken_init(void);
KRAKEN_API void kraken_cleanup(void);

/* ------------------------------------------------------------------ */
/* V2 Helper Functions                                                */
/* ------------------------------------------------------------------ */

static void add_log_v2(KrakenRunResultV2 *result, const char *log_line) {
    result->logs.count++;
    result->logs.strings = (const char **)realloc((void *)result->logs.strings, result->logs.count * sizeof(char *));
    result->logs.strings[result->logs.count - 1] = mystrdup(log_line);
}

static void add_finding_v2(KrakenRunResultV2 *result, KrakenFindingV2 *finding) {
    result->findings_count++;
    result->findings = (KrakenFindingV2 *)realloc(result->findings, result->findings_count * sizeof(KrakenFindingV2));
    result->findings[result->findings_count - 1] = *finding;
}

static void copy_target(KrakenTarget *dst, const KrakenTarget *src) {
    dst->kind = src->kind;
    if (src->kind == KRAKEN_TARGET_KIND_NETWORK) {
        dst->u.network.host = mystrdup(src->u.network.host);
        dst->u.network.port = src->u.network.port;
    } else if (src->kind == KRAKEN_TARGET_KIND_ETHERCAT) {
        dst->u.ethercat.iface = mystrdup(src->u.ethercat.iface);
        dst->u.ethercat.mac_address = mystrdup(src->u.ethercat.mac_address);
        dst->u.ethercat.slave_count = src->u.ethercat.slave_count;
        dst->u.ethercat.slaves_len = src->u.ethercat.slaves_len;
        if (src->u.ethercat.slaves_len > 0) {
            dst->u.ethercat.slaves = (uint16_t *)malloc(src->u.ethercat.slaves_len * sizeof(uint16_t));
            memcpy(dst->u.ethercat.slaves, src->u.ethercat.slaves, src->u.ethercat.slaves_len * sizeof(uint16_t));
        } else {
            dst->u.ethercat.slaves = NULL;
        }
    }
}

static void free_target(KrakenTarget *t) {
    if (t->kind == KRAKEN_TARGET_KIND_NETWORK) {
        free((void *)t->u.network.host);
    } else if (t->kind == KRAKEN_TARGET_KIND_ETHERCAT) {
        free((void *)t->u.ethercat.iface);
        free((void *)t->u.ethercat.mac_address);
        free((void *)t->u.ethercat.slaves);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* KRAKEN_MODULE_ABI_V2_H */
