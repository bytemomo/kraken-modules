#ifndef KRAKEN_MODULE_ABI_H
#define KRAKEN_MODULE_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#define KRAKEN_ABI_VERSION 1u
KRAKEN_API extern const uint32_t KRAKEN_MODULE_ABI_VERSION;

typedef struct {
    const char *host;
    uint16_t port;
} KrakenHostPort;

typedef struct {
    const char **strings;
    size_t count;
} KrakenStringList;

typedef struct {
    const char *key;
    const char *value;
} KrakenKeyValue;

typedef struct {
    KrakenKeyValue *items;
    size_t count;
} KrakenEvidence;

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
    KrakenHostPort target;
} KrakenFinding;

typedef struct {
    KrakenHostPort target;
    KrakenFinding *findings;
    size_t findings_count;
    KrakenStringList logs;
} KrakenRunResult;

/* Main entrypoint: run the module test.
   - host, port: target to assess
   - timeout_ms: execution timeout in milliseconds
   - params_json: UTF-8 JSON string with module-specific parameters (may be NULL)
   - out_result: pointer to a pointer to a KrakenRunResult struct. The module allocates memory for the struct.
   Return 0 on success, nonzero on error. */
typedef int (*KrakenRunFn)(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result);

/* Deallocator for buffers returned by kraken_run. */
typedef void (*KrakenFreeFn)(void *p);

KRAKEN_API int kraken_run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result);
KRAKEN_API void kraken_free(void *p);

/* ------------------------------------------------------------------ */
/* UTILS: %TODO Move in its own file                                  */
/* ------------------------------------------------------------------ */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char *json_extract_string(const char *json, const char *key) {
    if (!json)
        return NULL;

    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p)
        return NULL;

    p = strchr(p, ':');
    if (!p)
        return NULL;
    p++;

    // Skip whitespace and opening quote
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n'))
        p++;
    if (*p != '\"')
        return NULL;
    p++;

    // Find closing quote
    const char *end = p;
    while (*end && *end != '\"')
        end++;

    size_t len = end - p;
    char *result = (char *)malloc(len + 1);
    if (result) {
        memcpy(result, p, len);
        result[len] = '\0';
    }
    return result;
}

static char *mystrdup(const char *s) {
    if (!s)
        return NULL;
    size_t len = strlen(s) + 1;
    char *p = (char *)malloc(len);
    if (p) {
        memcpy(p, s, len);
    }
    return p;
}

static void add_log(KrakenRunResult *result, const char *log_line) {
    result->logs.count++;
    result->logs.strings = (const char **)realloc((void *)result->logs.strings, result->logs.count * sizeof(char *));
    result->logs.strings[result->logs.count - 1] = mystrdup(log_line);
}

static void add_finding(KrakenRunResult *result, KrakenFinding *finding) {
    result->findings_count++;
    result->findings = (KrakenFinding *)realloc(result->findings, result->findings_count * sizeof(KrakenFinding));
    result->findings[result->findings_count - 1] = *finding;
}

#ifdef __cplusplus
}
#endif

#endif /* KRAKEN_MODULE_ABI_H */
