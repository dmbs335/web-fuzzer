/*
 * mod_fuzztrace — Apache module for differential fuzzing instrumentation.
 *
 * Hooks into 6 request processing phases and captures request_rec field
 * snapshots (uri, filename, path_info, handler) at each phase.  After
 * the handler runs, the collected trace is serialised as JSON into the
 * X-FuzzTrace response header.
 *
 * Build:  apxs -i -a -c mod_fuzztrace.c
 * Config: LoadModule fuzztrace_module modules/mod_fuzztrace.so
 *
 * Copyright 2026 — security research tool, not for production use.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "ap_config.h"

/* ── Per-request note key ─────────────────────────────────────── */
#define TRACE_NOTE "fuzztrace_phases"

/* Maximum number of phases we track */
#define MAX_PHASES 6

/* ── Phase snapshot ───────────────────────────────────────────── */
typedef struct {
    const char *name;
    const char *uri;
    const char *filename;
    const char *path_info;
    const char *handler;
    const char *args;
    int status;
} phase_snap_t;

typedef struct {
    phase_snap_t snaps[MAX_PHASES];
    int count;
} trace_t;

/* ── Helpers ──────────────────────────────────────────────────── */

static const char *safe(const char *s) {
    return s ? s : "";
}

/* JSON-escape a string into pool memory (minimal: escape \ and ") */
static const char *json_esc(apr_pool_t *p, const char *s) {
    if (!s) return "";
    apr_size_t len = strlen(s);
    /* Worst case: every char escaped → 2x + 1 */
    char *buf = apr_palloc(p, len * 2 + 1);
    char *dst = buf;
    for (apr_size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            *dst++ = '\\';
            *dst++ = (char)c;
        } else if (c < 0x20) {
            /* Control chars → \uXXXX */
            dst += sprintf(dst, "\\u%04x", c);
        } else {
            *dst++ = (char)c;
        }
    }
    *dst = '\0';
    return buf;
}

/* Record a snapshot of the current request_rec state. */
static void record_phase(request_rec *r, const char *phase_name) {
    trace_t *trace = (trace_t *)apr_table_get(r->notes, TRACE_NOTE);
    if (!trace) {
        trace = apr_pcalloc(r->pool, sizeof(trace_t));
        trace->count = 0;
        apr_table_setn(r->notes, TRACE_NOTE, (const char *)trace);
    }
    if (trace->count >= MAX_PHASES) return;

    phase_snap_t *snap = &trace->snaps[trace->count++];
    snap->name = phase_name;
    snap->uri = apr_pstrdup(r->pool, safe(r->uri));
    snap->filename = apr_pstrdup(r->pool, safe(r->filename));
    snap->path_info = apr_pstrdup(r->pool, safe(r->path_info));
    snap->handler = apr_pstrdup(r->pool, safe(r->handler));
    snap->args = apr_pstrdup(r->pool, safe(r->args));
    snap->status = r->status;
}

/* Serialise the trace to JSON and set the X-FuzzTrace header. */
static void emit_trace(request_rec *r) {
    trace_t *trace = (trace_t *)apr_table_get(r->notes, TRACE_NOTE);
    if (!trace || trace->count == 0) return;

    apr_pool_t *p = r->pool;

    /* Build phases object */
    char *phases_json = apr_pstrdup(p, "");
    for (int i = 0; i < trace->count; i++) {
        phase_snap_t *s = &trace->snaps[i];
        char *snap_json = apr_psprintf(p,
            "%s\"%s\":{\"uri\":\"%s\",\"filename\":\"%s\","
            "\"path_info\":\"%s\",\"handler\":\"%s\",\"args\":\"%s\",\"status\":%d}",
            (i > 0 ? "," : ""),
            json_esc(p, s->name),
            json_esc(p, s->uri),
            json_esc(p, s->filename),
            json_esc(p, s->path_info),
            json_esc(p, s->handler),
            json_esc(p, s->args),
            s->status);
        phases_json = apr_pstrcat(p, phases_json, snap_json, NULL);
    }

    /* Final handler and status from last snapshot */
    phase_snap_t *last = &trace->snaps[trace->count - 1];
    char *json = apr_psprintf(p,
        "{\"phases\":{%s},\"status\":%d,\"final_handler\":\"%s\"}",
        phases_json, r->status, json_esc(p, safe(last->handler)));

    apr_table_setn(r->headers_out, "X-FuzzTrace", json);
}

/* ── Phase hooks ──────────────────────────────────────────────── */

static int fuzztrace_post_read(request_rec *r) {
    record_phase(r, "post_read");
    return DECLINED;
}

static int fuzztrace_translate(request_rec *r) {
    record_phase(r, "translate");
    return DECLINED;
}

static int fuzztrace_map_to_storage(request_rec *r) {
    record_phase(r, "map_to_storage");
    return DECLINED;
}

static int fuzztrace_access_check(request_rec *r) {
    record_phase(r, "access_check");
    return DECLINED;
}

static int fuzztrace_fixup(request_rec *r) {
    record_phase(r, "fixup");
    return DECLINED;
}

/* Output filter to inject trace header after handler completes. */
static apr_status_t fuzztrace_output_filter(ap_filter_t *f,
                                             apr_bucket_brigade *bb) {
    request_rec *r = f->r;

    /* Record handler-phase snapshot just before output */
    record_phase(r, "handler_phase");

    /* Emit the trace header */
    emit_trace(r);

    /* Remove ourselves so we only run once */
    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, bb);
}

static void fuzztrace_insert_filter(request_rec *r) {
    ap_add_output_filter("FUZZTRACE", NULL, r, r->connection);
}

/* ── Module registration ──────────────────────────────────────── */

static void fuzztrace_register_hooks(apr_pool_t *p) {
    /* Phase hooks — run LAST so other modules have already acted */
    ap_hook_post_read_request(fuzztrace_post_read, NULL, NULL,
                              APR_HOOK_LAST);
    ap_hook_translate_name(fuzztrace_translate, NULL, NULL,
                           APR_HOOK_LAST);
    ap_hook_map_to_storage(fuzztrace_map_to_storage, NULL, NULL,
                           APR_HOOK_LAST);
    ap_hook_access_checker(fuzztrace_access_check, NULL, NULL,
                           APR_HOOK_LAST);
    ap_hook_fixups(fuzztrace_fixup, NULL, NULL,
                   APR_HOOK_LAST);

    /* Output filter captures handler-phase state */
    ap_register_output_filter("FUZZTRACE", fuzztrace_output_filter,
                              NULL, AP_FTYPE_RESOURCE);
    ap_hook_insert_filter(fuzztrace_insert_filter, NULL, NULL,
                          APR_HOOK_LAST);
}

AP_DECLARE_MODULE(fuzztrace) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* per-directory config creator */
    NULL,                       /* per-directory config merger */
    NULL,                       /* per-server config creator */
    NULL,                       /* per-server config merger */
    NULL,                       /* command table */
    fuzztrace_register_hooks    /* register hooks */
};
