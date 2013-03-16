
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define Hbits   5
#define SHIFT_SIZE 8192 //2^(Hbits*2)
#define HASH_SIZE 1024
#define HASH_MASK 1023

typedef struct ngx_http_sub_hash_entry {
    ngx_uint_t index;
    ngx_str_t pattern;
    struct ngx_http_sub_hash_entry *next;
} ngx_http_sub_hash_entry_t;

typedef struct {
    u_char SHIFT[SHIFT_SIZE];
    ngx_http_sub_hash_entry_t *HASH[HASH_SIZE];
    ngx_array_t *hash_entries;
    ngx_uint_t lmin;
    ngx_uint_t lmax;
    ngx_uint_t referenced;
} ngx_http_sub_wm_tables_t;

typedef struct {
    ngx_uint_t index;
    u_char *pos;
    ngx_uint_t length;
} ngx_http_sub_wm_match_t;

typedef struct {
    ngx_array_t                *patterns;
    ngx_array_t                *values;
    ngx_uint_t                 tmp_buf_size;
    ngx_http_sub_wm_tables_t   *wm_struct;
    ngx_hash_t                 types;

    ngx_flag_t                 once;

    ngx_array_t               *types_keys;
} ngx_http_sub_loc_conf_t;


typedef enum {
    sub_main_state = 0,
    sub_tmp_state,
} ngx_http_sub_state_e;


typedef struct {
    ngx_http_complex_value_t   *values;
    ngx_http_sub_wm_tables_t   *wm_struct;
    ngx_str_t                  tmp;
    ngx_uint_t                 index;

    ngx_uint_t                 first_part_size;
    ngx_uint_t                 next_buf_offset;
    ngx_uint_t                 once;   /* unsigned  once:1 */

    ngx_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t              **last_out;
    ngx_chain_t               *busy;
    ngx_chain_t               *free;

    ngx_str_t                *repl;

    ngx_uint_t                 state;
} ngx_http_sub_ctx_t;


static ngx_int_t ngx_http_sub_output(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx);
static ngx_int_t ngx_http_sub_parse(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx);

static char * ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_sub_create_conf(ngx_conf_t *cf);
static char *ngx_http_sub_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sub_filter_commands[] = {

    { ngx_string("sub_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_sub_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("sub_filter_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, once),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sub_create_conf,              /* create location configuration */
    ngx_http_sub_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_sub_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_filter_module_ctx,       /* module context */
    ngx_http_sub_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_list_t *wm_struct_list;

static void ngx_http_sub_wm_prep(ngx_http_sub_wm_tables_t *wm_struct, ngx_http_sub_hash_entry_t *hash_entries, int nelts)
{
    int i,j;
    int hash;
    u_char *pattern;
    ngx_http_sub_hash_entry_t *hash_entry;

    for(i = 0; i < SHIFT_SIZE; i++) {
        wm_struct->SHIFT[i] = wm_struct->lmin - 1; //B = 2: lmin - B + 1
    }

    for(i = 0; i < nelts; i++) {
        pattern = hash_entries[i].pattern.data;
        
        for(j = wm_struct->lmin - 1; j > 0; j--) { //B = 2: j>=B-1
            hash = (pattern[j]<<Hbits) + pattern[j - 1];
            if(wm_struct->SHIFT[hash] > wm_struct->lmin - 1 - j) {
                wm_struct->SHIFT[hash] = wm_struct->lmin - 1 - j;
            }
        }
        j = wm_struct->lmin - 1;
        hash = (pattern[j] << Hbits) + pattern[j - 1];
        hash &= HASH_MASK;

        if(!wm_struct->HASH[hash] ||
                wm_struct->HASH[hash]->pattern.len <= hash_entries[i].pattern.len) {
            hash_entries[i].next = wm_struct->HASH[hash];
            wm_struct->HASH[hash] = &hash_entries[i];
        }
        else {
            hash_entry = wm_struct->HASH[hash];
            while(hash_entry->next &&
                    hash_entry->next->pattern.len <= hash_entries[i].pattern.len)
            {
                hash_entry = hash_entry->next;
            }
            hash_entries[i].next = hash_entry->next;
            hash_entry->next = &hash_entries[i];
        }
    }
}

static ngx_int_t ngx_http_sub_wm_search(ngx_http_sub_wm_tables_t *wm_struct,
        u_char *text, ngx_uint_t length, ngx_http_sub_wm_match_t *match)
{
    u_char *textstart;
    u_char *textend;
    u_char *qx, *px;
    int h, shift;
    ngx_http_sub_hash_entry_t *p;

    textstart = text;
    text += wm_struct->lmin - 1;
    textend = text + length - wm_struct->lmax;

    while (text <= textend) {
        h = (*text << Hbits) + (*(text - 1));
        shift = wm_struct->SHIFT[h];

        if (shift == 0) {
            shift = 1;
            h&=HASH_MASK;
            p = wm_struct->HASH[h];
            while (p) {
                size_t i = 0;
                px = p->pattern.data;
                qx = text - wm_struct->lmin + 1;

                while(i < p->pattern.len) {
                    if(px[i]!=qx[i]) {
                        break;
                    }
                    i++;
                }    
                if(i == p->pattern.len) {
                    match->index = p->index;
                    match->length = p->pattern.len;
                    match->pos = text - wm_struct->lmin + 1;
                    return 0;
                }
                p = p->next;
            }
        }
        text += shift;
    }

    match->index = -1;
    match->length = length < wm_struct->lmax - 1 ? length : wm_struct->lmax - 1;
    match->pos = textstart + length - match->length;
    return 1;
}

static ngx_int_t
ngx_http_sub_header_filter(ngx_http_request_t *r)
{
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

    if (!slcf->wm_struct
        || r->headers_out.content_length_n == 0
        || ngx_http_test_content_type(r, &slcf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->tmp.data = ngx_pnalloc(r->pool, slcf->tmp_buf_size);
    if (ctx->tmp.data == NULL) {
        return NGX_ERROR;
    }
    ctx->tmp.len = slcf->tmp_buf_size;

    ctx->repl = ngx_pcalloc(r->pool, slcf->values->nelts * sizeof(ngx_str_t));
 
    ctx->wm_struct = slcf->wm_struct;
    ctx->values = slcf->values->elts;

    ngx_http_set_ctx(r, ctx, ngx_http_sub_filter_module);

    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
        ngx_http_clear_etag(r);
    }
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_sub_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_sub_ctx_t        *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sub_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (ngx_http_sub_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    while (ctx->in || (ctx->buf && ctx->buf->last_buf)) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }
        else
        {
            if(ctx->buf->last_buf)
            {
                ngx_memzero(ctx->buf->last, ctx->tmp.len/2);
                ctx->buf->last += ctx->tmp.len/2;
            }
            else
            {
                ngx_uint_t next_buf_size = ctx->in->buf->last - ctx->in->buf->pos;
                ngx_uint_t tmp_buf_size = ctx->buf->last - ctx->buf->pos;
                ngx_uint_t rem_part_size = ctx->tmp.len/2 - (tmp_buf_size - ctx->first_part_size);
                ngx_uint_t next_part_size = next_buf_size < rem_part_size ? next_buf_size : rem_part_size;

                ngx_memcpy(ctx->buf->last, ctx->in->buf->pos, next_part_size);
                ctx->buf->last += next_part_size;

                if(ctx->in->buf->last_buf) {
                    rem_part_size -= next_part_size;
                    ngx_memzero(ctx->buf->last, rem_part_size);
                    ctx->buf->last += rem_part_size;
                }
                else if(next_part_size != rem_part_size) {
                    ctx->in = ctx->in->next;
                    continue;
                }
            }
            ctx->pos = ctx->buf->pos;
        }    
        
        ctx->pos += ctx->next_buf_offset;
        ctx->copy_start = ctx->pos;
        ctx->copy_end = ctx->pos;

        b = NULL;

        while (ctx->pos < ctx->buf->last) {
/*
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: \"%V\" state: %d", &ctx->saved, ctx->state);
*/
            rc = ngx_http_sub_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d, tmp: \"%V\" %p-%p",
                           rc, &ctx->tmp, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {
                /*
                   ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "saved: \"%V\"", &ctx->saved);
                 */
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;

                } else {
                    b = ngx_alloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                if(ctx->state == sub_main_state)
                {
                    ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                    b->pos = ctx->copy_start;
                    b->last = ctx->copy_end;
                    b->shadow = NULL;
                    b->last_buf = 0;
                    b->recycled = 0;

                    if (b->in_file) {
                        b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                        b->file_pos += b->pos - ctx->buf->pos;
                    }
                }
                else
                {
                    ngx_uint_t buf_size = ctx->copy_end - ctx->copy_start;
                    ngx_memzero(b, sizeof(ngx_buf_t));
                    b->pos = ngx_pnalloc(r->pool, buf_size);
                    if (b->pos == NULL) {
                        return NGX_ERROR;
                    }
                    ngx_memcpy(b->pos, ctx->copy_start, buf_size);
                    b->last = b->pos + buf_size;
                    b->memory = 1;
                }

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* rc == NGX_OK */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            if(!ctx->repl[ctx->index].data) {
                if (ngx_http_complex_value(r, &ctx->values[ctx->index], &ctx->repl[ctx->index])
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            if (ctx->repl[ctx->index].len) {
                b->memory = 1;
                b->pos = ctx->repl[ctx->index].data;
                b->last = ctx->repl[ctx->index].data + ctx->repl[ctx->index].len;

            } else {
                b->sync = 1;
            }

            cl->buf = b;
            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

//            ctx->once = slcf->once;

            continue;
        }

        if (ctx->buf->last_buf || ngx_buf_in_memory(ctx->buf)) {
            if (b == NULL) {
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;
                    ngx_memzero(b, sizeof(ngx_buf_t));

                } else {
                    b = ngx_calloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                b->sync = 1;

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        if(ctx->state == sub_main_state && ctx->first_part_size)
        {
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }
            b->last_buf = ctx->buf->last_buf;
            b->pos = ctx->tmp.data;
            b->last = b->pos + ctx->first_part_size;
            b->memory = 1;
            ctx->buf = b;
            ctx->state = sub_tmp_state;
        }
        else
        {
            ctx->buf = NULL;
            ctx->state = sub_main_state;
        }
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }
    return ngx_http_sub_output(r, ctx);
}

static ngx_int_t
ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}

static ngx_int_t
ngx_http_sub_parse(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    ngx_int_t rc;
    ngx_uint_t buf_size;
    ngx_http_sub_wm_match_t match;

    buf_size = ctx->buf->last - ctx->pos;
    rc = ngx_http_sub_wm_search(ctx->wm_struct, ctx->pos, buf_size, &match);

    ctx->copy_start = ctx->pos;

    if(!rc) {
        ctx->first_part_size = 0;
        ctx->index = match.index;
        ctx->copy_end = match.pos;
        ctx->pos = match.pos + match.length;
        return NGX_OK;
    }

    ctx->copy_end = match.pos;
    ctx->pos = ctx->buf->last;

    if(ctx->state == sub_main_state) {
        ctx->first_part_size = match.length;
        ngx_memcpy(ctx->tmp.data, ctx->copy_end, ctx->first_part_size);
        ctx->next_buf_offset = 0;
    }
    else {
        ctx->next_buf_offset = ctx->tmp.len/2 - match.length;
    }

    return NGX_AGAIN;
}

static char *
ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value, *pattern;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    pattern = ngx_array_push(slcf->patterns);
    *pattern = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = ngx_array_push(slcf->values);

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_sub_create_conf(ngx_conf_t *cf)
{
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->match = { 0, NULL };
     *     conf->sub = { 0, NULL };
     *     conf->sub_lengths = NULL;
     *     conf->sub_values = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */
    slcf->patterns = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));

    slcf->values = ngx_array_create(cf->pool, 1, sizeof(ngx_http_complex_value_t));

    slcf->once = NGX_CONF_UNSET;

    return slcf;
}

static void ngx_http_sub_merge_wm_tables(ngx_conf_t *cf, ngx_http_sub_loc_conf_t *conf,
                ngx_http_sub_loc_conf_t *prev)
{
    int i;
    int nelts = conf->patterns->nelts;
    ngx_str_t *patterns = conf->patterns->elts;
    ngx_http_sub_wm_tables_t *wm_struct;
    ngx_array_t *hash_entries;
    ngx_http_sub_hash_entry_t *hash_entry;

    if(conf->wm_struct) {
        return;
    }
    
    if(!nelts) {
        if(prev && prev->wm_struct) {
            conf->wm_struct = prev->wm_struct;
            conf->patterns = prev->patterns;
            conf->values = prev->values;
            conf->tmp_buf_size = prev->tmp_buf_size;
        }
        return;
    }

    if(!wm_struct_list) {
        wm_struct_list = ngx_list_create(cf->pool, 1, sizeof(ngx_http_sub_wm_tables_t));
    }
    wm_struct = ngx_list_push(wm_struct_list);
    ngx_memzero(wm_struct, sizeof(ngx_http_sub_wm_tables_t));

    hash_entries = ngx_array_create(cf->pool, nelts, sizeof(ngx_http_sub_hash_entry_t));

    wm_struct->lmax = wm_struct->lmin = patterns[0].len;
    for(i = 0; i < nelts; i++) {
        size_t len = patterns[i].len;
        if(len > wm_struct->lmax) {
            wm_struct->lmax = len;
        }
        else if(len < wm_struct->lmin) {
            wm_struct->lmin = len;
        }
        hash_entry = ngx_array_push(hash_entries);
        hash_entry->pattern = patterns[i];
        hash_entry->index = i;
    }

    ngx_http_sub_wm_prep(wm_struct, hash_entries->elts, hash_entries->nelts);
    wm_struct->hash_entries = hash_entries;
    conf->tmp_buf_size = (wm_struct->lmax - 1) * 2;
    conf->wm_struct = wm_struct;
}
 
static char *
ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sub_loc_conf_t *prev = parent;
    ngx_http_sub_loc_conf_t *conf = child;
//    ngx_conf_merge_value(conf->once, prev->once, 1);

    ngx_http_sub_merge_wm_tables(cf, prev, NULL);
    ngx_http_sub_merge_wm_tables(cf, conf, prev);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_sub_filter_init(ngx_conf_t *cf)
{
    //delete unreferenced wm structures and hash entries

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_sub_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_sub_body_filter;

    return NGX_OK;
}
