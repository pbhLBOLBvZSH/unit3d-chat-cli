#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ncurses.h>
#include <curl/curl.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <strings.h>
#include "jsmn.h"

#define INPUT_HEIGHT 3
#define POLL_INTERVAL 2
#define MAX_MSG_LEN 1024

typedef struct {
    char *memory;
    size_t size;
} MemoryStruct;

static WINDOW *out_win = NULL;
static WINDOW *in_win = NULL;
static pthread_mutex_t ui_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t running = 1;
static char tracker[512] = {0};
char rooms_url[512] = {0};
static char message_read_url[512] = {0};
static char message_send_url[512] = {0};
static char cookies[8192] = {0};
static char csrf_token[512] = {0};
static char xsrf_raw[512] = {0};
static char referer[512] = {0};
static char origin[512] = {0};
static char user_agent[256] = {0};
static long selected_room_id = 0;
static long last_id = 0;

// Trim whitespace in-place and return pointer to trimmed string
static char *trim(char *s) {
    if(!s) return s;
    while(*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s) - 1;
    while(e > s && isspace((unsigned char)*e)) { *e = '\0'; e--; }
    return s;
}

// Load simple key=value config file.
static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if(!f) return 0;
    char line[2048];
    while(fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if(!s || s[0] == '#' || s[0] == '\0') continue;
        char *eq = strchr(s, '=');
        if(!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        if     (strcmp(key, "TRACKER") == 0)    strncpy(tracker, val, sizeof(tracker)-1);
        else if(strcmp(key, "COOKIES") == 0)    strncpy(cookies, val, sizeof(cookies)-1);
        else if(strcmp(key, "CSRF_TOKEN") == 0) strncpy(csrf_token, val, sizeof(csrf_token)-1);
        else if(strcmp(key, "XSRF_TOKEN") == 0) strncpy(xsrf_raw, val, sizeof(xsrf_raw)-1);
        else if(strcmp(key, "REFERER") == 0)    strncpy(referer, val, sizeof(referer)-1);
        else if(strcmp(key, "ORIGIN") == 0)     strncpy(origin, val, sizeof(origin)-1);
        else if(strcmp(key, "USER_AGENT") == 0) strncpy(user_agent, val, sizeof(user_agent)-1);
    }
    fclose(f);

    size_t tracklen = strlen(tracker);
    if (tracker[tracklen-1] == '/') tracker[tracklen-1] = '\0';

    return (tracker[0] != '\0');
}


static void append_output(const char *line);
static int http_get(const char *url, MemoryStruct *out);
static int parse_rooms_and_prompt(void);
static int skip_token(const jsmntok_t *tokens, int idx, int tokn);

// Unescape a JSON string (handles basic escapes)
static void json_unescape(const char *in, int inlen, char *out, size_t outlen) {
    size_t o = 0;
    for(int i = 0; i < inlen && o + 1 < outlen; ++i) {
        char c = in[i];
        if(c == '\\' && i + 1 < inlen) {
            ++i;
            char e = in[i];
            switch(e) {
                case '"': out[o++] = '"'; break;
                case '\\': out[o++] = '\\'; break;
                case '/': out[o++] = '/'; break;
                case 'b': out[o++] = '\b'; break;
                case 'f': out[o++] = '\f'; break;
                case 'n': out[o++] = '\n'; break;
                case 'r': out[o++] = '\r'; break;
                case 't': out[o++] = '\t'; break;
                case 'u': /* skip unicode sequences */
                    /* very simple: skip 4 hex digits */
                    if(i + 4 < inlen) i += 4;
                    break;
                default:
                    out[o++] = e; break;
            }
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}


// Strip HTML tags and decode a wide set of entities.
// Two-pass approach:
//  1) Decode HTML entities (named and numeric) into a temporary buffer
//  2) Remove any tags by skipping content between '<' and '>' so only visible text remains
static void html_strip_and_unescape(char *s) {
    if(!s) return;
    size_t len = strlen(s);
    char *tmp = malloc(len + 1);
    if(!tmp) return;

    /* Pass 1: decode entities into tmp */
    char *r = s;
    size_t ti = 0;
    while(*r && ti < len) {
        if(*r == '&') {
            if(strncmp(r, "&quot;", 6) == 0) { tmp[ti++] = '"'; r += 6; continue; }
            if(strncmp(r, "&amp;", 5) == 0) { tmp[ti++] = '&'; r += 5; continue; }
            if(strncmp(r, "&lt;", 4) == 0) { tmp[ti++] = '<'; r += 4; continue; }
            if(strncmp(r, "&gt;", 4) == 0) { tmp[ti++] = '>'; r += 4; continue; }
            if(strncmp(r, "&#39;", 5) == 0) { tmp[ti++] = '\''; r += 5; continue; }
            if(r[1] == '#') {
                /* Numeric entity: decimal (&#123;) or hex (&#x1f;)
                 * We decode into a single byte for simplicity.
                 */
                r += 2; /* skip '&#' */
                int val = 0;
                if(*r == 'x' || *r == 'X') {
                    r++;
                    while(isxdigit((unsigned char)*r)) {
                        char c = *r++;
                        val = val * 16 + (isdigit((unsigned char)c) ? c - '0' : (tolower(c) - 'a' + 10));
                    }
                } else {
                    while(isdigit((unsigned char)*r)) { val = val * 10 + (*r - '0'); r++; }
                }
                if(*r == ';') r++;
                if(val > 0 && val < 256) tmp[ti++] = (char)val;
                continue;
            }
            /* unknown entity: skip until ; or consume & */
            char *semi = strchr(r, ';');
            if(semi) r = semi + 1; else tmp[ti++] = *r++;
            continue;
        }
        tmp[ti++] = *r++;
    }
    tmp[ti] = '\0';

    /* Pass 2: strip tags from tmp and write back into s */
    size_t si = 0;
    int in_tag = 0;
    for(size_t k = 0; k < ti; ++k) {
        char c = tmp[k];
        if(c == '<') { in_tag = 1; continue; }
        if(c == '>') { in_tag = 0; continue; }
        if(in_tag) continue;
        s[si++] = c;
    }
    s[si] = '\0';
    free(tmp);
}

// Parse rooms response and prompt user to pick a room id. Returns 1 on success
static int parse_rooms_and_prompt(void) {
    MemoryStruct chunk = {0};
    
    snprintf(rooms_url, sizeof(rooms_url), "%s/api/chat/rooms", tracker);
    snprintf(message_send_url, sizeof(message_send_url), "%s/api/chat/messages", tracker);
    if(http_get(rooms_url, &chunk) != 0 || !chunk.memory) { free(chunk.memory); return 0; }
    jsmn_parser p;
    jsmntok_t tokens[1024];
    jsmn_init(&p);
    int tokcount = jsmn_parse(&p, chunk.memory, chunk.size, tokens, sizeof(tokens)/sizeof(tokens[0]));
    if(tokcount < 0) { free(chunk.memory); return 0; }
    int found = 0;
    long ids[64];
    char names[64][128];
    int count = 0;
    for(int i=1;i<tokcount;i++){
        if(tokens[i].type==JSMN_STRING) {
            int len = tokens[i].end - tokens[i].start;
            if(len==4 && strncmp(chunk.memory + tokens[i].start, "data", 4) == 0) {
                int arr_idx = i+1;
                if(arr_idx >= tokcount || tokens[arr_idx].type != JSMN_ARRAY) break;
                int pos = arr_idx + 1;
                int elements = tokens[arr_idx].size;
                for(int el=0; el<elements && count<64; ++el) {
                    if(pos >= tokcount) break;
                    if(tokens[pos].type != JSMN_OBJECT) { pos = skip_token(tokens,pos,tokcount); continue; }
                    int obj_size = tokens[pos].size;
                    int j = pos + 1;
                    long id = 0;
                    char name[128] = "";
                    for(int kv=0; kv<obj_size; ++kv) {
                        if(tokens[j].type==JSMN_STRING) {
                            int klen = tokens[j].end - tokens[j].start;
                            if(klen==2 && strncmp(chunk.memory + tokens[j].start, "id",2)==0) {
                                if(tokens[j+1].type==JSMN_PRIMITIVE) {
                                    int vlen = tokens[j+1].end - tokens[j+1].start;
                                    char tmp[64]; memcpy(tmp, chunk.memory + tokens[j+1].start, vlen); tmp[vlen]=0;
                                    id = atol(tmp);
                                }
                            } else if(klen==4 && strncmp(chunk.memory + tokens[j].start, "name",4)==0) {
                                if(tokens[j+1].type==JSMN_STRING) {
                                    int vlen = tokens[j+1].end - tokens[j+1].start;
                                    int copylen = vlen < (int)sizeof(name)-1 ? vlen : (int)sizeof(name)-1;
                                    memcpy(name, chunk.memory + tokens[j+1].start, copylen); name[copylen]=0;
                                }
                            }
                        }
                        j = skip_token(tokens, j+1, tokcount);
                    }
                    pos = skip_token(tokens, pos, tokcount);
                    if(id && name[0]) {
                        ids[count] = id;
                        strncpy(names[count], name, sizeof(names[count])-1);
                        count++;
                    }
                }
                found = 1;
                break;
            }
        }
    }
    free(chunk.memory);
    if(!found || count==0) return 0;

    printf("Select a chat room by id:\n");
    for(int i=0;i<count;++i) printf("  %ld: %s\n", ids[i], names[i]);
    char buf[64];
    long sel = 0;
    while(1) {
        printf("Room id> ");
        if(!fgets(buf,sizeof(buf),stdin)) return 0;
        sel = atol(buf);
        for(int i=0;i<count;++i) if(ids[i]==sel) {
            selected_room_id = sel;
            snprintf(message_read_url, sizeof(message_read_url), "%s/api/chat/messages/%ld", tracker, selected_room_id);
            return 1;
        }
        printf("Invalid room id, try again.\n");
    }
    return 0;
}

// Skip a token and return the index of the next token after it
static int skip_token(const jsmntok_t *tokens, int idx, int tokn) {
    int i = idx;
    if(tokens[i].type == JSMN_OBJECT || tokens[i].type == JSMN_ARRAY) {
        int count = tokens[i].size;
        i++;
        for(int k = 0; k < count; ++k) {
            i = skip_token(tokens, i, tokn);
            /* object has key then value, so skip value after key
               however skip_token consumed both key and value during recursion */
        }
        return i;
    }
    return i + 1;
}

// Map a 6-digit hex color string ("#rrggbb") to an ncurses color pair index.
// We compute nearest base color and map that to predefined color pairs.
static int pick_color_pair_from_hex(const char *hex) {
    if(!hex || hex[0] == '\0') return 2; /* default pair */
    const char *p = hex;
    if(*p == '#') p++;
    if(strlen(p) < 6) return 2;
    unsigned int r=0,g=0,b=0;
    sscanf(p, "%2x%2x%2x", &r, &g, &b);
    /* base colors in RGB */
    const int base_rgb[8][3] = {
        {0,0,0},      /* black */
        {255,0,0},    /* red */
        {0,255,0},    /* green */
        {255,255,0},  /* yellow */
        {0,0,255},    /* blue */
        {255,0,255},  /* magenta */
        {0,255,255},  /* cyan */
        {255,255,255} /* white */
    };
    int best = 7; /* default white */
    long bestd = LONG_MAX;
    for(int i=0;i<8;i++){
        long dr = (int)r - base_rgb[i][0];
        long dg = (int)g - base_rgb[i][1];
        long db = (int)b - base_rgb[i][2];
        long d = dr*dr + dg*dg + db*db;
        if(d < bestd) { bestd = d; best = i; }
    }
    /* Map base color index to color pair:
       cyan/magenta/green -> pair 1,4,3 etc. */
    switch(best) {
        case 6: return 1; /* cyan -> user */
        case 5: return 4; /* magenta -> accent */
        case 2: return 3; /* green -> timestamp/accent */
        case 1: return 5; /* red -> error/accent */
        case 4: return 4; /* blue -> link/accent */
        default: return 2; /* white/default */
    }
}

// Display a message with username colored and formatted
static void display_message(const char *username, const char *message, const char *hexcolor) {
    int pair = pick_color_pair_from_hex(hexcolor);
    pthread_mutex_lock(&ui_lock);
    /* print username */
    wattron(out_win, COLOR_PAIR(pair) | A_BOLD);
    if(username && username[0]) {
        wprintw(out_win, "%s", username);
    } else {
        wprintw(out_win, "(unknown)");
    }
    wattroff(out_win, COLOR_PAIR(pair) | A_BOLD);
    wprintw(out_win, ": ");

    /* if message contains http, underline it */
    if(message && strstr(message, "http") != NULL) {
        wattron(out_win, A_UNDERLINE | COLOR_PAIR(4));
        wprintw(out_win, "%s", message);
        wattroff(out_win, A_UNDERLINE | COLOR_PAIR(4));
    } else {
        wattron(out_win, COLOR_PAIR(2));
        wprintw(out_win, "%s", message);
        wattroff(out_win, COLOR_PAIR(2));
    }
    wprintw(out_win, "\n");
    wrefresh(out_win);
    pthread_mutex_unlock(&ui_lock);
}

// Simple helper: find a key string inside [start,end) and return pointer to the quoted key occurrence (or NULL).
static const char *find_key_in_range(const char *start, const char *end, const char *key) {
    size_t klen = strlen(key);
    const char *p = start;
    while(p + klen <= end) {
        if(memcmp(p, key, klen) == 0) return p;
        p++;
    }
    return NULL;
}

// Extract a JSON string value for a given quoted key within [start,end). Returns 1 on success.
static int extract_string_in_range(const char *start, const char *end, const char *key, char *out, size_t outlen) {
    const char *k = find_key_in_range(start, end, key);
    if(!k) return 0;
    /* find colon */
    const char *c = k + strlen(key);
    while(c < end && *c != ':') c++;
    if(c >= end || *c != ':') return 0;
    c++;
    while(c < end && (*c == ' ' || *c == '\t' || *c == '\n' || *c == '\r')) c++;
    if(c >= end) return 0;
    if(*c != '"') return 0;
    /* parse quoted string, handling escapes */
    const char *s = c + 1;
    const char *r = s;
    char tmp[2048]; int ti = 0;
    while(r < end && *r) {
        if(*r == '"') {
            /* check if escaped */
            int back = 0; const char *b = r - 1;
            while(b >= s && *b == '\\') { back++; b--; }
            if(back % 2 == 0) break; /* not escaped */
        }
        if(ti + 1 < (int)sizeof(tmp)) tmp[ti++] = *r;
        r++;
    }
    tmp[ti] = '\0';
    /* unescape into out */
    json_unescape(tmp, ti, out, outlen);
    return 1;
}

// Extract a primitive (number/null/true/false) value for a key within [start,end). Returns 1 on success and copies into out.
static int extract_primitive_in_range(const char *start, const char *end, const char *key, char *out, size_t outlen) {
    const char *k = find_key_in_range(start, end, key);
    if(!k) return 0;
    const char *c = k + strlen(key);
    while(c < end && *c != ':') c++;
    if(c >= end || *c != ':') return 0;
    c++;
    while(c < end && (*c == ' ' || *c == '\t' || *c == '\n' || *c == '\r')) c++;
    if(c >= end) return 0;
    const char *r = c;
    int oi = 0;
    while(r < end && *r != ',' && *r != '}' && oi + 1 < (int)outlen) {
        out[oi++] = *r++;
    }
    out[oi] = '\0';
    /* trim trailing spaces */
    while(oi > 0 && (out[oi-1] == ' ' || out[oi-1] == '\r' || out[oi-1] == '\n' || out[oi-1] == '\t')) { out[oi-1] = '\0'; oi--; }
    return 1;
}

// Very lightweight extractor: scan the "data" array for object spans and only extract the keys we care about.
static void parse_and_display_json(const char *json) {
    if(!json) return;
    const char *p = strstr(json, "\"data\"");
    if(!p) return;
    p = strchr(p, '[');
    if(!p) return;
    const char *cur = p + 1;
    const char *endroot = json + strlen(json);

    char tmp[2048];
    char msgbuf[MAX_MSG_LEN];
    char username[128];
    char created_at[64];
    char colorhex[32];
    while(cur && cur < endroot) {
        /* find next '{' that starts an object */
        const char *obj = strchr(cur, '{');
        if(!obj) break;
        /* find matching '}' for this object, careful to skip strings */
        const char *r = obj;
        int depth = 0; int in_str = 0;
        const char *obj_end = NULL;
        for(; r < endroot; ++r) {
            char c = *r;
            if(c == '"') {
                /* check if escaped */
                int back = 0; const char *b = r - 1;
                while(b >= obj && *b == '\\') { back++; b--; }
                if(back % 2 == 0) in_str = !in_str;
            }
            if(in_str) continue;
            if(c == '{') depth++;
            else if(c == '}') {
                depth--;
                if(depth == 0) { obj_end = r + 1; break; }
            }
        }
        if(!obj_end) break;

        /* extract fields inside [obj, obj_end) */
        long id = 0; username[0] = '\0'; msgbuf[0] = '\0'; created_at[0] = '\0'; colorhex[0] = '\0';
        if (extract_primitive_in_range(obj, obj_end, "\"id\"", tmp, sizeof(tmp))) id = atol(tmp);
        if (extract_string_in_range(obj, obj_end, "\"message\"", msgbuf, sizeof(msgbuf))) html_strip_and_unescape(msgbuf);
        extract_string_in_range(obj, obj_end, "\"username\"", username, sizeof(username));
        extract_string_in_range(obj, obj_end, "\"created_at\"", created_at, sizeof(created_at));
        extract_string_in_range(obj, obj_end, "\"color\"", colorhex, sizeof(colorhex));

        if(id > last_id) {
            display_message(username, msgbuf, colorhex);
            if(id > last_id) last_id = id;
        }

        cur = obj_end;
    }
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct*)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) return 0; // should prolly handle this

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static int http_get(const char *url, MemoryStruct *out) {
    CURL *curl = curl_easy_init();
    if(!curl) return -1;
    struct curl_slist *headers = NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)out);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    /* If CHAT_COOKIES provided, send it explicitly as Cookie header */
    if(cookies[0]) {
        char ch[2048]; snprintf(ch, sizeof(ch), "Cookie: %s", cookies);
        headers = curl_slist_append(headers, ch);
    }

    if(headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    if(headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if(res != CURLE_OK) return -1;
    return 0;
}


static int http_post(const char *url, const char *json_body) {
    CURL *curl = curl_easy_init();
    if(!curl) return -1;
    struct curl_slist *headers = NULL;

    char rh[8192]; snprintf(rh, sizeof(rh), "Referer: %s", referer);
    char oh[8192]; snprintf(oh, sizeof(oh), "Origin: %s", origin);
    char ah[8192]; snprintf(ah, sizeof(ah), "Alt-Used: %s", referer);
    char xh[8192]; snprintf(xh, sizeof(xh), "X-XSRF-TOKEN: %s", xsrf_raw);
    char ch[8192]; snprintf(ch, sizeof(ch), "X-CSRF-TOKEN: %s", csrf_token);
    char ckh[8192]; snprintf(ckh, sizeof(ckh), "Cookie: %s", cookies);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br, zstd");
    headers = curl_slist_append(headers, "X-Requested-With: XMLHttpRequest");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Sec-Fetch-Dest: empty");
    headers = curl_slist_append(headers, "Sec-Fetch-Mode: cors");
    headers = curl_slist_append(headers, "Sec-Fetch-Site: same-origin");
    headers = curl_slist_append(headers, "Sec-GPC: 1");
    headers = curl_slist_append(headers, "Priority: u=0");
    headers = curl_slist_append(headers, "Pragma: no-cache");
    headers = curl_slist_append(headers, "Cache-Control: no-cache");

    headers = curl_slist_append(headers, ch);
    headers = curl_slist_append(headers, ckh);
    headers = curl_slist_append(headers, xh);
    headers = curl_slist_append(headers, rh);
    headers = curl_slist_append(headers, oh);
    headers = curl_slist_append(headers, ah);


    /* capture response body to help debugging on errors */
    MemoryStruct resp = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    if(res != CURLE_OK || code < 200 || code >= 300) {
        char outbuf[1024];
        snprintf(outbuf, sizeof(outbuf), "[error] failed to send message (HTTP %ld)", code);
        append_output(outbuf);
        if(resp.memory && resp.size > 0) {
            /* sanitize and append a short snippet */
            char snip[512];
            int sniplen = resp.size < (int)sizeof(snip)-1 ? (int)resp.size : (int)sizeof(snip)-1;
            memcpy(snip, resp.memory, sniplen); snip[sniplen] = '\0';
            html_strip_and_unescape(snip);
            char out2[1024];
            snprintf(out2, sizeof(out2), "[server] %s", snip);
            append_output(out2);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(resp.memory);

    return (res == CURLE_OK && code >= 200 && code < 300) ? 0 : -1;
}

static void append_output(const char *line) {
    pthread_mutex_lock(&ui_lock);
    wprintw(out_win, "%s\n", line);
    wrefresh(out_win);
    pthread_mutex_unlock(&ui_lock);
}

static void *reader_thread(void *arg) {
    (void)arg;
    while(running) {
        MemoryStruct chunk = {0};
        if(http_get(message_read_url, &chunk) == 0 && chunk.size > 0) parse_and_display_json(chunk.memory);
        free(chunk.memory);
        for(int i=0; i<POLL_INTERVAL && running; ++i) sleep(1);
    }
    return NULL;
}

static void *writer_thread(void *arg) {
    (void)arg;
    char buf[MAX_MSG_LEN];
    while(running) {
        /* Prepare the input box (brief critical section), then release lock while blocking on input */
        pthread_mutex_lock(&ui_lock);
        werase(in_win);
        box(in_win, 0, 0);
        mvwprintw(in_win, 1, 1, "> ");
        wrefresh(in_win);
        echo();
        curs_set(1);
        pthread_mutex_unlock(&ui_lock);

        /* Blocking call left outside the mutex so reader can update output while user types */
        mvwgetnstr(in_win, 1, 3, buf, sizeof(buf)-1);

        pthread_mutex_lock(&ui_lock);
        noecho();
        curs_set(0);
        pthread_mutex_unlock(&ui_lock);

        if(!running) break;
        if(strlen(buf) == 0) continue;
        if(strcmp(buf, "/quit") == 0) {
            running = 0;
            break;
        }

        char body[MAX_MSG_LEN+128];
        /* include chatroom_id and simple message body; minimal escaping */
        snprintf(body, sizeof(body), "{\"user_id\":18518,\"receiver_id\":null,\"bot_id\":null,\"chatroom_id\":%ld,\"message\":\"%s\",\"targeted\":0}", selected_room_id, buf);
        if(http_post(message_send_url, body) != 0) append_output("[error] failed to send message");
    }
    return NULL;
}

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    /* Load configuration from file (required). Try ./chat.conf then $HOME/.config/chat.conf */
    int cfg_loaded = 0;
    if(load_config("./chat.conf")) cfg_loaded = 1;
    else {
        const char *home = getenv("HOME");
        if(home) {
            char homecfg[512];
            snprintf(homecfg, sizeof(homecfg), "%s/.config/chat.conf", home);
            if(load_config(homecfg)) cfg_loaded = 1;
        }
    }
    if(!cfg_loaded) {
        fprintf(stderr, "Config file not found or missing CHAT_API_BASE. Create ./chat.conf or $HOME/.config/chat.conf\n");
        return 1;
    }

    if(!tracker[0]) {
        fprintf(stderr, "Config file not found or missing TRACKER. Create ./chat.conf or $HOME/.config/chat.conf\n");
        return 1;
    }
    if(!parse_rooms_and_prompt()) {
        fprintf(stderr, "Failed to fetch or select a chat room\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    // ncurses init
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    if(has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_CYAN, -1);   /* username */
        init_pair(2, COLOR_WHITE, -1);  /* message */
        init_pair(3, COLOR_GREEN, -1);  /* timestamp/accent */
        init_pair(4, COLOR_BLUE, -1);   /* links */
        init_pair(5, COLOR_RED, -1);    /* error */
    }

    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    out_win = newwin(rows - INPUT_HEIGHT, cols, 0, 0);
    in_win = newwin(INPUT_HEIGHT, cols, rows - INPUT_HEIGHT, 0);
    scrollok(out_win, TRUE);
    box(in_win, 0, 0);
    wrefresh(out_win);
    wrefresh(in_win);

    signal(SIGINT, handle_sigint);

    pthread_t rthread, wthread;
    if(pthread_create(&rthread, NULL, reader_thread, NULL) != 0) {
        endwin();
        fprintf(stderr, "Failed to create reader thread\n");
        return 1;
    }
    if(pthread_create(&wthread, NULL, writer_thread, NULL) != 0) {
        running = 0;
        pthread_join(rthread, NULL);
        endwin();
        fprintf(stderr, "Failed to create writer thread\n");
        return 1;
    }

    pthread_join(wthread, NULL);
    running = 0;
    pthread_join(rthread, NULL);

    delwin(out_win);
    delwin(in_win);
    endwin();

    curl_global_cleanup();

    return 0;
}
