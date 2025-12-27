#include "jsmn.h"
#include <string.h>
#include <stdio.h>

/* Minimal jsmn implementation (small subset) */
#define JSMN_ERROR_NOMEM -1
#define JSMN_ERROR_INVAL -2
#define JSMN_ERROR_PART -3

static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser, jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *tok;
    if (parser->toknext >= num_tokens) return NULL;
    tok = &tokens[parser->toknext++];
    tok->start = tok->end = -1;
    tok->size = 0;
    tok->type = JSMN_UNDEFINED;
    return tok;
}

void jsmn_init(jsmn_parser *parser) {
    parser->pos = 0;
    parser->toknext = 0;
    parser->toksuper = -1;
}

static int jsmn_parse_primitive(jsmn_parser *parser, const char *js, size_t len,
                                jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *token;
    int start = parser->pos;

    for (; parser->pos < (unsigned)len; parser->pos++) {
        switch (js[parser->pos]) {
            case '\t': case '\r': case '\n': case ' ': case ',': case ']': case '}':
                goto found;
            default:
                if (js[parser->pos] < 32) return JSMN_ERROR_INVAL;
        }
    }
found:
    if (tokens == NULL) {
        parser->pos--;
        return 0;
    }
    token = jsmn_alloc_token(parser, tokens, num_tokens);
    if (token == NULL) return JSMN_ERROR_NOMEM;
    token->type = JSMN_PRIMITIVE;
    token->start = start;
    token->end = parser->pos;
    token->size = 0;
    parser->pos--;
    return 0;
}

static int jsmn_parse_string(jsmn_parser *parser, const char *js, size_t len,
                             jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *token;
    int start = parser->pos++;

    for (; parser->pos < (unsigned)len; parser->pos++) {
        char c = js[parser->pos];
        if (c == '"') {
            if (tokens == NULL) { parser->pos++; return 0; }
            token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (token == NULL) return JSMN_ERROR_NOMEM;
            token->type = JSMN_STRING;
            token->start = start + 1;
            token->end = parser->pos;
            token->size = 0;
            return 0;
        }
        if (c == '\\') parser->pos++;
    }
    return JSMN_ERROR_PART;
}

int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
               jsmntok_t *tokens, unsigned int num_tokens) {
    int r;
    for (; parser->pos < (unsigned)len; parser->pos++) {
        char c = js[parser->pos];
        switch (c) {
            case '{': case '[': {
                jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
                if (token == NULL) return JSMN_ERROR_NOMEM;
                token->type = (c == '{') ? JSMN_OBJECT : JSMN_ARRAY;
                token->start = parser->pos;
                token->size = 0;
                token->end = -1;
                if (parser->toksuper != -1) tokens[parser->toksuper].size++;
                parser->toksuper = parser->toknext - 1;
                break;
            }
            case '}': case ']': {
                jsmntok_t *token;
                jsmntype_t type = (c == '}') ? JSMN_OBJECT : JSMN_ARRAY;
                int i;
                for (i = parser->toknext - 1; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) return JSMN_ERROR_INVAL;
                        token->end = parser->pos + 1;
                        parser->toksuper = -1;
                        for (i = i - 1; i >= 0; i--) {
                            if (tokens[i].start != -1 && tokens[i].end == -1) { parser->toksuper = i; break; }
                        }
                        break;
                    }
                }
                break;
            }
            case '"':
                r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
                if (r < 0) return r;
                if (parser->toksuper != -1) tokens[parser->toksuper].size++;
                break;
            case '\t': case '\r': case '\n': case ' ':
                break;
            case ':':
                break;
            case ',':
                break;
            case '\\':
                /* backslash outside of a string is invalid JSON */
                return JSMN_ERROR_INVAL;
            default:
                r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
                if (r < 0) return r;
                if (parser->toksuper != -1) tokens[parser->toksuper].size++;
                break;
        }
    }
    return parser->toknext;
}