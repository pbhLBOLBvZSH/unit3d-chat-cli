/* jsmn - JSON parser in C, minimal implementation (public domain / MIT style)
 * Header for a small JSON tokenizer used to parse the chat API response.
 * This is the official jsmn public domain header adapted for inclusion.
 */

#ifndef JSMN_H
#define JSMN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef enum {
    JSMN_UNDEFINED = 0,
    JSMN_OBJECT = 1,
    JSMN_ARRAY = 2,
    JSMN_STRING = 3,
    JSMN_PRIMITIVE = 4
} jsmntype_t;

/* JSON token description. type is the token type (object, array, string, primitive). 
 * start and end are indices in the JSON string. size is the number of child tokens.
 */
typedef struct {
    jsmntype_t type;
    int start;
    int end;
    int size;
} jsmntok_t;

typedef struct {
    unsigned int pos; /* offset in the JSON string */
    unsigned int toknext; /* next token to allocate */
    int toksuper; /* superior token node, e.g. parent object or array */
} jsmn_parser;

void jsmn_init(jsmn_parser *parser);
int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
               jsmntok_t *tokens, unsigned int num_tokens);

#ifdef __cplusplus
}
#endif

#endif /* JSMN_H */