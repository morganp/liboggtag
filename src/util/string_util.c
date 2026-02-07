/*
 * string_util.c – String helpers
 */

#include "string_util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

char *str_dup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *p = (char *)malloc(len + 1);
    if (p) memcpy(p, s, len + 1);
    return p;
}

int str_casecmp(const char *a, const char *b)
{
    if (!a || !b) return a != b;
    while (*a && *b) {
        int d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (d) return d;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

void str_copy(char *dst, size_t dst_size, const char *src)
{
    if (!dst || !dst_size) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}
