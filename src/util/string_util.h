/*
 * string_util.h – String helpers
 */

#ifndef STRING_UTIL_H
#define STRING_UTIL_H

#include <stddef.h>

char *str_dup(const char *s);
int   str_casecmp(const char *a, const char *b);
void  str_copy(char *dst, size_t dst_size, const char *src);

#endif /* STRING_UTIL_H */
