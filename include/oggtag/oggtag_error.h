/*
 * oggtag_error.h – Error codes for liboggtag
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OGGTAG_ERROR_H
#define OGGTAG_ERROR_H

#define OGGTAG_OK                    0

/* Generic errors */
#define OGGTAG_ERR_INVALID_ARG      -1
#define OGGTAG_ERR_NO_MEMORY        -2
#define OGGTAG_ERR_IO               -3
#define OGGTAG_ERR_NOT_OPEN         -4
#define OGGTAG_ERR_ALREADY_OPEN     -5
#define OGGTAG_ERR_READ_ONLY        -6

/* Format errors */
#define OGGTAG_ERR_NOT_OGG          -10
#define OGGTAG_ERR_BAD_HEADER       -11
#define OGGTAG_ERR_CORRUPT          -12
#define OGGTAG_ERR_TRUNCATED        -13
#define OGGTAG_ERR_UNSUPPORTED      -14
#define OGGTAG_ERR_BAD_CRC          -15

/* Tag errors */
#define OGGTAG_ERR_NO_TAGS          -20
#define OGGTAG_ERR_TAG_NOT_FOUND    -21
#define OGGTAG_ERR_TAG_TOO_LARGE    -22

/* Write errors */
#define OGGTAG_ERR_NO_SPACE         -30
#define OGGTAG_ERR_WRITE_FAILED     -31
#define OGGTAG_ERR_SEEK_FAILED      -32
#define OGGTAG_ERR_RENAME_FAILED    -33

#endif /* OGGTAG_ERROR_H */
