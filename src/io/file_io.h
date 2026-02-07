/*
 * file_io.h – Buffered POSIX file I/O
 */

#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define FIO_BUF_SIZE 8192

typedef struct {
    int      fd;
    uint8_t  buf[FIO_BUF_SIZE];
    size_t   buf_pos;
    size_t   buf_len;
    off_t    file_pos;   /* logical position */
    off_t    buf_start;  /* file offset where buf[0] came from */
    int      dirty;      /* lazy-seek flag */
} file_io_t;

int   fio_open(file_io_t *fio, const char *path, int read_write);
void  fio_close(file_io_t *fio);
int   fio_seek(file_io_t *fio, off_t offset);
off_t fio_tell(const file_io_t *fio);
off_t fio_size(file_io_t *fio);
int   fio_read(file_io_t *fio, void *dst, size_t len);
int   fio_write(file_io_t *fio, const void *src, size_t len);
int   fio_truncate(file_io_t *fio, off_t length);

#endif /* FILE_IO_H */
