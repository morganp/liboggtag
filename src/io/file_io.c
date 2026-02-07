/*
 * file_io.c – Buffered POSIX file I/O with lazy seek
 */

#include "file_io.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int fio_open(file_io_t *fio, const char *path, int read_write)
{
    memset(fio, 0, sizeof(*fio));
    fio->fd = open(path, read_write ? O_RDWR : O_RDONLY);
    if (fio->fd < 0) return -1;
    fio->buf_start = -1;
    return 0;
}

void fio_close(file_io_t *fio)
{
    if (fio->fd >= 0) {
        close(fio->fd);
        fio->fd = -1;
    }
}

int fio_seek(file_io_t *fio, off_t offset)
{
    fio->file_pos = offset;
    fio->dirty = 1;
    return 0;
}

off_t fio_tell(const file_io_t *fio)
{
    return fio->file_pos;
}

off_t fio_size(file_io_t *fio)
{
    off_t cur = lseek(fio->fd, 0, SEEK_CUR);
    off_t end = lseek(fio->fd, 0, SEEK_END);
    lseek(fio->fd, cur, SEEK_SET);
    return end;
}

static int fio_fill(file_io_t *fio)
{
    if (fio->dirty ||
        fio->file_pos < fio->buf_start ||
        fio->file_pos >= fio->buf_start + (off_t)fio->buf_len) {
        if (lseek(fio->fd, fio->file_pos, SEEK_SET) < 0)
            return -1;
        ssize_t n = read(fio->fd, fio->buf, FIO_BUF_SIZE);
        if (n < 0) return -1;
        fio->buf_start = fio->file_pos;
        fio->buf_len   = (size_t)n;
        fio->buf_pos   = 0;
        fio->dirty     = 0;
    } else {
        fio->buf_pos = (size_t)(fio->file_pos - fio->buf_start);
    }
    return 0;
}

int fio_read(file_io_t *fio, void *dst, size_t len)
{
    uint8_t *out = (uint8_t *)dst;
    size_t   rem = len;
    while (rem > 0) {
        if (fio_fill(fio) < 0) return -1;
        size_t avail = fio->buf_len - fio->buf_pos;
        if (avail == 0) return -1;  /* EOF */
        size_t n = (rem < avail) ? rem : avail;
        memcpy(out, fio->buf + fio->buf_pos, n);
        out           += n;
        rem           -= n;
        fio->file_pos += (off_t)n;
        fio->buf_pos  += n;
    }
    return 0;
}

int fio_write(file_io_t *fio, const void *src, size_t len)
{
    if (lseek(fio->fd, fio->file_pos, SEEK_SET) < 0) return -1;
    const uint8_t *p = (const uint8_t *)src;
    size_t rem = len;
    while (rem > 0) {
        ssize_t n = write(fio->fd, p, rem);
        if (n <= 0) return -1;
        p             += n;
        rem           -= (size_t)n;
        fio->file_pos += n;
    }
    /* Invalidate read buffer */
    fio->buf_start = -1;
    fio->buf_len   = 0;
    fio->dirty     = 1;
    return 0;
}

int fio_truncate(file_io_t *fio, off_t length)
{
    if (ftruncate(fio->fd, length) < 0) return -1;
    fio->buf_start = -1;
    fio->buf_len   = 0;
    fio->dirty     = 1;
    return 0;
}
