/*
 * ogg_crc.h – Ogg CRC-32 (polynomial 0x04C11DB7, direct / non-reflected)
 */

#ifndef OGG_CRC_H
#define OGG_CRC_H

#include <stddef.h>
#include <stdint.h>

uint32_t ogg_crc_update(uint32_t crc, const uint8_t *data, size_t len);
uint32_t ogg_crc_calc(const uint8_t *data, size_t len);

#endif /* OGG_CRC_H */
