/**********************************************************************
 * Copyright (c) 2020-2023
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 **********************************************************************/

#include "bitmap.h"
#include "nvmev.h"

long small_nbits;
long large_nbits;
unsigned long small_bitmap[600000];
unsigned long large_bitmap[300000];
long small_capacity;
long large_capacity;

size_t small_last_pos;
size_t large_last_pos;

static unsigned long long dev_size;
static unsigned long long total_written;

void bits_print(unsigned long *v, u32 nbits)
{
    s32 i;
    u32 wc = BIT_WORD(nbits);
    u64 mask1, mask2 = BIT(BITS_PER_TYPE(long) - 1);

    for (i = wc; i >= 0; i--) {
        printk("v[%d] = ", i);
        mask1 = mask2;
        while (mask1) {
            printk("%d", (v[i] & mask1 ? 1 : 0));
            mask1 >>= 1;
        }
        printk("\n");
    }

    printk("\n");
}

int bitmap_allocator_init(u64 size)
{
    dev_size = size;

    small_nbits = size/2/SMALL_LENGTH;
    large_nbits = size/2/LARGE_LENGTH;

    // nbits = 10;
    NVMEV_INFO("small_bitmap size = %zu bits, %lu %lu\n", sizeof(small_bitmap) * BITS_PER_BYTE, small_nbits, BITS_TO_LONGS(small_nbits));
	NVMEV_INFO("large_bitmap size = %zu bits, %lu %lu\n", sizeof(large_bitmap) * BITS_PER_BYTE, large_nbits, BITS_TO_LONGS(large_nbits));

    bitmap_zero(small_bitmap, small_nbits);
    bitmap_zero(large_bitmap, large_nbits);

	NVMEV_INFO("Initialized an bitmap with size %llu", size);
	return 1;
}

size_t bitmap_allocate(u64 length, void* args)
{
    size_t off;
    size_t calculated_offset;

    total_written += length;

    if (length > LARGE_LENGTH) {
        NVMEV_ERROR("Invalid length want bitmap allocation!!");
    }

    if (length > SMALL_LENGTH) {
        off = bitmap_find_next_zero_area(large_bitmap, large_nbits, large_last_pos, 1, 0);  // pos = 0, n = 1, mask = 0
        bitmap_set(large_bitmap, off, 1);

		large_last_pos = off + 1;
		if (large_last_pos > large_nbits) {
			large_last_pos = 0;
		}

        calculated_offset = dev_size / 2 + off * LARGE_LENGTH;


        NVMEV_DEBUG("large_allocate(%llu): returning offset %llu, %luth bitmap index", length, calculated_offset, off);

        large_capacity++;
        if (large_capacity > (large_nbits - 10))
            NVMEV_INFO("large bitmap is nearly full!!");
    }
    else {
        off = bitmap_find_next_zero_area(small_bitmap, small_nbits, small_last_pos, 1, 0);  // pos = 0, n = 1, mask = 0
        bitmap_set(small_bitmap, off, 1);

        small_last_pos = off + 1;
        if (small_last_pos > small_nbits) {
			small_last_pos = 0;
		}

        calculated_offset = off * SMALL_LENGTH;

        NVMEV_DEBUG("small_allocate(%llu): returning offset %llu, %luth bitmap index", length, calculated_offset, off);

        small_capacity++;
        if (small_capacity > (small_nbits - 10))
            NVMEV_INFO("small bitmap is nearly full!!");
    }

    return calculated_offset;
}

void bitmap_kill(void)
{

}


//inline uint64_t find_next_zero_bit(char *bitmap, uint64_t nbits, uint64_t sidx)
//{
//	uint64_t idx;
//	for (idx = sidx; idx < nbits; idx ++) {
//		if (wftl_test_bit(idx, bitmap) == 0) {
//			return idx;
//		}
//	}
//	return idx;
//}







