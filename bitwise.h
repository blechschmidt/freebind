#ifndef INC_BITWISE
#define INC_BITWISE

void bitwise_xor(uint8_t *dst, uint8_t *src1, uint8_t *src2, size_t len)
{
	for(size_t i = 0; i < len; i++)
	{
		dst[i] = src1[i] ^ src2[i];
	}
}

void bitwise_clear(uint8_t *buf, size_t bit_offset, size_t bit_len)
{
	for(size_t i = bit_offset; i < bit_offset + bit_len; i++)
	{
		buf[i / 8] &= ~(1 << (7 -(i % 8)));
	}
}
#endif
