#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cidr.h"
#include "bitwise.h"

void test_cidr_from_string_1()
{
	cidr_t cidr;
	char ip[] = "127.2.3.4";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 32);
	uint8_t expected[] = {127, 2, 3, 4};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_2()
{
	cidr_t cidr;
	char ip[] = "127.127.212.0/24";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 24);
	uint8_t expected[] = {127, 127, 212, 0};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_3()
{
	cidr_t cidr;
	char ip[] = "2a00:1450:4001:ffff:ffff::200e/63";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 63);
	uint8_t expected[] = {0x2a, 0x00, 0x14, 0x50, 0x40, 0x01, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_4()
{
	cidr_t cidr;
	char ip[] = "2a00:1450:4001:ffff:ffff::200e/65";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 65);
	uint8_t expected[] = {0x2a, 0x00, 0x14, 0x50, 0x40, 0x01, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_5()
{
	cidr_t cidr;
	char ip[] = "2a00:1450:4001:ffff:ffff::200e/64";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 64);
	uint8_t expected[] = {0x2a, 0x00, 0x14, 0x50, 0x40, 0x01, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_6()
{
	cidr_t cidr;
	char ip[] = "2a00:1450:4001:ffff:ffff::200e/0";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 0);
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_7()
{
	cidr_t cidr;
	char ip[] = "2a00:1450:4001:ffff:ffff::200e/128";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 128);
	uint8_t expected[] = {0x2a, 0x00, 0x14, 0x50, 0x40, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_cidr_from_string_8()
{
	cidr_t cidr;
	char ip[] = "ffff:1450:4001:ffff:ffff::200e/2";
	int result = cidr_from_string(&cidr, ip);
	assert(result == 1);
	assert(cidr.mask == 2);
	uint8_t expected[] = {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	assert(memcmp(expected, cidr.prefix, sizeof(expected)) == 0);
}

void test_bitwise_clear_1()
{
	uint8_t data[] = {0xff, 0xff};
	bitwise_clear(data, 1, 8);
	uint8_t expected[] = {0x80, 0x7f};
	assert(memcmp(expected, data, sizeof(data)) == 0);
}

void main()
{
	test_bitwise_clear_1();
	test_cidr_from_string_1();
	test_cidr_from_string_2();
	test_cidr_from_string_3();
	test_cidr_from_string_4();
	test_cidr_from_string_5();
	test_cidr_from_string_6();
	test_cidr_from_string_7();
	test_cidr_from_string_8();
}
