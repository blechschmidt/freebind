#ifndef INC_CIDR
#define INC_CIDR

#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "bitwise.h"

typedef struct
{
	uint8_t protocol;
	uint8_t mask;
	uint8_t prefix[16];
} cidr_t;

int str_is_numeric(char *str)
{
	while(*str != 0)
	{
		if(!isdigit(*str))
		{
			return 0;
		}
		str++;
	}
	return 1;
}

int ipv4_str_to_buf(char *str, uint8_t *buf)
{
	if(strstr(str, ".") == NULL)
	{
		return 0;
	}
	return inet_pton(AF_INET, str, buf) == 1;
}

int ipv6_str_to_buf(char *str, uint8_t *buf)
{
	if(strstr(str, ":") == NULL)
	{
		return 0;
	}
	return inet_pton(AF_INET6, str, buf) == 1;
}

int cidr_from_string(cidr_t *cidr, char *str)
{
	if(str == NULL)
	{
		return 0;
	}

	char *remaining = str;
	strtok_r(remaining, "/", &remaining);
	if(ipv4_str_to_buf(str, cidr->prefix))
	{
		cidr->protocol = 4;
		cidr->mask = 32;
	}
	else if(ipv6_str_to_buf(str, cidr->prefix))
	{
		cidr->protocol = 6;
		cidr->mask = 128;
	}
	else
	{
		return 0;
	}

	if(remaining != NULL && *remaining != 0)
	{
		if(!str_is_numeric(remaining) || strlen(remaining) > 3) // strlen check for prevention atoi failures
		{
			return 0;
		}
		int mask = atoi(remaining);
		if((cidr->protocol == 4 && mask > 32) || (cidr->protocol == 6 && mask > 128))
		{
			return 0;
		}
		cidr->mask = (uint8_t)mask;
	}
	bitwise_clear(cidr->prefix, cidr->mask, (cidr->protocol == 4 ? 32 : 128) - cidr->mask); // zero out the bytes that are not covered by the mask
	return 1;
}

void get_random_bytes(uint8_t *buf, size_t len) // not cryptographically secure
{
	for(size_t i = 0; i < len; i++)
	{
		buf[i] = rand();
	}
}

int get_random_address_from_cidr(cidr_t *cidr, buffer_t *buf)
{
	if(cidr->protocol == 4)
	{
		struct sockaddr_in *ip4addr = safe_malloc(sizeof(*ip4addr));
		ip4addr->sin_family = AF_INET;
		ip4addr->sin_port = 0;
		uint8_t random[4];
		get_random_bytes(random, sizeof(random));
		bitwise_clear(random, 0, cidr->mask);
		bitwise_xor((uint8_t*)&ip4addr->sin_addr.s_addr, random, cidr->prefix, sizeof(random));
		buf->len = sizeof(*ip4addr);
		buf->data = ip4addr;
	}
	else if(cidr->protocol == 6)
	{
		struct sockaddr_in6 *ip6addr = safe_malloc(sizeof(*ip6addr));
		bzero(ip6addr, sizeof(*ip6addr));
		ip6addr->sin6_family = AF_INET6;
		ip6addr->sin6_port = 0;
		uint8_t random[16];
		get_random_bytes(random, sizeof(random));
		bitwise_clear(random, 0, cidr->mask);
		bitwise_xor((uint8_t*)&ip6addr->sin6_addr.s6_addr, random, cidr->prefix, sizeof(random));
		buf->len = sizeof(*ip6addr);
		buf->data = ip6addr;
	}
	else
	{
		buf->len = 0;
		buf->data = NULL;
		return 0;
	}
	return 1;
}

#endif
