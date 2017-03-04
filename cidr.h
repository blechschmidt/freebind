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
	char *token = str;
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
		if(cidr->protocol == 4 && mask > 32 || cidr->protocol == 6 && mask > 128)
		{
			return 0;
		}
		cidr->mask = (uint8_t)mask;
	}
	bitwise_clear(cidr->prefix, cidr->mask, (cidr->protocol == 4 ? 32 : 128) - cidr->mask); // zero out the bytes that are not covered by the mask
	return 1;
}
#endif
