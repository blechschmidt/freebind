#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>

#include "list.h"
#include "cidr.h"

char *env_random;
char *env_iface;
char *env_bind_entrypoint;
buffer_t socket_cidrs_ipv4;
buffer_t socket_cidrs_ipv6;
int bind_upon_connect = 0;

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
		char random[4];
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
		char random[16];
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

void free_buf_array(buffer_t *arr)
{
	for(size_t i = 0; i < arr->len; i++)
	{
		free(((void**)arr->data)[i]);
	}
}

void cleanup()
{
	free_buf_array(&socket_cidrs_ipv4);
	free_buf_array(&socket_cidrs_ipv6);
}

void __attribute__((constructor)) initialize()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	srand(ts.tv_sec + ts.tv_nsec);
	
	env_iface = getenv("FREEBIND_IFACE");
	
	env_bind_entrypoint = getenv("FREEBIND_ENTRYPOINT");
	if(env_bind_entrypoint != NULL && strcasecmp("connect", env_bind_entrypoint) == 0)
	{
		bind_upon_connect = 1;
	}

	env_random = getenv("FREEBIND_RANDOM");
	if(env_random == NULL)
	{
		return;
	}

	single_list_t* cidr_list_ipv4 = single_list_new();
	single_list_t* cidr_list_ipv6 = single_list_new();
	char *token;
	char *remaining = env_random;
	while((token = strtok_r(remaining, ", ", &remaining)))
	{
		cidr_t *cidr = safe_malloc(sizeof(*cidr));
		if(!cidr_from_string(cidr, token))
		{
			free(cidr);
			continue;
		}
		if(cidr->protocol == 4)
		{
			single_list_push_back(cidr_list_ipv4, cidr);
		}
		else if(cidr->protocol == 6)
		{
			single_list_push_back(cidr_list_ipv6, cidr);
		}
	}
	socket_cidrs_ipv4 = single_list_to_array(cidr_list_ipv4);
	single_list_free(cidr_list_ipv4);
	socket_cidrs_ipv6 = single_list_to_array(cidr_list_ipv6);
	single_list_free(cidr_list_ipv6);
	atexit(cleanup);
}

void freebind(int result)
{
	int domain;
	socklen_t optlen = sizeof(int);
	if(getsockopt(result, SOL_SOCKET, SO_DOMAIN, &domain, &optlen) != 0)
	{
		perror("Freebind: Failed to determine socket type");
		return;
	}
	if(domain == PF_INET || domain == PF_INET6)
	{
		const int enable = 1;
		setsockopt(result, SOL_IP, IP_FREEBIND, &enable, sizeof(enable));

		buffer_t *socket_cidrs = &socket_cidrs_ipv4;
		if(domain == PF_INET6)
		{
			socket_cidrs = &socket_cidrs_ipv6;
		}
		if(socket_cidrs->len > 0)
		{
			buffer_t address;
			if(get_random_address_from_cidr(((cidr_t**)socket_cidrs->data)[rand() % socket_cidrs->len], &address))
			{
				if(bind(result, (struct sockaddr*)address.data, address.len) != 0)
				{
					perror("Freebind: Failed to bind to specified address");
				}
				free(address.data);
			}
		}
		if(env_iface != NULL)
		{
			struct ifreq ifr;
			strncpy(ifr.ifr_name, env_iface, sizeof(ifr.ifr_name));
			if(setsockopt(result, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
			{
				perror("Freebind: Failed to bind to device");
			}
		}
	}
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len)
{
	int (*original_connect)(int, const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "connect");
	if(bind_upon_connect)
	{
		freebind(socket);
	}
	return original_connect(socket, address, address_len);
}

int socket(int domain, int type, int protocol)
{
	int (*original_socket)(int, int, int) = dlsym(RTLD_NEXT, "socket");
	int result = original_socket(domain, type, protocol);
	if(!bind_upon_connect)
	{
		freebind(result);
	}
	return result;
}
