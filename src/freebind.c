#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>

#include "list.h"
#include "cidr.h"

char *env_iface;
buffer_t socket_cidrs_ipv4;
buffer_t socket_cidrs_ipv6;
int bind_upon_connect = 0;
int (*original_connect)(int, const struct sockaddr*, socklen_t);
int (*original_socket)(int, int, int);


void free_buf_array(buffer_t *arr)
{
	for(size_t i = 0; i < arr->len; i++)
	{
		free(((void**)arr->data)[i]);
	}
}

void __attribute__((destructor))  cleanup()
{
	free_buf_array(&socket_cidrs_ipv4);
	free_buf_array(&socket_cidrs_ipv6);
}

void __attribute__((constructor)) initialize()
{
	struct timespec ts;
	char *env_random;
	char *env_bind_entrypoint;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	srand(ts.tv_sec + ts.tv_nsec);
	
	env_iface = getenv("FREEBIND_IFACE");
	
	env_bind_entrypoint = getenv("FREEBIND_ENTRYPOINT");
	if(env_bind_entrypoint != NULL && strcasecmp("connect", env_bind_entrypoint) == 0)
	{
		bind_upon_connect = 1;
	}

	char *tenv_random = getenv("FREEBIND_RANDOM");
	if(tenv_random == NULL)
	{
		return;
	}

	// Copy because strtok_r modifies the string, which would break the environment for child processes
	env_random = safe_malloc(strlen(tenv_random) + 1);
	strcpy(env_random, tenv_random);

	single_list_t* cidr_list_ipv4 = single_list_new();
	single_list_t* cidr_list_ipv6 = single_list_new();
	char *token;
	char *remaining = env_random;
	for (token = strtok_r(remaining, ", ", &remaining); token != NULL; token = strtok_r(NULL, ", ", &remaining))
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
	free(env_random);
	socket_cidrs_ipv4 = single_list_to_array(cidr_list_ipv4);
	single_list_free(cidr_list_ipv4);
	socket_cidrs_ipv6 = single_list_to_array(cidr_list_ipv6);
	single_list_free(cidr_list_ipv6);
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
			ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = 0;
			if(setsockopt(result, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
			{
				perror("Freebind: Failed to bind to device");
			}
		}
	}
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len)
{
	if(!original_connect)
	{
		original_connect = dlsym(RTLD_NEXT, "connect");
	}
	if(bind_upon_connect)
	{
		freebind(socket);
	}
	return original_connect(socket, address, address_len);
}

int socket(int domain, int type, int protocol)
{
	if(!original_socket)
	{
		original_socket = dlsym(RTLD_NEXT, "socket");
	}
	int result = original_socket(domain, type, protocol);
	if(!bind_upon_connect)
	{
		freebind(result);
	}
	return result;
}
