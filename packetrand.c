#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "buffers.h"
#include "list.h"
#include "cidr.h"

int queue_num;
unsigned char packetbuf[4096];
buffer_t cidrs_ipv4;
buffer_t cidrs_ipv6;
struct nfq_handle *h;
struct nfq_q_handle *qh;
int fd;
int rv;
char buf[4096] __attribute__ ((aligned));

static uint32_t print_pkt (struct nfq_data *tb, int *size)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    uint16_t proto;
    size_t packet_len;
    unsigned char *packet_data;

    ph = nfq_get_msg_packet_hdr(tb);
    if(!ph)
    {
        return id;
    }
    id = ntohl(ph->packet_id);
    proto = ntohs(ph->hw_protocol);
    if(proto != 0x86dd && proto != 0x800)
    {
        return id;
    }
    
    packet_len = nfq_get_payload(tb, &packet_data);
    if (packet_len >= 0 && packet_len <= sizeof(packetbuf))
    {
        *size = packet_len;
        memcpy(packetbuf, packet_data, packet_len);
        if(proto == 0x800 && packet_len >= 16 && cidrs_ipv4.len > 0)
        {
            cidr_t *cidr = ((cidr_t**)cidrs_ipv4.data)[rand() % cidrs_ipv4.len];
            char random[4];
            get_random_bytes(random, sizeof(random));
            bitwise_clear(random, 0, cidr->mask);
            bitwise_xor(packetbuf + 12, random, cidr->prefix, sizeof(random));
        }
        else if(proto == 0x86dd && packet_len >= 24 && cidrs_ipv6.len > 0)
        {
            cidr_t *cidr = ((cidr_t**)cidrs_ipv6.data)[rand() % cidrs_ipv6.len];
            char random[16];
            get_random_bytes(random, sizeof(random));
            bitwise_clear(random, 0, cidr->mask);
            bitwise_xor(packetbuf + 8, random, cidr->prefix, sizeof(random));
        }
    }

    return id;
}
    

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int size = 0;
    u_int32_t id = print_pkt(nfa, &size);
    return nfq_set_verdict(qh, id, NF_ACCEPT, size, packetbuf);
}

void print_help(char *name)
{
    fprintf(stderr, "Usage: %s <queue-num> cidr0 [ cidr1 [ ...cidrN ] ]\n", name);
}

int main(int argc, char **argv)
{
    single_list_t* cidr_list_ipv4 = single_list_new();
    single_list_t* cidr_list_ipv6 = single_list_new();

    if(argc < 3)
    {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }
    int queue_num = atoi(argv[1]);
    for(int i = 2; i < argc; i++)
    {
        cidr_t *cidr = safe_malloc(sizeof(*cidr));
        if(!cidr_from_string(cidr, argv[i]))
        {
            fprintf(stderr, "Invalid CIDR argument: %s\n", argv[i]);
            free(cidr);
            free(cidr_list_ipv4);
            free(cidr_list_ipv6);
            return EXIT_FAILURE;
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
    cidrs_ipv4 = single_list_to_array(cidr_list_ipv4);
    cidrs_ipv6 = single_list_to_array(cidr_list_ipv6);
    free(cidr_list_ipv4);
    free(cidr_list_ipv6);

    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);

    nfq_close(h);

    exit(0);
}
