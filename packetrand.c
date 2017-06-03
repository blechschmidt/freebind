#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <signal.h>

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


// Source: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
uint16_t ip_checksum(void* vdata,size_t length)
{
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset)
	{
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end)
    {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length)
    {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16)
    {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1)
    {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

void handle_sigint(int signal)
{
    exit(EXIT_FAILURE);
}

static uint32_t handle_pkt (struct nfq_data *tb, int *size)
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
        if(proto == 0x800 && packet_len >= 20 && cidrs_ipv4.len > 0)
        {
            cidr_t *cidr = ((cidr_t**)cidrs_ipv4.data)[rand() % cidrs_ipv4.len];
            char random[4];
            get_random_bytes(random, sizeof(random));
            bitwise_clear(random, 0, cidr->mask);
            bitwise_xor(packetbuf + 12, random, cidr->prefix, sizeof(random));
        }
        else if(proto == 0x86dd && packet_len >= 40 && cidrs_ipv6.len > 0)
        {
            cidr_t *cidr = ((cidr_t**)cidrs_ipv6.data)[rand() % cidrs_ipv6.len];
            char random[16];
            get_random_bytes(random, sizeof(random));
            bitwise_clear(random, 0, cidr->mask);
            bitwise_xor(packetbuf + 8, random, cidr->prefix, sizeof(random));
            if(packetbuf[6] == 17 && packet_len >= 48) // clear udp checksum
            {
                char pseudo_hdr[sizeof(packetbuf)];
                packetbuf[46] = 0;
                packetbuf[47] = 0;
                bzero(pseudo_hdr, sizeof(pseudo_hdr));
                memcpy(pseudo_hdr, packetbuf + 8, 32);
                memcpy(pseudo_hdr + 34, packetbuf + 44, 2);
                pseudo_hdr[39] = 17;
                memcpy(pseudo_hdr + 40, packetbuf + 40, packet_len - 40);
                *((uint16_t*)(packetbuf + 46)) = ip_checksum(pseudo_hdr, packet_len);
            }
        }
    }

    return id;
}
    

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int size = 0;
    u_int32_t id = handle_pkt(nfa, &size);
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
    
    fprintf(stderr, "Detach from terminal. Will keep running in the background.\n");
    signal(SIGINT, handle_sigint);
    daemon(1, 0);

    while (1)
    {
        rv = recv(fd, buf, sizeof(buf), 0);
        if(rv >= 0)
        {
            nfq_handle_packet(h, buf, rv);
        }
    }

    nfq_destroy_queue(qh);

    nfq_close(h);

    exit(0);
}
