#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <signal.h>
#include <time.h>

#include "buffers.h"
#include "list.h"
#include "cidr.h"

int queue_num;
unsigned char packetbuf[4096];
uint8_t pseudo_hdr[sizeof(packetbuf)];
buffer_t cidrs_ipv4;
buffer_t cidrs_ipv6;
struct nfq_handle *h;
struct nfq_q_handle *qh;
int fd;
int rv;
char buf[4096] __attribute__ ((aligned));
char addr[16];
int rand_port = 0;
uint16_t orig_port;

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
    int indev = nfq_get_indev(tb);

    ph = nfq_get_msg_packet_hdr(tb);
    if(!ph)
    {
        return id;
    }
    id = ntohl(ph->packet_id);
    proto = ntohs(ph->hw_protocol);
    if(proto != 0x86dd && proto != 0x0800)
    {
        return id;
    }
    packet_len = nfq_get_payload(tb, &packet_data);
    if (proto == 0x86dd && packet_len >= 48 && packet_len <= sizeof(packetbuf) && packet_data[6] == 17)
    {
        if(cidrs_ipv6.len <= 0 && !rand_port)
        {
            return id;
        }
        *size = packet_len;
        memcpy(packetbuf, packet_data, packet_len);
        if(cidrs_ipv6.len > 0)
        {
            if(!indev)
            {
                cidr_t *cidr = ((cidr_t**)cidrs_ipv6.data)[rand() % cidrs_ipv6.len];
                uint8_t random[16];
                get_random_bytes(random, sizeof(random));
                bitwise_clear(random, 0, cidr->mask);
                bitwise_xor(packetbuf + 8, random, cidr->prefix, sizeof(random));
            }
            else
            {
                memcpy(packetbuf + 24, addr, sizeof(addr));
            }
        }
        if(rand_port)
        {
            if(!indev)
            {
                uint16_t port = rand() % (0x10000 - 1024) + 1024;
                *((uint16_t*)(packetbuf + 40)) = htons(port);
            }
            else
            {
                uint16_t port = orig_port;
                *((uint16_t*)(packetbuf + 42)) = htons(port);
            }
        }
        packetbuf[46] = 0;
        packetbuf[47] = 0;
        bzero(pseudo_hdr, 40);
        memcpy(pseudo_hdr, packetbuf + 8, 32);
        memcpy(pseudo_hdr + 34, packetbuf + 44, 2);
        pseudo_hdr[39] = 17;
        memcpy(pseudo_hdr + 40, packetbuf + 40, packet_len - 40);
        *((uint16_t*)(packetbuf + 46)) = ip_checksum(pseudo_hdr, packet_len);
    }
    else if(proto == 0x0800 && packet_len >= 28 && packet_len <= sizeof(packetbuf) && packet_data[9] == 17)
    {
        if(!rand_port)
        {
            return id;
        }
        uint8_t ip_hl = (packet_data[0] & 0xF) * 4;
        if(packet_len < ip_hl + 8 || ip_hl < 20)
        {
            return id;
        }
        memcpy(packetbuf, packet_data, packet_len);
        if(cidrs_ipv4.len > 0)
        {
            if(!indev)
            {
                cidr_t *cidr = ((cidr_t**)cidrs_ipv4.data)[rand() % cidrs_ipv4.len];
                uint8_t random[4];
                get_random_bytes(random, sizeof(random));
                bitwise_clear(random, 0, cidr->mask);
                bitwise_xor(packetbuf + 12, random, cidr->prefix, sizeof(random));
            }
            else
            {
                memcpy(packetbuf + 16, addr, 4);
            }
        }
        if(rand_port)
        {
            if(!indev)
            {
                uint16_t port = rand() % (0x10000 - 1024) + 1024;
                *((uint16_t*)(packetbuf + ip_hl)) = htons(port);
            }
            else
            {
                uint16_t port = orig_port;
                *((uint16_t*)(packetbuf + ip_hl + 2)) = htons(port);
            }
        }

        // IP checksum
        packetbuf[10] = 0;
        packetbuf[11] = 0;
        *((uint16_t*)(packetbuf + 10)) = ip_checksum(packetbuf, ip_hl);

        // UDP checksum
        uint16_t udp_len = ntohs(*((uint16_t*)(packetbuf + ip_hl + 4)));
        if(packet_len != ip_hl + udp_len || udp_len < 8)
        {
            return id;
        }
        
        *size = packet_len;
        memcpy(pseudo_hdr, packetbuf + 12, 8);
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = 17;
        pseudo_hdr[10] = packetbuf[ip_hl + 4];
        pseudo_hdr[11] = packetbuf[ip_hl + 5];
        packetbuf[ip_hl + 6] = 0;
        packetbuf[ip_hl + 7] = 0;
        memcpy(pseudo_hdr + 12, packetbuf + ip_hl, udp_len);
        *((uint16_t*)(packetbuf + ip_hl + 6)) = ip_checksum(pseudo_hdr, 12 + udp_len);


    }

    return id;
}
    

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int size = -1;
    u_int32_t id = handle_pkt(nfa, &size);
    return nfq_set_verdict(qh, id, NF_ACCEPT, size, size >= 0 ? packetbuf : NULL);
}

void print_help(char *name)
{
    fprintf(stderr, "Usage: %s <queue-num> [-r <orig_port>] [source rand_cidr0 [ ...rand_cidrN ]]\n", name);
}

int main(int argc, char **argv)
{
    srand(time(NULL));
    single_list_t* cidr_list_ipv4 = single_list_new();
    single_list_t* cidr_list_ipv6 = single_list_new();
    if(argc < 4)
    {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }
    int queue_num = atoi(argv[1]);
    size_t addr_start_arg = 2;
    if(strcmp(argv[2], "-r") == 0)
    {
            rand_port = 1;
            int oport = atoi(argv[3]);
            if(oport <= 0 || oport > 0xFFFF)
            {
                fprintf(stderr, "Invalid original port.\n");
                exit(EXIT_FAILURE);
            }
            orig_port = oport;
            addr_start_arg += 2;
    }
    if(addr_start_arg < argc && inet_pton(AF_INET6, argv[addr_start_arg], addr) != 1 && inet_pton(AF_INET, argv[addr_start_arg], addr) != 1)
    {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }
    for(int i = addr_start_arg + 1; i < argc; i++)
    {
        cidr_t *cidr = safe_malloc(sizeof(*cidr));
        if(!cidr_from_string(cidr, argv[i]))
        {
            fprintf(stderr, "Invalid CIDR argument: %s\n", argv[i]);
            free(cidr);
            free(cidr_list_ipv4);
            free(cidr_list_ipv6);
            exit(EXIT_FAILURE);
        }
        if(cidr->protocol == 4)
        {
            /*fprintf(stderr, "IPv4 address rewriting is not supported.\n");
            free(cidr);
            free(cidr_list_ipv4);
            free(cidr_list_ipv6);
            exit(EXIT_FAILURE);*/
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

    qh = nfq_create_queue(h, queue_num, &cb, NULL);
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
