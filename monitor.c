#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "netstructs.h"

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

int packet_count = 0;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int monitor()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;
    struct bpf_program fp;
    char * filter_exp = "port 80";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;


    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device %s\n", errbuf);
        return 2;
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s, %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1 ) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    //
    // packet = pcap_next(handle, &header);
    // printf("Packet length: %d\n", header.len);

    pcap_loop(handle, 5, packet_handler, packet);
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct sniff_ip *ip;

    int size_tcp;

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);

    struct in_addr dest_address = ip->ip_dst;

    char buf[INET_ADDRSTRLEN];
    const char * translated_address = inet_ntop(AF_INET, &dest_address, buf, INET_ADDRSTRLEN);

    printf("Packet number %d: \n Address: %s\n\n", packet_count, translated_address);
    packet_count++;

}
