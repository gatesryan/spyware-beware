#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "netstructs.h"
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helpers.h"

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

int packet_count = 0;
int last_packet = -1;

GtkTextBuffer * textview_buffer;
char * output_str_array[65536];
char * port_info_str = NULL;
int packet_num = -1;

time_t start_time;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void update_text_view();


int monitor(GtkTextBuffer * gui_buffer, int port)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;
    struct bpf_program fp;

    char filter[20];
    sprintf(filter, "port %d", port);
    char * filter_exp = filter;
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

    packet = pcap_next(handle, &header);
    // printf("Packet length: %d\n", header.len);

    output_str_array[65535] = NULL;
    textview_buffer = gui_buffer;

    start_time = time(NULL);
    pcap_loop(handle, -1, packet_handler, packet);
    pcap_close(handle);

    return 0;
}

// int monitor_entire_network()
// {
//     char *dev, errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t * handle;
//     struct bpf_program fp;
//
//     char filter[20];
//     sprintf(filter, "port %d", port);
//     char * filter_exp = filter;
//     bpf_u_int32 mask;
//     bpf_u_int32 net;
//     struct pcap_pkthdr header;
//     const u_char *packet;
//
//
//     dev = pcap_lookupdev(errbuf);
//     if (dev == NULL) {
//         fprintf(stderr, "Couldn't find default device %s\n", errbuf);
//         return 2;
//     }
//
//     if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
//         fprintf(stderr, "Can't get netmask for device %s\n", dev);
//         net = 0;
//         mask = 0;
//     }
//
//     handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//     if (handle == NULL) {
//         fprintf(stderr, "Couldn't open device %s, %s\n", dev, errbuf);
//         return 2;
//     }
//
// }

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    packet_count++;


    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;


    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    u_short port = tcp->th_sport;


    struct in_addr dest_address = ip->ip_dst;

    char buf[INET_ADDRSTRLEN];
    const char * translated_address = inet_ntop(AF_INET, &dest_address, buf, INET_ADDRSTRLEN);


    u_char protocol = ip->ip_p;

    time_t elapsed_time = time(NULL) - start_time;
    long packets_per_second = elapsed_time == 0 ? 0 : packet_count/elapsed_time;
    // char * port_info_str;
    asprintf(&port_info_str, "\nMost Recent Packet number: %d: \nAddress: %s\nAverage number of packets per second:%ld\nProtocol: %u\n", packet_count, translated_address, packets_per_second, protocol);

}

void update_text_view()
{

    if (port_info_str != NULL && packet_num != packet_count){
        packet_num = packet_count;
        // gtk_text_buffer_insert_at_cursor(textview_buffer, port_info_str, -1);
        gtk_text_buffer_set_text(textview_buffer, port_info_str, -1);
    }
}
