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
#include <unistd.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define NUM_OF_PORTS 65535

int packet_count = 0;
int packet_num = -1;

struct port_info* baseline_array[NUM_OF_PORTS];
struct port_info* current_usage_array[NUM_OF_PORTS];

int packet_counts[NUM_OF_PORTS];

GtkTextBuffer * textview_buffer;
GtkLabel * label;

pcap_t * handle;


gchar * output_str;
gchar * label_str;

time_t start_time;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void update_text_view();
int* get_most_used_port_nums();
void entire_network_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int port_is_common(int port_number);
int determine_status_of_network();


int monitor(GtkTextBuffer * gui_buffer, int port)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char filter[20];
    sprintf(filter, "port %d", port);
    char * filter_exp = filter;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    packet_count = 0;
    packet_num = -1;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device %s\n", errbuf);
        return 2;
    }

    // find first non loopback network interface
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    // open network interface for sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s, %s\n", dev, errbuf);
        return 2;
    }

    // compile filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // set filter so that only traffic on selected port is shown
    if (pcap_setfilter(handle, &fp) == -1 ) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }



    textview_buffer = gui_buffer;

    start_time = time(NULL);
    pcap_loop(handle, -1, packet_handler, packet);
    pcap_close(handle);

    return 0;
}

int monitor_entire_network(GtkTextBuffer * gui_buffer, GtkLabel * lab)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    label = lab;

    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    textview_buffer = gui_buffer;


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

    for (int i = 0; i < 65535; i++) {
        baseline_array[i] = malloc(sizeof(struct port_info));
        current_usage_array[i] = malloc(sizeof(struct port_info));

        baseline_array[i]->src_address = NULL;
        baseline_array[i]->dest_address = NULL;
        baseline_array[i]->packets_per_second = -1;

        current_usage_array[i]->src_address = NULL;
        current_usage_array[i]->dest_address = NULL;
        current_usage_array[i]->packets_per_second = -1;

        packet_counts[i] = 0;

    }

    start_time = time(NULL);

    pcap_loop(handle, -1, entire_network_packet_handler, packet);

}

/*
* Handles packets on selected port and constructs string to display to user of port info
*/
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
    struct in_addr src_address = ip->ip_src;

    char buf[INET_ADDRSTRLEN];
    const char * translated_address_out = inet_ntop(AF_INET, &dest_address, buf, INET_ADDRSTRLEN);
    const char * translated_address_in = inet_ntop(AF_INET, &src_address, buf, INET_ADDRSTRLEN);


    char * port_info_str_out = NULL;
    char * port_info_str_in = NULL;

    u_char protocol = ip->ip_p;

    time_t elapsed_time = time(NULL) - start_time;
    float packets_per_second = elapsed_time == 0 ? 0 : packet_counts[port]/elapsed_time;
    // char * port_info_str;
    asprintf(&port_info_str_out, "\nMost Recent Outgoing Packet number: %d: \nAddress: %s\nAverage number of outgoing packets per second:%.2f\nProtocol: %u\n", packet_count, translated_address_out, packets_per_second, protocol);
    asprintf(&port_info_str_in, "\nMost Recent Incoming Packet number: %d: \nAddress: %s\nAverage number of incoming packets per second:%.2f\nProtocol: %u\n\n--------------------------\n", packet_count, translated_address_in, packets_per_second, protocol);


    if (port_info_str_out != NULL && port_info_str_in != NULL){
        size_t total_string_size = strlen(port_info_str_out) + strlen(port_info_str_in);
        output_str = malloc(total_string_size+1);
        strcpy(output_str, port_info_str_out);

        strcat(output_str, port_info_str_in);
        // fprintf(stderr, "%s", output_str[total_string_size]);

    }

}

void entire_network_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    u_short port = tcp->th_sport;


    packet_counts[port]++;

    struct in_addr dest_address = ip->ip_dst;
    struct in_addr src_address = ip->ip_src;

    char buf[INET_ADDRSTRLEN];
    const char * translated_address_out = inet_ntop(AF_INET, &dest_address, buf, INET_ADDRSTRLEN);
    const char * translated_address_in = inet_ntop(AF_INET, &src_address, buf, INET_ADDRSTRLEN);

    time_t elapsed_time = time(NULL) - start_time;

    u_char protocol = ip->ip_p;

    // build a baseline picture of network traffic for 30 seconds
    if (elapsed_time < 30){
        baseline_array[port]->src_address = translated_address_in;
        baseline_array[port]->dest_address = translated_address_out;
        baseline_array[port]->protocol = protocol;

        float packets_per_second = elapsed_time == 0 ? 0 : packet_count/elapsed_time;

        baseline_array[port]->packets_per_second = packets_per_second;

        asprintf(&label_str, "Building baseline image of network.");
    }

    else if (elapsed_time < 60){
        current_usage_array[port]->src_address = translated_address_in;
        current_usage_array[port]->dest_address = translated_address_out;
        current_usage_array[port]->protocol = protocol;

        float packets_per_second = elapsed_time == 0 ? 0 : packet_counts[port]/elapsed_time;
        current_usage_array[port]->packets_per_second = packets_per_second;


        int * frequently_used_ports = get_most_used_port_nums();
        char * frequently_used_ports_str;



        asprintf(&frequently_used_ports_str, "Most used ports are: %d, %d, %d, %d, %d\n\n",
                              frequently_used_ports[0],
                              frequently_used_ports[1],
                              frequently_used_ports[2],
                              frequently_used_ports[3],
                              frequently_used_ports[4]);




        char * port_info_str_out[5];
        size_t total_str_length = 0;
        for (int i = 0; i < 5; i++){
            int port_num = frequently_used_ports[i];
            asprintf(&port_info_str_out[i],  "Port: %d\n Most recent outgoing packet address: %s\nMost recent incoming packet address:%s\nAverage number of outgoing packets per second:%.2f\nProtocol: %u\n-------------------------------------------------------------------------\n\n",
                                                                        port_num,
                                                                        current_usage_array[port_num]->dest_address,
                                                                        current_usage_array[port_num]->src_address,
                                                                        current_usage_array[port_num]->packets_per_second,
                                                                        current_usage_array[port_num]->protocol);
            total_str_length += strlen(port_info_str_out[i]);


        }


        output_str = malloc(total_str_length+strlen(frequently_used_ports_str)+1);
        strcpy(output_str, frequently_used_ports_str);
        // strcat(output_str, port_info_str_out[0]);
        for (int i = 0; i < 5; i++){
            strcat(output_str, port_info_str_out[i]);
        }

    }
    else{
        if (determine_status_of_network()){
            asprintf(&label_str, "You may have spyware");
        }
        else{
            asprintf(&label_str, "No Spyware detected");
        }
        pcap_breakloop(handle);
    }





}

void update_text_view()
{

    if (output_str != NULL && packet_num != packet_count){
        packet_num = packet_count;
        // gtk_text_buffer_insert_at_cursor(textview_buffer, port_info_str, -1);
        //
        gtk_text_buffer_set_text(textview_buffer, output_str, -1);
    }

    if (label_str != NULL){
        gtk_label_set_text(GTK_LABEL(label), label_str);
    }
}

void update_text_view_full()
{
    if (output_str != NULL){
        packet_num = packet_count;
        // gtk_text_buffer_insert_at_cursor(textview_buffer, port_info_str, -1);
        //
        gtk_text_buffer_set_text(textview_buffer, output_str, -1);
    }
}

int* get_most_used_port_nums()
{
    int max1, max2, max3, max4, max5 = 0;
    for (int i = 0; i < 65535; i++){
        struct port_info * current_port = current_usage_array[i];

        struct port_info * max1_port = current_usage_array[max1];
        struct port_info * max2_port = current_usage_array[max2];
        struct port_info * max3_port = current_usage_array[max3];
        struct port_info * max4_port = current_usage_array[max4];
        struct port_info * max5_port = current_usage_array[max5];


        if (current_usage_array[i]->packets_per_second > current_usage_array[max5]->packets_per_second) {
            max5 = i;
        }
        else if (current_usage_array[i]->packets_per_second > current_usage_array[max4]->packets_per_second){
            max4 = i;
        }
        else if (current_usage_array[i]->packets_per_second > current_usage_array[max3]->packets_per_second){
            max3 = i;
        }
        else if (current_usage_array[i]->packets_per_second > current_usage_array[max2]->packets_per_second){
            max2 = i;
        }
        else if (current_usage_array[i]->packets_per_second > current_usage_array[max1]->packets_per_second){
            max1 = i;
        }
    }

    int * ret = malloc(5*sizeof(int));
    ret[0] = max1;
    ret[1] = max2;
    ret[2] = max3;
    ret[3] = max4;
    ret[4] = max5;

    return ret;

}

/*
* Returns 1 for possible spyware
* 0 if it determines no spyware
*/
int determine_status_of_network()
{
    for (int i = 0; i < NUM_OF_PORTS; i++){
        if (current_usage_array[i]->packets_per_second > 3*baseline_array[i]->packets_per_second && !port_is_common(i)){
            return 1;
        }
    }
    return 0;
}

int port_is_common(int port_number){
    switch(port_number){
        case 20/20:
        case 22:
        case 23:
        case 25:
        case 53:
        case 67:
        case 68:
        case 69:
        case 80:
        case 110:
        case 123:
        case 137:
        case 138:
        case 139:
        case 143:
        case 161:
        case 162:
        case 179:
        case 389:
        case 443:
        case 636:
        case 989:
        case 990:
            return 1;
        default:
            return 0;
    }
}
