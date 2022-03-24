#include <iostream>
#include <cstring>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
using namespace std;

#define ETHERNET_HEADER_LEN 14

u_int16_t handle_ethernet(const u_char * packet) {
    struct ether_header *eptr;
    string ether_saddr;
    string ether_daddr;

    // analyze header information: src addr & dst addr
    eptr = (struct ether_header *) packet;
    ether_saddr = ether_ntoa((const struct ether_addr *)&eptr->ether_shost);
    ether_daddr = ether_ntoa((const struct ether_addr *)&eptr->ether_dhost);
    printf("ethernet header source address: %s\n", ether_saddr.c_str());
    printf("ethernet header destination address: %s\n", ether_daddr.c_str());

    // analyze packet type
    u_int16_t ether_type = ntohs(eptr->ether_type);  // converts the unsigned short integer netshort from network byte order to host byte order
    if (ether_type == ETHERTYPE_IP) {
        printf("packet type: IP\n");
    }
    else if (ether_type == ETHERTYPE_ARP) {
        printf("packet type: ARP\n");
    }
    else if (ether_type == ETHERTYPE_REVARP) {
        printf("packet type: REVARP\n");
    }
    else {
        printf("packet type: other\n");
    }

    return ether_type;
}

int handle_ip(const struct iphdr * ip_packet, uint8_t * protocol, int * ip_len) {
    struct in_addr addr;

    int ip_header_len = ip_packet->ihl * 4; // packet header length
    if (ip_header_len < 20) {
        printf("\tInvalid IP header length: %u bytes\n", ip_header_len);
        return -1;
    }

    // get protocol and ip packet length
    *protocol = ip_packet->protocol;
    *ip_len = ntohs(ip_packet->tot_len);    // converts the unsigned short integer netshort from network byte order to host byte order

    // print source and destination IP addresses
    addr.s_addr = ip_packet->saddr;
    printf("\tFrom: %s\n", inet_ntoa(addr));
    addr.s_addr = ip_packet->daddr;
	printf("\tTo: %s\n", inet_ntoa(addr));

    // print protocol
    switch(*protocol) {
		case IPPROTO_TCP:
			printf("\tProtocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("\tProtocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("\tProtocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("\tProtocol: IP\n");
			break;
		default:
			printf("\tProtocol: unknown\n");
			break;
	}
    return ip_header_len;
}

int handle_tcp(const struct tcphdr * tcp_packet) {
    int tcp_header_len = tcp_packet->doff * 4;
    if (tcp_header_len < 20) {
        printf("\t\tInvalid TCP header length: %u bytes\n", tcp_header_len);
        return -1;
    }
    uint16_t sport = ntohs(tcp_packet->source);
    uint16_t dport = ntohs(tcp_packet->dest);
    printf("\t\tSrc port: %d\n", sport);
	printf("\t\tDst port: %d\n", dport);
    return tcp_header_len;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char * payload, int len, int offset) {
    const u_char * ch;

    printf("\t\t\t%05d\t", offset);

    // print data in hex
    ch = payload;
    for (int i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        if (i == 7)
            printf(" ");
    }

    // for alignment
    if (len < 8)
        printf(" ");
    if (len < 16) {
        int gap = 16 - len;
        for (int i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("\t");

    // print data in ascii
    ch = payload;
    for (int i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
}

void print_payload(const u_char * payload, int len) {
    printf("\t\t\tPayload length: %d bytes\n", len);
    if (len == 0)
        return;
    
    int len_rem = len;
    int offset = 0;
    int line_width = 16;
    const u_char *p = payload;

    // payload length < 16
    if (len_rem < line_width) {
        print_hex_ascii_line(p, len_rem, offset);
    }

    while (true) {
        print_hex_ascii_line(p, line_width, offset);
        p += line_width;
        offset += line_width;
        len_rem -= line_width;
        if (len_rem <= line_width) {
            print_hex_ascii_line(p, len_rem, offset);
            break;
        }
    }
}

void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
    static int packet_num = 0;
    const struct iphdr * ip_packet;
    uint8_t protocol; 
    const u_char * payload;

    int ip_header_len;
    int ip_len;
    int tcp_header_len;
    int payload_len;

    // handle ethernet packet
    printf("Packet number: %d\n", ++packet_num);
    u_int16_t ether_type = handle_ethernet(packet);

    // handle ip packet
    ip_packet = (struct iphdr *)(packet + ETHERNET_HEADER_LEN);
    ip_header_len = handle_ip(ip_packet, &protocol, &ip_len);
    if (ip_header_len == -1) {
        return;
    }

    // handle TCP packet
    if(protocol == IPPROTO_TCP) {
        const struct tcphdr * tcp_packet;
        tcp_packet = (struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
        tcp_header_len = handle_tcp(tcp_packet);
        if (tcp_header_len == -1) {
            return;
        }
    }

    // handle payload
    payload = (u_char *)(packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len);
    payload_len = ip_len - ip_header_len - tcp_header_len;
    print_payload(payload, payload_len);
}

int main(int argc, char *argv[]) {

    pcap_t * handle;                // session handle
    pcap_if_t * alldevs = NULL;     // all devices
    pcap_if_t * dev;                // device used
    char errbuf[PCAP_ERRBUF_SIZE];  // store error message
    bpf_u_int32 net;                // ip
    bpf_u_int32 mask;               // netmask
    string net_s;
    string mask_s;
    struct in_addr addr;
    int promisc_flag = 0;           // notzero: promiscuous mode
    char filter_exp[100] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";      // filter expression
    struct bpf_program fp;          // compiled filter
    struct pcap_pkthdr header;      // packet header
    const u_char * packet;          // the actual packet
    int NUM_PACKETS = 5;             // number of packet want to capture
    
    // get dev info
    pcap_findalldevs(&alldevs, errbuf);
    if (alldevs == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return -1;
    }
    dev = alldevs;  // first device is the one needed
    printf("DEVICE: %s\n", dev->name);

    // get network address & mask of device
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't get net & mask of device %s: %s\n", dev->name, errbuf);
        return -1;
    }

    // transform net&mask into human readable form
    addr.s_addr = net;
    net_s = inet_ntoa(addr);
    addr.s_addr = mask;
    mask_s = inet_ntoa(addr);
    printf("net: %s\tmask:%s\n", net_s.c_str(), mask_s.c_str());

    // open session
    handle = pcap_open_live(dev->name, BUFSIZ, promisc_flag, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
	    return -1;
    }

    // compile and apply filter to seesion
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't install filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    // capture packets
    pcap_loop(handle, NUM_PACKETS, process_packet, NULL);

    // clean up
    pcap_freealldevs(alldevs);
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}