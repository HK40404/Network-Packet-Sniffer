#ifndef SNIFFER_H
#define SNIFFER_H

#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <QString>
#include <QObject>
#include <QVector>
using namespace std;

#define ETHERNET_HEADER_LEN 14
#define UDP_HEADER_LEN 8

struct snf_arphdr
{
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
    unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    uint32_t ar_sip;		/* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
    uint32_t ar_tip;		/* Target IP address.  */
};

class Filter{
public:
    QString sip;
    QString dip;
    QString sport;
    QString dport;
    QString protocol;

    Filter();
    bool check();
    QString get_filter_exp();
};

struct snfPacket {
    QString info;
    QString packet;
};

class Sniffer: public QObject{

    Q_OBJECT
private:
    pcap_t * shandle;               /* session handle */
    pcap_if_t * dev;                /* device used */
    char errbuf[PCAP_ERRBUF_SIZE];  /* store error message */
    bpf_u_int32 net;                /* ip */
    bpf_u_int32 mask;               /* netmask */
    int promisc_flag;               /* 0: not use promisc mode */
    int capture_num;
    QString filter_exp;           /* filter expression */
    struct bpf_program fp;          /* compiled filter program */

public:
    Sniffer(QObject * parent = nullptr);
    void init(int cap_num, bool prom_flag);
    int activate();
    void set_filter(QString filter_str);
    int apply_filter();
    static void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
    static u_int16_t handle_ethernet(const u_char * packet, QString * ether_saddr, QString * ether_daddr);
    static int handle_ip(const struct iphdr * ip_packet, uint8_t * protocol, int * ip_len, QString * ip_saddr, QString * ip_daddr);
    static int handle_tcp(const struct tcphdr * tcp_packet, int * sport, int * dport);
    static int handle_udp(const struct udphdr * udp_packet, int * sport, int * dport);
    static void handle_arp(const struct snf_arphdr * arp_packet);
    static void handle_icmp(const struct icmphdr * icmp_packet);
    static void handle_payload(const u_char * payload, int len);
    static QString get_readable_payload(const QString * payload);
    static void get_hex_ascii_line(const QString * payload, int offset, int len, char * buf);
    ~Sniffer();

public slots:
    void capture(int cap_num, bool prom_flag, QString filter_exp);

signals:
    void finish_capture();
};

#endif // SNIFFER_H
