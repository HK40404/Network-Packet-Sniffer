#include "sniffer.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDebug>
#include <QVector>
#include <QString>
#include <string.h>
#include <cstring>

extern MainWindow * mwindow;
QVector<snfPacket> packets;

Sniffer::Sniffer(QObject * parent) :QObject(parent) {
    shandle = NULL;
    dev = NULL;
}

Sniffer::~Sniffer()
{
    // clean up
    pcap_freecode(&fp);
    if (dev) pcap_freealldevs(dev);
    if (shandle) pcap_close(shandle);
}

void Sniffer::init(int cap_num, bool prom_flag) {
    this->filter_exp = "";
    this->promisc_flag = prom_flag;
    this->capture_num = cap_num;

    qDebug("capture number: %d", this->capture_num);
    if (this->promisc_flag) {
        qDebug("promisc mode: on");
    }
    else {
        qDebug("promisc mode: off");
    }

    pcap_if_t * alldevs = NULL;     /* all devices */
    pcap_findalldevs(&alldevs, errbuf);
    if (alldevs == NULL) {
        qDebug("Couldn't find default device: %s", errbuf);
        return;
    }
    dev = alldevs;  // first device is the one needed
    qDebug("DEVICE: %s", dev->name);

    // get network address & mask of device
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == PCAP_ERROR) {
        qDebug("Couldn't get net & mask of device %s: %s", dev->name, errbuf);
        return;
    }

    QString net_qs;
    QString mask_qs;
    struct in_addr addr;

    // transform net&mask into human readable form
    addr.s_addr = net;
    net_qs = inet_ntoa(addr);
    addr.s_addr = mask;
    mask_qs = inet_ntoa(addr);
    qDebug("net: %s\tmask: %s", net_qs.toStdString().c_str(), mask_qs.toStdString().c_str());
}

int Sniffer::activate() {
    shandle = pcap_open_live(dev->name, BUFSIZ, promisc_flag, 1000, errbuf);
    if (shandle == NULL) {
        qDebug("Couldn't open device %s: %s", dev->name, errbuf);
        return -1;
    }
    return 0;
}

void Sniffer::set_filter(QString filter_str) {
    this->filter_exp = filter_str;
}

/*
 *  compile and apply filter to seesion
 */
int Sniffer::apply_filter() {
    if (pcap_compile(shandle, &fp, filter_exp.toStdString().c_str(), 1, mask) == PCAP_ERROR) {
        qDebug("Couldn't parse filter '%s': %s", filter_exp.toStdString().c_str(), pcap_geterr(shandle));
        return -1;
    }
    if (pcap_setfilter(shandle, &fp) == PCAP_ERROR) {
        qDebug("Couldn't install filter '%s': %s", filter_exp.toStdString().c_str(), pcap_geterr(shandle));
        return -1;
    }
    return 0;
}

/*
 * capture and process packet
*/
void Sniffer::capture(int cap_num, bool prom_flag, QString filter_exp) {
//    qDebug()<<"当前线程ID:"<<QThread::currentThreadId();
    init(cap_num, prom_flag);
    activate();
    set_filter(filter_exp);
    apply_filter();
    pcap_loop(shandle, capture_num, process_packet, NULL);
    emit finish_capture();
}

void Sniffer::process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
    const struct iphdr * ip_packet;
    uint8_t protocol;
    const u_char * payload;

    int ip_header_len;
    int ip_len;
    int tcp_header_len;
    int payload_len;

    QString ether_saddr = "-";
    QString ether_daddr = "-";
    QString ip_saddr = "-";
    QString ip_daddr = "-";
    int sport = 0;
    int dport = 0;

    // store packet information
    struct snfPacket current_packet{"", ""};
    packets.push_back(current_packet);

    // handle ethernet packet
    qDebug("Packet number: %d", packets.size());
    u_int16_t ether_type = handle_ethernet(packet, &ether_saddr, &ether_daddr);

    // handle arp packet
    if (ether_type == ETHERTYPE_ARP) {
        const struct snf_arphdr * arp_packet = (struct snf_arphdr *)(packet + ETHERNET_HEADER_LEN);
        handle_arp(arp_packet);
        mwindow->add_packet_row(ether_saddr, ether_daddr, ip_saddr, ip_daddr, sport, dport);
        return;
    }
    // handle ip packet
    else if (ether_type == ETHERTYPE_IP) {
        ip_packet = (struct iphdr *)(packet + ETHERNET_HEADER_LEN);
        ip_header_len = handle_ip(ip_packet, &protocol, &ip_len, &ip_saddr, &ip_daddr);
        if (ip_header_len == -1) {
            return;
        }
    }

    // handle TCP packet
    if(protocol == IPPROTO_TCP) {
        const struct tcphdr * tcp_packet;
        tcp_packet = (struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
        tcp_header_len = handle_tcp(tcp_packet, &sport, &dport);
        if (tcp_header_len == -1) {
            return;
        }
        payload = (u_char *)(packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len);
        payload_len = ip_len - ip_header_len - tcp_header_len;
        handle_payload(payload, payload_len);
    }
    else if (protocol == IPPROTO_UDP) {
        const struct udphdr * udp_packet;
        udp_packet = (struct udphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
        if (handle_udp(udp_packet, &sport, &dport) == -1) {
            return;
        }
        payload = (u_char *)(packet + ETHERNET_HEADER_LEN + ip_header_len + UDP_HEADER_LEN);
        payload_len = ip_len - ip_header_len - UDP_HEADER_LEN;
        handle_payload(payload, payload_len);
    }
    else if (protocol == IPPROTO_ICMP) {
        const struct icmphdr * icmp_packet;
        icmp_packet = (struct icmphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
        handle_icmp(icmp_packet);
    }

    mwindow->add_packet_row(ether_saddr, ether_daddr, ip_saddr, ip_daddr, sport, dport);
}

u_int16_t Sniffer::handle_ethernet(const u_char * packet, QString * ether_saddr, QString * ether_daddr) {
    struct ether_header *eptr;

    // analyze header information: src addr & dst addr
    eptr = (struct ether_header *) packet;
    *ether_saddr = ether_ntoa((const struct ether_addr *)&eptr->ether_shost);
    *ether_daddr = ether_ntoa((const struct ether_addr *)&eptr->ether_dhost);
    QString ether_info = "";
    ether_info += "Data Link Layer: Ethernet\n";
    ether_info += QString("Ethernet header source address: %1\n").arg(*ether_saddr);
    ether_info += QString("Ethernet header destination address: %1\n").arg(*ether_daddr);
    packets[packets.size()-1].info += ether_info;

    // analyze packet type
    u_int16_t ether_type = ntohs(eptr->ether_type);  // converts the unsigned short integer netshort from network byte order to host byte order
    return ether_type;
}

int Sniffer::handle_ip(const struct iphdr * ip_packet, uint8_t * protocol, int * ip_len, QString * ip_saddr, QString * ip_daddr) {
    struct in_addr addr;
    int ip_header_len = ip_packet->ihl * 4; // packet header length
    if (ip_header_len < 20) {
        qDebug("\tInvalid IP header length: %u bytes", ip_header_len);
        return -1;
    }

    // get protocol and ip packet length
    *protocol = ip_packet->protocol;
    *ip_len = ntohs(ip_packet->tot_len);    // converts the unsigned short integer netshort from network byte order to host byte order

    // print source and destination IP addresses
    addr.s_addr = ip_packet->saddr;
    *ip_saddr = inet_ntoa(addr);
    addr.s_addr = ip_packet->daddr;
    *ip_daddr = inet_ntoa(addr);

    QString ip_info = "";
    ip_info += "\tNetwork Layer: Internet Protocol Version 4(IPv4)\n";
    ip_info += QString("\tFrom: %1\n").arg(*ip_saddr);
    ip_info += QString("\tTo: %1\n").arg(*ip_daddr);
    packets[packets.size()-1].info += ip_info;
    return ip_header_len;
}

void Sniffer::handle_arp(const struct snf_arphdr * arp_packet) {
    struct in_addr addr;

    uint hardware_type = ntohs(arp_packet->ar_hrd);
    uint proto_type = ntohs(arp_packet->ar_pro);
    uint hdaddr_len = arp_packet->ar_hln;
    uint proto_len = arp_packet->ar_pln;
    uint opcode = ntohs(arp_packet->ar_op);
    QString eth_saddr = ether_ntoa((const struct ether_addr *)&arp_packet->ar_sha);
    QString eth_daddr = ether_ntoa((const struct ether_addr *)&arp_packet->ar_tha);
    addr.s_addr = ntohl(arp_packet->ar_sip);
    QString ip_saddr = inet_ntoa(addr);
    addr.s_addr = ntohl(arp_packet->ar_tip);
    QString ip_daddr = inet_ntoa(addr);

    QString arp_info = "";
    arp_info += "\tNetwork Layer: Address Resolution Protocol(ARP) packet\n";
    QString hd_type = "";
    if (hardware_type == 1) hd_type = "(ethernet)";
    arp_info += QString("\tHardware type: %1%2\n").arg(hardware_type).arg(hd_type);
    QString proto = "";
    if (proto_type == 0x800) proto = "(IPV4)";
    arp_info += QString("\tProtocol type: %1%2\n").arg(proto_type).arg(proto);
    arp_info += QString("\tHardware address Length: %1\n").arg(hdaddr_len);
    arp_info += QString("\tProtocol address Length: %1\n").arg(proto_len);
    QString op = "";
    if (opcode == 1) {
        op = "(ARP Request)";
    }
    else if (opcode == 2) {
        op = "(ARP Response)";
    }
    arp_info += QString("\tOpcode: %1%2\n").arg(opcode).arg(op);
    arp_info += QString("\tSender MAC Address: %1\n").arg(eth_saddr);
    arp_info += QString("\tSender IP Address: %1\n").arg(ip_saddr);
    arp_info += QString("\tTarget MAC Address: %1\n").arg(eth_daddr);
    arp_info += QString("\tTarget IP Address: %1\n").arg(ip_daddr);
    packets[packets.size()-1].info += arp_info;
}

void Sniffer::handle_icmp(const struct icmphdr * icmp_packet) {
    uint type = icmp_packet->type;
    uint code = icmp_packet->code;
    uint id = ntohs(icmp_packet->un.echo.id);
    uint sequence = ntohs(icmp_packet->un.echo.sequence);

    QString icmp_info = "";
    icmp_info += "\tInternet Control Message Protocol(ICMP)\n";
    QString icmp_op = "";
    if (type == ICMP_ECHO) {
        icmp_op = "[ICMP ECHO(ping) REQUEST]";
    }
    else if (type == ICMP_ECHOREPLY) {
        icmp_op = "[ICMP ECHO(ping) REPLY]";
    }
    icmp_info += QString("\tICMP type: %1%2\n").arg(type).arg(icmp_op);
    icmp_info += QString("\tICMP Code: %1\n").arg(code);
    icmp_info += QString("\tICMP Identifier: %1\n").arg(id);
    icmp_info += QString("\tICMP Sequence number: %1\n").arg(sequence);
    packets[packets.size()-1].info += icmp_info;
}

int Sniffer::handle_tcp(const struct tcphdr * tcp_packet, int * sport, int * dport) {
    int tcp_header_len = tcp_packet->doff * 4;
    if (tcp_header_len < 20) {
        qDebug("\t\tInvalid TCP header length: %u bytes", tcp_header_len);
        return -1;
    }
    *sport = ntohs(tcp_packet->source);
    *dport = ntohs(tcp_packet->dest);
    QString tcp_info = "";
    tcp_info += "\t\tTransport Layer: Transmission Control Protocol(TCP)\n";
    tcp_info += QString("\t\tSource port: %1\n").arg(*sport);
    tcp_info += QString("\t\tDestination port: %1\n").arg(*dport);

    packets[packets.size()-1].info += tcp_info;
    return tcp_header_len;
}

int Sniffer::handle_udp(const struct udphdr * udp_packet, int * sport, int * dport) {
    *sport = ntohs(udp_packet->source);
    *dport = ntohs(udp_packet->dest);

    int udp_packet_len = udp_packet->len;
    if (udp_packet_len < 8) {
//        printf("\t\tInvalid UDP packet length: %u bytes\n", udp_packet_len);
        return -1;
    }

    QString udp_info = "";
    udp_info += "\t\tTransport Layer: User datagram protocol(UDP)\n";
    udp_info += QString("\t\tSource port: %1\n").arg(*sport);
    udp_info += QString("\t\tDestination port: %1\n").arg(*dport);
    packets[packets.size()-1].info += udp_info;
    return udp_packet_len;
}

void Sniffer::handle_payload(const u_char *payload, int len) {
    string payload_s(payload, payload+len);
    QString payload_qs = QString::fromStdString(payload_s);
    packets[packets.size()-1].packet = payload_qs;
}

QString Sniffer::get_readable_payload(const QString * payload) {
    QString res = "";
    char buf[100];
    sprintf(buf, "Payload length: %d bytes\n", payload->size());
    string buf_s = string(buf, buf+strlen(buf));
    res.append(QString::fromStdString(buf_s));
    if (payload->size() == 0)
        return res;

    int offset = 0;
    int line_width = 16;
    int len_rem = payload->size();

    // payload length < 16
    if (len_rem < line_width) {
        get_hex_ascii_line(payload, offset, len_rem, buf);
        buf_s = string(buf, buf+strlen(buf));
        res.append(QString::fromStdString(buf_s));
    }

    while (true) {
        get_hex_ascii_line(payload, offset, line_width, buf);
        buf_s = string(buf, buf+strlen(buf));
        res.append(QString::fromStdString(buf_s));

        offset += line_width;
        len_rem -= line_width;
        if (len_rem <= line_width) {
            get_hex_ascii_line(payload, offset, len_rem, buf);
            buf_s = string(buf, buf+strlen(buf));
            res.append(QString::fromStdString(buf_s));
            break;
        }
    }
    return res;
}

/*
 * get data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void Sniffer::get_hex_ascii_line(const QString * payload, int offset, int len, char * buf) {
    u_char ch;
    int buf_len = 0;

    sprintf(buf, "%05d\t", offset);
    buf_len += 6;

    // data in hex
    for (int i = 0; i < len; i++) {
        ch = (*payload)[offset+i].unicode();
        sprintf(buf+buf_len, "%02x ", ch);
        buf_len += 3;
        if (i == 7) {
            sprintf(buf+buf_len, " ");
            buf_len += 1;
        }
    }

    if (len < 8) {
        sprintf(buf+buf_len, " ");
        buf_len += 1;
    }
    if (len < 16) {
        int gap = 16 - len;
        for (int i = 0; i < gap; i++) {
            sprintf(buf+buf_len, "   ");
            buf_len += 3;
        }
    }
    sprintf(buf+buf_len, "\t");
    buf_len += 1;

    // data in ascii
    for (int i = 0; i < len; i++) {
        ch = (*payload)[offset+i].unicode();
        if (isprint(ch)) {
            sprintf(buf+buf_len, "%c", ch);
            buf_len += 1;
        }
        else {
            sprintf(buf+buf_len, ".");
            buf_len += 1;
        }
    }
    sprintf(buf+buf_len, "\n");
}


Filter::Filter(){
   sip = "";
   dip = "";
   sport = "";
   dport = "";
   protocol = "";
}

bool Filter::check()  {
    bool succeed;
    int port;
    in_addr_t addr;

    if (sport != "") {
        port = sport.toInt(&succeed);
        if (!succeed) return false;
        if (port > 65535 or port < 0)
            return false;
    }
    if (dport != "") {
        port = dport.toInt(&succeed);
        if (!succeed) return false;
        if (port > 65535 or port < 0)
            return false;
    }
    if (sip != "") {
        int dot_num = 0;
        for (int i = 0; i < sip.size(); ++i) {
            if (sip[i] == '.') dot_num++;
        }
        if (dot_num != 3) return false;
        addr = inet_addr(sip.toStdString().c_str());
        if (addr == INADDR_NONE) {
            return false;
        }
    }
    if (dip != "") {
        int dot_num = 0;
        for (int i = 0; i < dip.size(); ++i) {
            if (dip[i] == '.') dot_num++;
        }
        if (dot_num != 3) return false;
        addr = inet_addr(dip.toStdString().c_str());
        if (addr == INADDR_NONE) {
            return false;
        }
    }

    return true;
}

/*
 * transform filter to filter expression
 * assume the filter is legal
*/
QString Filter::get_filter_exp() {
    QString exp = "";
    if (sip != "") {
        exp += "src host " + sip;
    }
    if (dip != "") {
        if (exp != "")
            exp += " and ";
        exp += "dst host " + dip;
    }
    if (sport != "") {
        if (exp != "")
            exp += " and ";
        exp += "src port " + sport;
    }
    if (dport != "") {
        if (exp != "")
            exp += " and ";
        exp += "dst port " + dport;
    }
    if (protocol != "") {
        if (exp != "")
            exp += " and ";
        if (protocol == "IP") {
            exp += "ip";
        }
        else if (protocol == "ARP") {
            exp += "arp";
        }
        else if (protocol == "ICMP") {
            exp += "icmp";
        }
        else if (protocol == "TCP") {
            exp += "tcp";
        }
        else if (protocol == "UDP") {
            exp += "udp";
        }
        else if (protocol == "HTTP") {
            exp += "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
        }
    }
    return exp;
}
