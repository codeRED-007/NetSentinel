#include "PacketParser.h"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sstream>

PacketInfo parsePacket(const u_char* data) {
    PacketInfo info;
    const struct ether_header* eth = (struct ether_header*)data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return info;

    const struct ip* iphdr = (struct ip*)(data + sizeof(struct ether_header));
    info.srcIP = inet_ntoa(iphdr->ip_src);
    info.dstIP = inet_ntoa(iphdr->ip_dst);

    if (iphdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcph = (struct tcphdr*)((u_char*)iphdr + (iphdr->ip_hl << 2));
        info.srcPort = ntohs(tcph->source);
        info.dstPort = ntohs(tcph->dest);
        info.protocol = "TCP";
    } else if (iphdr->ip_p == IPPROTO_UDP) {
        const struct udphdr* udph = (struct udphdr*)((u_char*)iphdr + (iphdr->ip_hl << 2));
        info.srcPort = ntohs(udph->source);
        info.dstPort = ntohs(udph->dest);
        info.protocol = "UDP";
    }
    return info;
}