#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>

struct PacketInfo {
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string protocol;
};

PacketInfo parsePacket(const u_char* data);

#endif