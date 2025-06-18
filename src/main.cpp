#include "PacketSniffer.h"
#include "PacketParser.h"
#include "IDS.h"
#include <iostream>

int main() {
    IDS ids;
    PacketSniffer sniffer("wlo1", [&](const struct pcap_pkthdr* header, const u_char* data) {
        PacketInfo info = parsePacket(data);
        if (!info.srcIP.empty()) {
            ids.analyzePacket(info);
            std::cout << "[INFO] " << info.protocol << " | Src: " << info.srcIP
                      << " | Dst: " << info.dstIP << " | SrcPort: " << info.srcPort
                      << " | DstPort: " << info.dstPort << std::endl;
        }
    });
    sniffer.start();
    std::cin.get();
    sniffer.stop();
    return 0;
}