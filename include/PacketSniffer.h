#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <thread>
#include <functional>
#include <string>

class PacketSniffer {
public:
    using PacketCallback = std::function<void(const struct pcap_pkthdr*, const u_char*)>;

    PacketSniffer(const std::string& device, PacketCallback callback);
    void start();
    void stop();

private:
    std::string device_;
    pcap_t* handle_;
    std::thread snifferThread_;
    PacketCallback callback_;
    bool running_ = false;
};

#endif