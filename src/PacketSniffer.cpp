#include "PacketSniffer.h"
#include <iostream>

PacketSniffer::PacketSniffer(const std::string& device, PacketCallback callback)
    : device_(device), callback_(callback) {}

void PacketSniffer::start() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(device_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "Could not open device " << device_ << ": " << errbuf << std::endl;
        return;
    }

    running_ = true;
    snifferThread_ = std::thread([this]() {
        while (running_) {
            struct pcap_pkthdr* header;
            const u_char* data;
            int result = pcap_next_ex(handle_, &header, &data);
            if (result == 1 && callback_) {
                callback_(header, data);
            }
        }
        pcap_close(handle_);
    });
}

void PacketSniffer::stop() {
    running_ = false;
    if (snifferThread_.joinable()) snifferThread_.join();
}

