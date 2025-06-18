#include "IDS.h"
#include <iostream>

void IDS::analyzePacket(const PacketInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (info.protocol == "TCP" && info.dstPort != 0) {
        synCount_[info.srcIP]++;
        auto now = std::chrono::steady_clock::now();

        if (synCount_[info.srcIP] > 100 &&
            std::chrono::duration_cast<std::chrono::seconds>(now - lastSeen_[info.srcIP]).count() < 5) {
            std::cout << "[ALERT] Possible SYN Flood from " << info.srcIP << std::endl;
            synCount_[info.srcIP] = 0;
        }
        lastSeen_[info.srcIP] = now;
    }
}
