#ifndef IDS_H
#define IDS_H

#include "PacketParser.h"
#include <unordered_map>
#include <chrono>
#include <mutex>

class IDS {
public:
    void analyzePacket(const PacketInfo& info);

private:
    std::unordered_map<std::string, int> synCount_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastSeen_;
    std::mutex mutex_;
};

#endif