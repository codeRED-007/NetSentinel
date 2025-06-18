# C++ Real-Time Packet Sniffer and Intrusion Detection System (IDS)

This project is a real-time packet sniffer and basic intrusion detection system written in C++.
It uses the `libpcap` library to capture live network traffic and applies simple rule-based
analysis to detect potential threats such as SYN flood attacks and port scans.

---

## Features

- Real-time packet capture using `libpcap`
- Parses Ethernet, IP, TCP, and UDP headers
- Detects common network anomalies:
  - SYN flood attacks
  - Port scans based on destination port diversity
- Multithreaded architecture for non-blocking capture and analysis
- Command-line interface (CLI) output with timestamps and protocol details
- Logs alerts to a file (`alerts.log`) for later review
- Modular design: separation of packet capture, parsing, and threat analysis

---


