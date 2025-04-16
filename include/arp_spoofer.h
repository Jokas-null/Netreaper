#ifndef ARP_SPOOFER_H
#define ARP_SPOOFER_H

#include <string>
#include <vector>
#include "network_scanner.h"

class ARPSpoofer {
public:
    ARPSpoofer(const std::string& iface, const std::string& my_ip, const std::string& my_mac);
    void spoof_single(const Device& victim, const Device& gateway);
    void spoof_all(const std::vector<Device>& devices, const Device& gateway);
    void restore_network();

private:
    std::string interface;
    std::string my_ip;
    std::string my_mac;
    Device last_victim;
    Device last_gateway;
};

// Solo declarar extern aquí
extern ARPSpoofer* globalSpoofer;

#endif