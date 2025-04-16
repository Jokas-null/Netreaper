#ifndef NETWORK_SCANNER_H
#define NETWORK_SCANNER_H

#include <string>
#include <vector>

struct Device {
    std::string ip;
    std::string mac;
};

class NetworkScanner {
public:
    NetworkScanner(const std::string& interface, const std::string& ip);
    std::vector<Device> scan();

private:
    std::string interface;
    std::string ip;
};

#endif // NETWORK_SCANNER_H