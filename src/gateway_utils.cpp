#include "gateway_utils.h"
#include <cstdlib>
#include <iostream>

void enable_gateway_mode() {
    std::cout << "[*] Activando IP forwarding y reglas iptables...\n";
    system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null");
    system("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE");
    system("sudo iptables -A FORWARD -i eth0 -j ACCEPT");
}

void restore_host_network(const std::string& iface) {
    std::cout << "[*] Restaurando red del sistema...\n";

    // Limpiar iptables y forwarding
    system("sudo iptables -F");
    system("sudo iptables -t nat -F");
    system("sudo sysctl -w net.ipv4.ip_forward=0");

    // Verificar si hay reglas tc antes de borrarlas
    std::string check_tc = "sudo tc qdisc show dev " + iface + " | grep -q 'qdisc'";
    if (system(check_tc.c_str()) == 0) {
        std::string clear_tc = "sudo tc qdisc del dev " + iface + " root";
        system(clear_tc.c_str());
    }

    std::cout << "[✔] Red del host restaurada.\n";
}