#include "traffic_control.h"
#include <cstdlib>
#include <iostream>

void apply_tc_limit(const std::string& iface, const std::string& ip) {
    remove_tc(iface);
    std::string cmd =
        "sudo tc qdisc add dev " + iface + " root handle 1: htb default 30 && "
        "sudo tc class add dev " + iface + " parent 1: classid 1:1 htb rate 100mbit && "
        "sudo tc class add dev " + iface + " parent 1:1 classid 1:30 htb rate 100kbps && "
        "sudo tc filter add dev " + iface + " protocol ip parent 1:0 prio 1 u32 match ip dst " + ip + " flowid 1:30";
    system(cmd.c_str());
    std::cout << "[*] Límite de 100kbps aplicado a " << ip << std::endl;
}

void apply_tc_loss(const std::string& iface, const std::string& ip) {
    remove_tc(iface);
    std::string cmd =
        "sudo tc qdisc add dev " + iface + " root handle 1: prio && "
        "sudo tc qdisc add dev " + iface + " parent 1:3 handle 30: netem loss 50% && "
        "sudo tc filter add dev " + iface + " protocol ip parent 1:0 prio 3 u32 match ip dst " + ip + " flowid 1:3";
    system(cmd.c_str());
    std::cout << "[*] Pérdida del 50% de paquetes aplicada a " << ip << std::endl;
}

void apply_tc_delay(const std::string& iface, const std::string& ip) {
    remove_tc(iface);
    std::string cmd =
        "sudo tc qdisc add dev " + iface + " root handle 1: prio && "
        "sudo tc qdisc add dev " + iface + " parent 1:3 handle 30: netem delay 1000ms && "
        "sudo tc filter add dev " + iface + " protocol ip parent 1:0 prio 3 u32 match ip dst " + ip + " flowid 1:3";
    system(cmd.c_str());
    std::cout << "[*] Latencia de 1000ms aplicada a " << ip << std::endl;
}

void apply_tc_combo(const std::string& iface, const std::string& ip) {
    remove_tc(iface);
    std::string cmd =
        "sudo tc qdisc add dev " + iface + " root handle 1: prio && "
        "sudo tc qdisc add dev " + iface + " parent 1:3 handle 30: netem delay 1000ms loss 30% rate 100kbps && "
        "sudo tc filter add dev " + iface + " protocol ip parent 1:0 prio 3 u32 match ip dst " + ip + " flowid 1:3";
    system(cmd.c_str());
    std::cout << "[*] Combo (delay + pérdida + límite) aplicado a " << ip << std::endl;
}

void remove_tc(const std::string& iface) {
    std::string cmd = "sudo tc qdisc del dev " + iface + " root";
    system(cmd.c_str());
    std::cout << "[*] Reglas de tráfico eliminadas de " << iface << std::endl;
}