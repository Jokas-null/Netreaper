#ifndef GATEWAY_UTILS_H
#define GATEWAY_UTILS_H

#include <string>

void enable_gateway_mode();
void restore_host_network(const std::string& iface);

// Solo declarar extern aquí
extern std::string global_iface;

#endif