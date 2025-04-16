#ifndef TRAFFIC_CONTROL_H
#define TRAFFIC_CONTROL_H

#include <string>

void apply_tc_limit(const std::string& iface, const std::string& ip);
void apply_tc_loss(const std::string& iface, const std::string& ip);
void apply_tc_delay(const std::string& iface, const std::string& ip);
void apply_tc_combo(const std::string& iface, const std::string& ip);
void remove_tc(const std::string& iface);

#endif // TRAFFIC_CONTROL_H