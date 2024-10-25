// not best practice but will use a single header file for simplicity


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>


#ifndef IP_H
#define IP_H
u_char* handle_IP(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet);
#endif


#ifndef ETHERNET_H
#define ETHERNET_H
u_int16_t handle_ethernet(u_char *args,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet);
#endif


#ifndef ARP_H
#define ARP_H
u_char* handle_ARP(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet);
#endif