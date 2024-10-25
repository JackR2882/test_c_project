#include "project_headers.h"
#include <iostream>

#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>



#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif



int funcxyz()
{

    std::cout << "Inside funcxyz!\n";
    return(0);

}


u_int16_t handle_ethernet(u_char *args,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet);


u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        std::cout << "Packet length less than ethernet header length!\n";
        return(-1);
    }

    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    std::cout << "ETH: " << ether_ntoa((struct ether_addr*)eptr->ether_shost) << " ";
    

    if (ether_type == ETHERTYPE_IP)
    {
        std::cout << "(IP)\n";
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        std::cout << "(ARP)\n";
    }
    else if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        std::cout << "(RARP)\n";
    }
    else
    {
        std::cout << "(?)\n";
    }

    return(ether_type);

}