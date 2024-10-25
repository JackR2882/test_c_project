/*    My Headers    */
#include "headers/project_headers.h"

/* External Headers */
#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>



void read_packet(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet)
{

    /* call handle_ethernet from ethernet.cpp */
    /* parses ethrnet frame into type */
    u_int16_t type = handle_ethernet(args, pkthdr, packet);

    if(type==ETHERTYPE_IP)
    {
        /* call handle_IP from ip.cpp */
        /* parses IP packet */
        std::cout << ""; // causes a seg fault if removed - NEEDS FIXING
        handle_IP(args, pkthdr, packet);
    }
    else if (type==ETHERTYPE_ARP)
    {
        /* call handle_ARP from arp.cpp */
        /* parses arp packet */
        handle_ARP(args, pkthdr, packet);
    }
    else if(type==ETHERTYPE_REVARP)
    {

    }


}


int main()
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    struct pcap_pkthdr header;
    const u_char *packet;


    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        std::cout << "ERROR: Couldn't find device!\n";
    }
    std::cout << "Device found: " << dev << '\n';

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        std::cout << "ERROR: " << errbuf << '\n';
        return(1);
    }

    /* repeatedly grab a packet (25 times) */
    pcap_loop(handle, 5, read_packet, NULL);

    /* close the session */
    pcap_close(handle);

    return(0);

}