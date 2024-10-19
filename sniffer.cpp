/*
** 
**
**  Packet sniffer.
**
**  https://www.tcpdump.org/pcap.html
**
**
*/

#include <stdio.h>
#include <iostream>
#include <pcap.h>

int main() {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    struct pcap_pkthdr header;
    const u_char *packet;


    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        std::cout << "ERROR: Couldn't find device!\n";
        return(1); 
    }
    std::cout << "Device found: " << dev << '\n';
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        std::cout << "ERROR: " << errbuf << '\n';
        return(1);
    }


    /* Grab a packet */
    packet = pcap_next(handle, &header);
    std::cout << "Successfully captured a packet of length: " << header.len << '\n';
    /* Close the session */
    pcap_close(handle);

    return(0);

}