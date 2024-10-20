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



void handle_packet(u_char *useless,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet)
{
    static int count = 1;
    std::cout << "Packet " << count << ": ";
    std::cout << "Successfully captured a packet of length: " << pkthdr[count-1].len << '\n';
    count++;
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
        return(1); 
    }
    std::cout << "Device found: " << dev << '\n';
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        std::cout << "ERROR: " << errbuf << '\n';
        return(1);
    }


    /* grab a packet */
    packet = pcap_next(handle, &header);
    std::cout << "Successfully captured a packet of length: " << header.len << '\n';
    /* close the session */
    //pcap_close(handle);

    /* repeatedly grab a packet (25 times) */
    pcap_loop(handle, 25, handle_packet, NULL);


    /* close the session */
    pcap_close(handle);

    return(0);

}