// add to tasks.json

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




/*   ...Testing...   */
int func1()
{

    std::cout << ("Inside ip.cpp!\n");
    return(0);

}



int func2()
{
    std::cout << ("Inside ip.cpp![2]\n");
    return(0);
}
/* ...End Testing... */




/* structure of an IP ethernet header - sourced from tcpdump */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};



u_char* handle_IP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct my_ip* ip;
    //u_int length = pkthdrif->len;
    u_int length = ip->ip_len;
    u_int hlen,off,version;
    int i;

    int len;

    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check length is valid */
    if (length < sizeof(struct my_ip))
    {
        std::cout << "Truncated IP " << length << '\n';
        return(NULL); 
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);

    if (version != 4)
    {
        std::cout << "Unknown version " << version << '\n';
    }

    if (hlen < 5)
    {
        std::cout << "Bad header length " << hlen << '\n';
    }

    if (length < len)
    {
        std::cout << "Truncated IP " << len-length << " bytes missing!\n";
    }

    /* check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0)
    {
        std::cout   << "IP: " << inet_ntoa(ip->ip_src) << ", "
                    << "Header length: " << hlen << ", "
                    << "Version: " << version << ", "
                    << "Offset? " << off << '\n';
    }

    //std::cout << "Protocol: " << ip->ip_p << '\n';

    return(NULL);    

}




