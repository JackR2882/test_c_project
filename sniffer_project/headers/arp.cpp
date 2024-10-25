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



/* structure of an ARP ethernet header - sourced from tcpdump */
struct  arp_pkthdr {
        u_int16_t ar_hrd;     /* format of hardware address */
#define ARPHRD_ETHER    1       /* ethernet hardware format */
#define ARPHRD_IEEE802  6       /* token-ring hardware format */
#define ARPHRD_ARCNET   7       /* arcnet hardware format */
#define ARPHRD_FRELAY   15      /* frame relay hardware format */
#define ARPHRD_ATM2225  19      /* ATM (RFC 2225) */
#define ARPHRD_STRIP    23      /* Ricochet Starmode Radio hardware format */
#define ARPHRD_IEEE1394 24      /* IEEE 1394 (FireWire) hardware format */
#define ARPHRD_INFINIBAND 32    /* InfiniBand RFC 4391 */
        u_int16_t ar_pro;     /* format of protocol address */
        u_int8_t  ar_hln;     /* length of hardware address */
        u_int8_t  ar_pln;     /* length of protocol address */
        u_int16_t ar_op;      /* one of: */
#define ARPOP_REQUEST   1       /* request to resolve address */
#define ARPOP_REPLY     2       /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY  4       /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY  9       /* response identifying peer */
#define ARPOP_NAK       10      /* NAK - only valid for ATM ARP */

/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	nd_byte		ar_sha[];	/* sender hardware address */
	nd_byte		ar_spa[];	/* sender protocol address */
	nd_byte		ar_tha[];	/* target hardware address */
	nd_byte		ar_tpa[];	/* target protocol address */
#endif
#define ar_sha(ap)	(((const u_char *)((ap)+1))+  0)
#define ar_spa(ap)	(((const u_char *)((ap)+1))+  GET_U_1((ap)->ar_hln))
#define ar_tha(ap)	(((const u_char *)((ap)+1))+  GET_U_1((ap)->ar_hln)+GET_U_1((ap)->ar_pln))
#define ar_tpa(ap)	(((const u_char *)((ap)+1))+2*GET_U_1((ap)->ar_hln)+GET_U_1((ap)->ar_pln))
};



u_char* handle_ARP(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{

    const struct arp_pkthdr* arp;
    u_int length = arp->ar_hln;
    std::cout << length << ' ' << '\n';
    std::cout << arp->ar_op << '\n';
    std::cout << arp->ar_hrd << '\n';


    std::cout << "INSIDE <handle_ARP>\n";

    return(NULL);

}