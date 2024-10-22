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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>


#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

u_int16_t handle_ethernet(u_char *args,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet);
u_char* handle_IP(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet);

u_char* handle_ARP(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet);


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




void handle_packet(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet)
{
    
    
    u_int16_t type = handle_ethernet(args, pkthdr, packet);

    if(type==ETHERTYPE_IP)
    {
        std::cout << "FIX ME" << '\n'; // causes a seg fault if I remove it?
        //handle_IP(args, pkthdr, packet);
    }
    else if (type==ETHERTYPE_ARP)
    {
        // can generate arp traffic with 'sudo arping 192.168.1.189'
        handle_ARP(args, pkthdr, packet);
    }
    else if (type==ETHERTYPE_REVARP)
    {
        /* handle reverse arp packet */
    }
    

    static int count = 1;
    std::cout << "Packet " << count << ": ";
    std::cout << "Successfully captured a packet of length: " << pkthdr[count-1].len << '\n';
    count++;

}


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
        std::cout << "IP: " << inet_ntoa(ip->ip_src) << '\n';
        std::cout << "Header length: " << hlen << '\n';
        std::cout << "Version: " << version << '\n';
        std::cout << "Offset? " << off << '\n';
    }

    return(NULL);    

}



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

    std::cout << "ETH: " << ether_ntoa((struct ether_addr*)eptr->ether_shost) << '\n';
    

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
    //packet = pcap_next(handle, &header);
    //std::cout << "Successfully captured a packet of length: " << header.len << '\n';
    /* close the session */
    //pcap_close(handle);

    /* repeatedly grab a packet (25 times) */
    pcap_loop(handle, 25, handle_packet, NULL);


    /* close the session */
    pcap_close(handle);

    return(0);

}