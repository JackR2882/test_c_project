/*    My Headers    */
//#include "headers/project_headers.h"

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
#include <ctime>
#include <fstream>
#include <string>
#include <cstring>



int icmp_count = 0;
int tcp_count = 0;
int udp_count = 0;
int dns_count = 0;

std::string output_file = "data/test_output.csv";

std::ofstream write_file;


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


/* structure of a TCP header */
struct my_tcp {
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int32_t seq; /* sequence number */
    u_int32_t ack;
    u_int8_t not_sure; /* fix this later */
    u_int8_t flags; /* fix this later */
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
    /* options if data_offset > 5, padded with zeros to a multiple of 32 bits */
    /* data */
};


/* structure of a UDP header */
struct my_udp {
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int16_t length;
    u_int16_t checksum;
};



void read_packet(u_char *args,
                const struct pcap_pkthdr* pkthdr,
                const u_char* packet)
{


    /* get the timestamp for the current date and time */
    time_t timestamp;
    time(&timestamp);
    /* strip \n from timemestamp */
    char *ts;
    ts = ctime(&timestamp);
    ts[std::strlen(ts) - 1] = '\0';


    const struct my_ip* ip;
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));


    std::cout << "--------------------------------------------\n";


    struct ether_header *eth_hdr;
    eth_hdr = (struct ether_header *) packet;

    u_int16_t eth_type = ntohs(eth_hdr->ether_type);

    if (eth_type == ETHERTYPE_IP)
    {
        std::cout << "(IP)\n";

        std::cout << "Bytes avaialable: " << pkthdr->caplen << " | ";
        std::cout << "Expected packet size: " << pkthdr->len << '\n';


        /* variables to store transport layer information */
        int s_port = 0;
        int d_port = 0;
        int c_length = 0;
        std::string proto = "";
        std::string tcp_flag = "";

        /* pointers to various headers */
        const u_char *ip_hdr;
        const u_char *tcp_hdr;
        const u_char *udp_hdr;
        const u_char *payload;

        int ether_hdr_len = 14; // static
        int ip_hdr_len;
        int tcp_hdr_len;
        int payload_len;


        /* update ip header pointer */
        ip_hdr = packet + ether_hdr_len;
        ip_hdr_len = ((*ip_hdr) & 0x0F);
        ip_hdr_len = ip_hdr_len * 4;
        std::cout << "IP header length (IHL) in bytes: " << ip_hdr_len << '\n';

        /* protocol is always the 10th byte of the IP header */
        u_char protocol = *(ip_hdr + 9);
        
        std::cout << "Source IP: " << inet_ntoa(ip->ip_src) << '\n';
        std::cout << "Destination IP: " << inet_ntoa(ip->ip_dst) << '\n';


        if (protocol == IPPROTO_TCP)
        {

            tcp_hdr = packet + ether_hdr_len + ip_hdr_len; /* update tcp header pointer */

            const struct my_tcp* tcp;
            tcp = (struct my_tcp*)(tcp_hdr);

            tcp_count++;
            std::cout << "(TCP) packet count: " << tcp_count << '\n';

            tcp_hdr_len = ((*(tcp_hdr + 12)) & 0xF0) >> 4; /* tcp header length is stored in first half of 12th byte in header */
            tcp_hdr_len = tcp_hdr_len * 4; /* multiply by four to get a byte count */
            std::cout << "TCP header length in bytes: " << tcp_hdr_len << '\n';
    

            std::cout << "Source port: " << ntohs(tcp->src_port) << '\n';
            std::cout << "Destination port: " << ntohs(tcp->dst_port) << '\n';


            int content_length;
            content_length = pkthdr->caplen - (ether_hdr_len + ip_hdr_len + tcp_hdr_len);
            std::cout << "Payload size: " << content_length << '\n';


            s_port = ntohs(tcp->src_port);
            d_port = ntohs(tcp->dst_port);
            c_length = content_length;
            proto = "TCP";

            // parse tcp flag
            std::cout << "Flag: ";
            switch(unsigned(tcp->flags))
            {
                case 1:
                    std::cout << "FIN\n"; tcp_flag = "FIN"; break;
                case 2:
                    std::cout << "SYN\n"; tcp_flag = "SYN"; break;
                case 4:
                    std::cout << "RST\n"; tcp_flag = "RST"; break;
                case 8:
                    std::cout << "PSH\n"; tcp_flag = "PSH"; break;
                case 16:
                    std::cout << "ACK\n"; tcp_flag = "ACK"; break;
                case 32:
                    std::cout << "URG\n"; tcp_flag = "URG"; break;
                case 64:
                    std::cout << "ECE\n"; tcp_flag = "ECE"; break;
                case 128:
                    std::cout << "CWR\n"; tcp_flag = "CWR"; break;
                
            }

        }
        else if (protocol == IPPROTO_UDP)
        {

            udp_count++;
            std::cout << "(UDP) packet count: " << udp_count << '\n';

            udp_hdr = packet + ether_hdr_len + ip_hdr_len; /* update tcp header pointer */

            const struct my_udp* udp;
            udp = (struct my_udp*)(udp_hdr);

            std::cout << "Source port: " << udp->src_port << '\n';
            std::cout << "Destination port: " << udp->dst_port << '\n';

            int content_length;
            content_length = pkthdr->caplen - (ether_hdr_len + ip_hdr_len + ntohs(udp->length));
            std::cout << "Payload size: " << content_length << '\n';

            s_port = ntohs(udp->src_port);
            d_port = ntohs(udp->dst_port);
            c_length = content_length;
            proto = "UDP";

        }
        else
        {
            std::cout << "<UNSUPPORTED PROTOCOL: " << protocol << ")\n";
            return;
        }

        std::cout   << "Writing: << " << inet_ntoa(ip->ip_src) << ','
                    << inet_ntoa(ip->ip_dst) << ','
                    << proto << ','
                    << s_port << ','
                    << d_port << ','
                    << c_length << ','
                    << ts << ','
                    << tcp_flag << ','
                    << " >>\n";

        write_file  << inet_ntoa(ip->ip_src) << ','
                    << inet_ntoa(ip->ip_dst) << ','
                    << proto << ','
                    << ntohs(s_port) << ','
                    << ntohs(d_port) << ','
                    << c_length << ','
                    << ts << ','
                    << tcp_flag << ','
                    << '\n';

    }
    else if (eth_type == ETHERTYPE_ARP)
    {
        std::cout << "(ARP)\n";
    }
    else if (eth_type == ETHERTYPE_REVARP)
    {
        std::cout << "(REVARP)\n";
    }
    else
    {
        std::cout << "(UNSUPPORTED ETHERTYPE: " << eth_type <<  ")\n";
    }

    std::cout << "--------------------------------------------\n";


}


int main()
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *devs;

    struct pcap_pkthdr header;
    const u_char *packet;


    /* grab device */
    pcap_findalldevs(&devs, errbuf);
    if (devs->name == NULL) // error check for device not found
    {
        std::cout << "ERROR: " << errbuf << '\n';
        return(1);
    }
    dev = devs->name; // device found

    std::cout << "Device found: " << dev << '\n';

    /* open device for listening */
    handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
    if (handle == NULL)
    {
        std::cout << "ERROR: " << errbuf << '\n';
        return(1);
    }

    /* open output file */
    write_file.open(output_file);
    /* output column titles */
    write_file << "Source-IP,Destination-IP,Protocol,Source-Port,Destination-Port,Content-Length,Timestamp,TCP-Flag\n";


    /* repeatedly grab a packet (5 times) */
    pcap_loop(handle, 5, read_packet, NULL);
    /* repeatedly grab a packet (unlimited times) */
    //pcap_loop(handle, -1, read_packet, NULL);

    /* close device after listening */
    pcap_close(handle);

    /* close output file */
    write_file.close();

    return(0);

}