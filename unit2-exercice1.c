//*** C program using libpcap to collect traffic by ORIOL LALAGUNA ROYO ***//

#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; //Destination host address
    u_char ether_shost[ETHER_ADDR_LEN]; //Source host address
    u_short ether_type;                 //IP/ARP/RARP/ETC
};

/* IP HEADER */
struct sniff_ip {
    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int ip_hl:4, /* header length */
    ip_v:4; /* version */
    #if BYTE_ORDER == BIG_ENDIAN
    u_int ip_v:4, /* version */
    ip_hl:4; /* header length */
    #endif
    #endif /* not _IP_VHL */
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* TCP HEADER */
struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq; /* sequence number */
    tcp_seq th_ack; /*acknowledgement number */
    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int th_x2:4, /* (unused) */
    th_off:4; /* data offset */
    #endif
    #if BTE_ORDER == BIG_ENDIAN
    u_int th_off:4, /* data offset */
    th_x2:4; /* (unused) */
    #endif
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

int execute;
//void trap(int signal){ execute = 0; }

int main() { 
    //signal(SIGINT, &trap);
    execute = 1;

    pcap_t *handle;                 //Session handle
    char *dev ="enp0s3";            //The device to sniff on (virtualbox default ubuntu v.18 interface)
    char errbuf[PCAP_ERRBUF_SIZE];  //Error string
    struct bpf_program filter;      //The compiled filter
    char filter_app[]= "port 443, port 80";  //The filter expression
    bpf_u_int32 mask;               //Our netmask
    bpf_u_int32 net;                //Our IP
    struct pcap_pkthdr header;      //The header that pcap gives us
    const u_char *packet;           //The actual packet
    
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packed payload*/
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);

    while(execute){
        /* Define the device  */
        dev = pcap_lookupdev(errbuf); 
        /* Find the properties for the device */
        pcap_lookupnet(dev, &net, &mask, errbuf);
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        /* Compile and apply the filter */
        pcap_compile(handle, &filter, filter_app, 0, net);
        pcap_setfilter(handle, &filter);
        /* Grab a packet */
        packet = pcap_next(handle, &header);

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + size_ethernet);
        tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
        payload = (u_char*)(packet + size_ethernet + size_ip + size_tcp);

        /* Print its length */
        printf("Jacked a packet with length of [%d]\n", header.len);
        /* Print its received time */
        printf ("received at %s", ctime((const time_t*)&header.ts.tv_sec));
        /* Print its IP information */
        printf("src address: %s -- ",  inet_ntoa(ip->ip_src));
        printf("dest address: %s\n", inet_ntoa(ip->ip_dst));
        printf("\n");

        /* And close the session */
        pcap_close(handle);
    }
    //signal(SIGINT, SIG_DFL);
    return(0); 
}
