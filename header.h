
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct eth_hdr {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_hdr {
    u_char ihl:4,		    /*IP header length*/
           version:4;       /* version << 4 | header length >> 2 */
    u_char tos;		        /* type of service */
    u_short tot_len;		/* total length */
    u_short id;		        /* identification */
    u_short frag_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ttl;		/* time to live */
    u_char protocol;		/* protocol */
    u_short check;		/* checksum */
    struct in_addr saddr, daddr; /* source and dest address */
};


/* TCP header */
typedef u_int tcp_seq;

struct tcp_hdr{
    u_short sport;	/* source port */
    u_short dport;	/* destination port */
    tcp_seq seq;		/* sequence number */
    tcp_seq ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
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
    u_short window;		/* window */
    u_short checksum;		/* checksum */
    u_short urg_ptr;		/* urgent pointer */


};

struct icmp_hdr
{
    unsigned char type;        // ICMP message type
    unsigned char code;        // Error code
    unsigned short int checksum; // Checksum for ICMP Header and data
    unsigned short int id;     // Used for identifying request
    unsigned short int seq;    // Sequence number
};

struct app_hdr{
    uint32_t timestamp;
    uint16_t total_length;
    union
    {
        uint16_t reserved : 3, cache_flag : 1, steps_flag : 1, type_flag : 1, status_code : 10;
        uint16_t flags;
    };
    uint16_t cache_control;
    uint16_t padding;
};





