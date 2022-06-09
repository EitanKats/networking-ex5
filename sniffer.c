#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;
    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char str[INET_ADDRSTRLEN];

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct iphdr *ip = (struct iphdr *) (packet + sizeof(struct ethheader));

        inet_ntop(AF_INET, &(ip->saddr), str, INET_ADDRSTRLEN);
        printf("       From: %s\n", str);
        inet_ntop(AF_INET, &(ip->daddr), str, INET_ADDRSTRLEN);
        printf("         To: %s\n", str);

        struct icmphdr *icmp_hdr = (struct icmphdr *) ((char *) ip + (4 * ip->ihl));
        printf("ICMP msgtype=%d, code=%d", icmp_hdr->type, icmp_hdr->code);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net = 0;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}
