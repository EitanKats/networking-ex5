#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct iphdr *ip = (struct iphdr *)
                (packet + sizeof(struct ethheader));

        printf("       From: %s\n", inet_ntoa(ip->src));
        printf("         To: %s\n", inet_ntoa(ip->dest));

        /* determine protocol */
        switch (ip->proto) {
            case IPPROTO_TCP:
                printf("   Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                return;
            default:
                printf("   Protocol: others\n");
                return;
        }
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
