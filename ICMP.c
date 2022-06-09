// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
// 
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>

// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short *paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant _2QXDIKDnWcIGaod9GQqQjW4jgOEVup2ZvrLr
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click 
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

#define SOURCE_IP "0.0.0.0"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

int pid = -1;
struct protoent *proto = NULL;

void display(void *buf, int bytes) {
    int i;
    struct iphdr *ip = buf;
    struct icmphdr *icmp = buf + ip->ihl * 4;

    printf("----------------\n");
    printf("IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d\n",
           ip->version, ip->ihl * 4, ntohs(ip->tot_len), ip->protocol, ip->ttl);
    printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d]\n",
           icmp->type, icmp->code, ntohs(icmp->checksum),
           icmp->un.echo.id, icmp->un.echo.sequence);
}

int main() {
    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;

    // Source IP
    if (inet_pton(AF_INET, SOURCE_IP, &(iphdr.ip_src)) <= 0) {
        fprintf(stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return -1;
    }

    // Destination IPv
    if (inet_pton(AF_INET, DESTINATION_IP, &(iphdr.ip_dst)) <= 0) {
        fprintf(stderr, "inet_pton() failed for destination-ip with error: %d", errno);
        return -1;
    }

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // It serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18;

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    struct timeval start;
    struct timeval end;
    long double micro_seconds;

    gettimeofday(&start, NULL);
    // Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof(dest_in)) == -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }

    // Close the raw socket descriptor.
    unsigned char buf[1024];
    int bytes, len = sizeof(dest_in);

    bzero(buf, sizeof(buf));
    bytes = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &dest_in, &len);
    if (bytes > 0) {
        gettimeofday(&end, NULL);
        micro_seconds = (long double) (end.tv_usec - start.tv_usec);

        printf("Took %Lf Micro seconds , and %Lf Milli seconds\n", micro_seconds, micro_seconds/1000.0);
        display(buf, bytes);
        return 1;
    } else {
        perror("recvfrom");
    }
    close(sock);
    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}


