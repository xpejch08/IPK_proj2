#include <stdio.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <signal.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <chrono>


class packetSniffer {
    public:
    /**
     * @brief function that gets all availible interfaces
     */
    pcap_if_t *allInterfaces(){
        pcap_if_t *allInterfaces;
        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_findalldevs(&allInterfaces, errbuf) == -1){
            std::cout << "Error: no interfaces" << errbuf << std::endl;
            exit(1);
        }
        return allInterfaces;
    };
    static void setPacketObject(packetSniffer *packetObject){
        snifferForPacket = packetObject;
    }
    /**
     * @brief function that prints all availible interfaces
     */
    void printInterfaces(pcap_if_t *allInterfaces){
        pcap_if_t *interface;
        int i = 0;
        for(interface = allInterfaces; interface; interface = interface->next){
            std::cout << i << ": " << interface->name << std::endl;
            i++;
        }
    };
    void activeInterface(std::string interfaceArgument, pcap_if_t *allInterfaces){
        pcap_if_t *interface;
        int i = 0;
        for(interface = allInterfaces; interface; interface = interface->next){
            if(interfaceArgument == interface->name){
                std::cout << "Interface: " << interface->name << std::endl;
                return;
            }
            i++;
        }
        std::cout << "Interface not found" << std::endl;
        exit(1);
    };

    void pcapFilter(){
        if(portNumber != -1) {
            if (udp) {
                pcFilter = "(udp port " + std::to_string(portNumber) + ") or";
            }
            if (tcp) {
                pcFilter = "(tcp port " + std::to_string(portNumber) + ") or";
            }
        }else{
            if (udp) {
                pcFilter = "(udp) or";
            }
            if (tcp) {
                pcFilter = "(tcp) or";
            }
        }
        if (icmp4) {
            pcFilter = "(icmp4) or";
        }
        if (icmp6) {
            pcFilter = "(icmp6) or";
        }
        if (igmp) {
            pcFilter = "(igmp) or";
        }
        if (mld) {
            pcFilter = "(mld) or";
        }
        if (ndp) {
            pcFilter = "(ndp) or";
        }
        if (arp) {
            pcFilter = "(arp) or";
        }
        pcFilter = pcFilter.substr(0, pcFilter.size()-3);
    }
    void timeStamp(){
        auto time = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(time);
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()) % 1000;
        std::stringstream stream;
        stream << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%S") << "."
                << std::setfill('0') << std::setw(3) << millis.count() << "Z";
        printf("timestamp: %s \n", stream.str().c_str());
    }
    void printMacAddress(auto filter){
        printf("src MAC: %02X:%02X:%02X:%02X:%02X:%02X",
               filter->ether_shost[0], filter->ether_shost[1],
               filter->ether_shost[2], filter->ether_shost[3],
               filter->ether_shost[4], filter->ether_shost[5]);

        printf("dst MAC: %02X:%02X:%02X:%02X:%02X:%02X",
               filter->ether_dhost[0], filter->ether_dhost[1],
               filter->ether_dhost[2], filter->ether_dhost[3],
               filter->ether_dhost[4], filter->ether_dhost[5]);
    }

    static void packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        snifferForPacket->timeStamp();
        auto size = header->len;
        struct mac_filter *macFilter = (struct mac_filter*)packet;
        const struct iphdr *ipHeader = (struct iphdr*)(packet + sizeof(struct ether_header));
        const struct ether_header *ethernetHeader = (struct ether_header*)packet;
        auto *ipH = (struct ip*)(packet + sizeof(struct ether_header));
        const struct tcphdr *tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        const struct udphdr *udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        const struct icmp *icmpHeader = (struct icmp*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        const struct ip6_hdr *ip6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        const struct ip4_hdr *ip4Header = (struct ip4_hdr*)(packet + sizeof(struct ether_header));
        auto *arpHeader = (struct ether_arp*)(packet + sizeof(struct ether_header));

        if(ethernetHeader->ether_type == htons(ETHERTYPE_IP)){
            //icmp IPV4
            if(ipHeader->protocol == 1){
                snifferForPacket->printMacAddress(ethernetHeader);

            }
            //igmp ipv4
            else if(ipHeader->protocol == 2){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
            //tcp ipv4
            else if(ipHeader->protocol == 6){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
            //udp ipv4
            else if(ipHeader->protocol == 17){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
        }
        else if(ethernetHeader->ether_type == htons(ETHERTYPE_IPV6)){
            //icmp ipv6
            if(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
            //mld ipv6
            else if(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
            //tcp ipv6
            else if(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
            //udp ipv6
            else if(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
            //ndp ipv6
            else if(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58){
                printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
            }
        }
        else if(ethernetHeader->ether_type == htons(ETHERTYPE_ARP)){
            printf("src MAC: %s \n", ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost));
        }


    };
    // Other class members go here

    int checkArguments(int argc, char *argv[]){
        std::string argument;
        pcap_if_t *allInterfaces = this->allInterfaces();
        if(argc < 2){
            printInterfaces(allInterfaces);
            return 0;
        }
        for(int i = 1; i < argc; i++){
            argument = argv[i];
            if(argument == "-h" || argument == "--help"){
                printHelp();
                exit(0);
            }
            else if(argument == "-p") {
                    p = true;
                    try {
                        portNumber = std::stoi(argv[i+1]);
                    }
                    catch (std::exception const &e) {
                        std::cout << "Error: no port number specified" << std::endl;
                        exit(1);
                    }
                    if(portNumber < 0 || portNumber > 65535){
                        std::cout << "Error: invalid port number specified" << std::endl;
                        exit(1);
                    }
            }
            else if(argument == "-u" || argument == "--udp"){
                udp = true;
            }
            else if(argument == "-t" || argument == "--tcp"){
                tcp = true;
            }
            else if(argument == "-i" || argument == "--interface"){
                interface = true;
                try {
                    interfaceArgument = std::string(argv[i+1]);
                }
                catch (std::exception const &e) {
                    printInterfaces(allInterfaces);
                }
                activeInterface(interfaceArgument, allInterfaces);
            }
            else if(argument == "--arp"){

            }
            else if(argument == "--icmp4"){
                icmp4 = true;
            }
            else if(argument == "--icmp6"){
                icmp6 = true;
            }
            else if(argument == "--ndp"){
                ndp = true;
            }
            else if(argument == "--igmp"){

            }
            else if(argument == "mld"){

            }
            else if(argument == "-n"){
                n = true;
                try {
                    packetCountTmp = std::stoi(argv[i+1]);
                }
                catch (std::exception const &e) {
                    std::cout << "Error: no packet count specified" << std::endl;
                    exit(1);
                }
                if(packetCountTmp < 0){
                    std::cout << "Error: invalid packet count specified" << std::endl;
                    exit(1);
                }else{
                    packetCount = packetCountTmp;
                }
            }
            else{
                std::cout << "Error: invalid argument" << std::endl;
                exit(1);
            }
        }
        if(!udp && !tcp && !icmp4 && !icmp6 && !igmp){
            udp = true;
            tcp = true;
            icmp4 = true;
            icmp6 = true;
            igmp = true;
        }
        if (!interface) {
            printInterfaces(allInterfaces);
            return 0;
        }


    };
    void printHelp(){
        std::cout << "Usage: packetSniffer [options] [interface]" << std::endl;
        std::cout << "Options:" << std::endl;
    };
    bool icmp4 = false;
    bool icmp6 = false;
    bool arp = false;
    bool igmp = false;
    bool mld = false;
    bool ndp = false;
    //specifies the number of packets to display, i.e., the "time" the program runs; if not specified, consider displaying only one packet, i.e., as if -n 1
    bool n = false;
    bool p = false;
    bool udp = false;
    bool interface = false;
    bool tcp = false;
    bool help = false;
    int packetCount = 0;
    int portNumber = -1;
    int packetCountTmp = 0;
    std::string interfaceArgument;
    std::string pcFilter;
    bpf_u_int32 ipOfSniffed;
    bpf_u_int32 netmaskOfSniffed;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *sniffedDevice;
    bpf_program pcFilterBpf;

    private:
    static packetSniffer * snifferForPacket;
};


packetSniffer * packetSniffer::snifferForPacket = nullptr;

int main(int argc, char *argv[]){
    packetSniffer sniffer;
    sniffer.checkArguments(argc, argv);
    sniffer.pcapFilter();
    packetSniffer::setPacketObject(&sniffer);


    if (pcap_lookupnet(sniffer.interfaceArgument.c_str(), &sniffer.ipOfSniffed, &sniffer.netmaskOfSniffed, sniffer.errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s. ErrorBuffer: %s", sniffer.interfaceArgument.c_str(),
                sniffer.errbuf);
        return 1;
    }
    if((sniffer.sniffedDevice = pcap_open_live(sniffer.interfaceArgument.c_str(), BUFSIZ, 1, 1000, sniffer.errbuf)) == nullptr){
        pcap_close(sniffer.sniffedDevice);
        fprintf(stderr, "Can't open device %s. ErrorBuffer: %s", sniffer.interfaceArgument.c_str(),
                sniffer.errbuf);
        return 1;
    }
    if (pcap_datalink(sniffer.sniffedDevice) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported", sniffer.interfaceArgument.c_str());
        return 1;
    }
    if (!sniffer.pcFilter.empty()) {
        if(pcap_compile(sniffer.sniffedDevice, &sniffer.pcFilterBpf, sniffer.pcFilter.c_str(), 0, sniffer.ipOfSniffed) == PCAP_ERROR){
            fprintf(stderr, "Couldn't parse filter %s: %s", sniffer.pcFilter.c_str(), pcap_geterr(sniffer.sniffedDevice));
            pcap_close(sniffer.sniffedDevice);
            return 1;
        }
        if(pcap_setfilter(sniffer.sniffedDevice, &sniffer.pcFilterBpf) == PCAP_ERROR){
            fprintf(stderr, "Couldn't install filter %s: %s", sniffer.pcFilter.c_str(), pcap_geterr(sniffer.sniffedDevice));
            pcap_close(sniffer.sniffedDevice);
            return 1;
        }
    }
    if(pcap_loop(sniffer.sniffedDevice, sniffer.packetCount, packetSniffer::packet,  nullptr) == PCAP_ERROR){
        fprintf(stderr, "Error while capturing packets: %s", pcap_geterr(sniffer.sniffedDevice));
        pcap_close(sniffer.sniffedDevice);
        return 1;
    }
    return 0;

}

