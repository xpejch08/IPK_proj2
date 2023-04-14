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
    void printInterfaces(pcap_if_t *allInterfaces){
        pcap_if_t *interface;
        int i = 0;
        for(interface = allInterfaces; interface; interface = interface->next){
            std::cout << i << ": " << interface->name << std::endl;
            i++;
        }
    };

    int checkArguments(int argc, char *argv[]){
        std::string argument;
        pcap_if_t *allInterfaces = this->allInterfaces();
        for(int i = 1; i < argc; i++){
            argument = argv[i];
            if(argument == "-h" || argument == "--help"){
                printHelp();
                return 0;
            }
            else if(argument == "-p") {

            }
            else if(argument == "-u" || argument == "--udp"){
                udp = true;
            }
            else if(argument == "-t" || argument == "--tcp"){
                tcp = true;
            }
            else if(argument == "-i" || argument == "--interface"){
                interface = true;
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

            }
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
    bool n = false;
    bool udp = false;
    bool interface = false;
    bool tcp = false;
    bool help = false;

};

int main(int argc, char *argv[]){


}

