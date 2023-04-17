# IPK Project2 ZETA variant
Implementation of a packet sniffer in c++
## Authors

- [@xpejch08](https://www.github.com/xpejch08)

## Basic theory about packet sniffing and protocols
### What is a packet sniffer
A packet sniffer is a tool used for monitoring traffic on a network. It's function is to capture datapackets sent through the network. The sniffer in our case can detect the timestamp of the sent packet the source and destination MAC adress, the length of the frame, the source and destination IP if the desired protocol contains one, the source and destination port number if the the desired protocol contains one and the byte offset.
#### Use of packet sniffers
Packet sniffers can be used legitametly or illegitimately. That is because a packet sniffer can retrieve a lot of data from a packet such as the IP and MAC adress and mainly the actua packets. With this data you could find website that a user sending the packet visits and amongst other information in some cases even retrieve for example log in details. Packet sniffers are practically used by software companies for checking the traffic on your network, they can also be used in contained enviroments like firms or schools to check the workers/students internet traffic. We can also divide sniffers into active and passive sniffers. Passive sniffers (like the one in my implementation) just read and analyze the packets, active sniffers can actually change the data. 
#### How do they work
My implementation revolves mostly aaround a c++ library called pcap.h (the refference to the library can be found in sources below). Using the functions from the pcap library we can detect specific packets based on the command line arguments the user inputs.

1. I try to lookup the mask for the device where we want to sniff our packets using the pcap_lookupnet function defined in pcap.h. 
2. If I find the mask without error we continue by an attempt on opening a live capture session on the specified device using the pcap_open_live function
3. I then check if the device provides ethernet headers as specified in the task. The device is storred in sniffer.sniffedDevice. 
4. I then check for a packet filter derived from the input arguments with the function pcap_compile and then set the filter using the pcap_setfilter function.
5. Using the pcap_loop function I sniff for packets on the desired device stored in sniffer.sniffedDevice, the function also takes in the parameter sniffer.packetCount which tells me how many packets the user wants to sniff.
6. Then I close the device using pcap_close
**If any of the pcap functions return errors the device is closed with pcap_close and the program is ended**

### The protocols I use to sniff
#### The OSI model
The Open Systems Interconnection model is a model used for decribing network communication. It describes the network protocols and how communication works between different devices. It is described in 7 layers
![Picture 1](/img/osi.png "OSI model")

#### TCP
TCP (Transmission Control Protocol) is a defined way of communication through a network between 2 seperete candidates. TCP unlike UDP is a connection-oriented protocol which means the connection has to be established and maintained untill the final message exchange ends. That makes TCP more reliable. TCP is one of the most used protocols, because it ensures you will recieve your packets correctly. In TCP communication there are 4 main parts to implement on the client side and those are:
- Creating a socket and connecting to a server
- Sending a message(request) to the server
- Read the reply from the server
- Closing the connection with the server
#### UDP
UDP (User Datagram Protocol) is also a defined way of communication similar to TCP. The main difference between TCP and UDP is that UDP is a connectionless and unreliable protocol. There is no need to establish a connection prior to data transfer, that can result in some loss of data and that is why UDP is used mainly for low-latency, losst-tolerating connections established over a network. The UDP communication is used for example in voice or video connection mainly because it is more efficient. One of the reasons is that UDP doesn't check for errors. In UDP communication there are also 4 main parts to implement on the client side:
- Creating a socket(in UDP u don't have to conncect before sending packets)
- Creating a packet(datagram) with the serverIP and port and sending it
- Reading a packet(datagram) from the server
- closing th connection
#### icmp
Internet Control Message Protocol is a protocol used by devices such as routers or switches. It is used to communicate messages about the condition of the network and operational conditions such as error messages. Icmp is used with both IPv4 and IPv6 hence the commanadl line arguments specified in the task. This protocol works on top of the IP Internet Protocol.
#### arp
Adress Resolution Protocol is a protocol used to map a network adress to a physical adress. for example it caps the IP adress to the MAC address. When 2 devices want to communicate they usually know just the network adress. That is why arp exists, it maps the network adress of the devices we want to communicate to and gets it's physical address. It can be used with both IPv4 and IPv6. 
#### ndp
Neighbor Discovery protocol is an IPv6 protocol used for discovering neighboring nodes on a network. There are 4 main messages it uses Neighbor Solicitation (NS), Neighbor Advertisement (NA), Router Solicitation (RS), and Router Advertisement (RA). When NDP is used, nodes can automatically obtain IPv6 addresses. It runs under the ICMP IPv6 protocol
#### igmp
Internmet Group Managment Protocol is a protocol used for hosts to establish multicast memberships. It is used mainly by IP hosts to report their multicast group memberships to multicast routers. 
#### mld
the Multicast Listener Discovery runs under the ICMP IPv6 protocol like NDP the difference between NDP and MLD is that MLD is used for discovering which hosts on a link are interested in recieving multitask traffic.
### My implementation
I decided to use c++ for my implementation.
#### Main structure of program
My program consists of 2 main parts
- class packetSniffer
- main function of program
#### packet Sniffer class:
This class contains all methods (except for the signalHandler) that are used for the sniffer implementation and are not inbuilt functions of the pcap.h lib.  

methods: 
- pcap_if_t allInterfaces
- static void setPacketObject
- void printInterfaces
- void interfaceCheck
- void pcapFilter
- void timeStamp
- void printMacAndFrameLen
- void srcIP
- void printIpOfIpv6
- void printByteOffset
- void printSrcDstArp
- static void packet
- int checkArguments
- void printHelp  
variables public:
- boolean variables for each command line argument set in the checkArguments function
- boolean interfaceExists that is set when checking if interface exists
- std::string interfaceArgument contains the name of the interface we want to sniff packets on
- std::string pcFilter used for setting the pcap filter, the sniffer then looks only for packets defined in the filter
- bpf_u_int32 used for getting the ip of the sniffed device
- bpf_u_int32 used for getting the netmask of the sniffed device
- char errbuf[PCAP_ERRBUF_SIZE] used for storing error messages
- pcap_t *sniffedDevice predefined struct from pcap.h for storing info about the sniffed device
- bpf_program pcFilterBpf predefined structure for storing information about the pcap filter  

**allInterfaces method**: a function that returns all availible interfaces using the pcap_findalldevs function. The interfaces are stored in the allInterfaces variable of type pcap_if_t.  
**setPacketObject method**: this method is used for setting the variable snifferForPacket. I had to create this variable and method, because the pcap_loop function takes a pointer to a static function as the third parameter, because of that I couldn't regularly access the method from inside of the class unless I made it static. But because of that, calling nonstatic methods from the function is an error. This method sets this object to point to the same memory as the object defined in main so I can use it's methods in a static function.  
**printInterfaces method**: function that prints all availible interfaces on stdin, called when the -interface/-i parameter is used  
**interfaceCheck method**: this method checks if the interface passed in the command line argument exists  
**pcapFilter method**: This method sets the pcapFilter accordingly based on the command line arguments. It checks whether or not the boolean variables for each argument are true or not and then concatenates them to an std::string. The string is then used in the pcap_compile function in main to create the actual filter. It first checks whether or not the port number was specified, then accordingly sets the udp and tcp filter. If not, it sets the rest. 
**timestamp method**: this method creates the timestamp according to the RFC 3339 format  
**printMacAndFrameLen method**: This method prints out the source and destination MAC address and then prints out the length of the frame in bytes. I pass the function a const struct ether_header* that contains all of the data in the ->ethershost[n]. I also pass the frame length.  
**srcIP method**: This method takes in a parameter of struct ip* and prints the source and destination ip. Used in IPv4 protocols.  
**printIpOfIpv6**: This method takes 2 parameters of the const struct in6_addr* type. These structures contain the IPv6 ip adress. I pass 2 parameters one for source and one for destination. This method was implemented based on an answer I found on stackoverflow (the source is found below).  
**printByteOffset method**: This method prints the actual packet data. It takes in the data of the packet and the length. It iterates through the data and prints out the characters in hexadecimal, after 16 bytes it prints out the corresponding characters in ASCII. If they are printable the character is printed else a '.' is printed. In the end, if the number is not divisible by 16 it padds the rest with spaces, so the format stays intact.
**printSrcDstArp method**: this function prints the source and destination if the ARP protocol is used with the packet. It takes in 2 string(source and destination), and prints them on stdout.
**packet method**: This is the main method of the packetSniffer. It is called in the pcap_loop function in main and prints out the data requested for the specific packet. First I call the timeStamp method through the snifferForPacket object to print the timestamp of the sniffed packet. Then I create variables for each protocol that we will need. Also I declare a ether_header variable and assign it to the pacet. This built in structure contains the data about our packet. I use it in the if else clauses to check for the type and then respond accordingly. I also set the variable of type iphdr. This variable contains the specific protocol number which we use for checking the desired protocol and printing out the correct data. I also save the length of the packet in the variable size. First I check for the ETHERTYPE_IP which tells me that the packet is a IPv4 protocol. Next I check the specific protocol. The icmp IPv4 and igmp IPv4 only contain the MAC adresses and the Source addresses. The tcp and udp with IPv4 also print out the source and destination port. After that I move on to the ETHERNETYPE_IPV6. The icmp IPv6, MLD and NDP contain the MAC adress and the IP's the TCP and UDP packets also contain the ports  so i print the packets accordingly to there type. The last part is checking for ETHERTYPE_ARP. I first assign a new ether_arp variable I use that to extract the source and destination IP. I then print the MAC adresses and call the printSrcDstArp to print out the source and destination IP's. In the end I call the printByteOffset that prints the contents of the packet.  
**checkArguments method**: this method is used for checking the command line arguments and parses them accordingly. Also the method sets the boolean variables that check what command line argument was set.
**printHelp method**: This method prints the usage oh the program when the command line help parameter is included.
#### main function of program
In the main function I first declare the sniffer object of the packetSniffer class. It then calls the chekArguments method and pcapFilter method to set the pcap filter. I then call the setPacketObject method because of the pointer function (described above in the setPacketObject method). Next i call the signal function that checks for the keyboard interruption by user. When it gets interrupted i close the device that has been opened with pcap_close and end the program.  
Then the main sniffer part begins. I described this part in the **What is a packet sniffer - how do they work**


## Usage/Examples and Testing
### testing interface print
```
stepan@stepan-Lenovo-Legion-5-15ARH05H:~/Documents/c++/ipk/proj2git/IPK_proj2$ ./ipk-sniffer -i
0: wlp4s0
1: any
2: lo
3: eno1
4: bluetooth0
5: bluetooth-monitor
6: nflog
7: nfqueue
8: dbus-system
9: dbus-session
```
###
```
stepan@stepan-Lenovo-Legion-5-15ARH05H:~/Documents/c++/ipk/proj2git/IPK_proj2$ sudo ./ipk-sniffer -i wlp4s0 -n 1
[sudo] password for stepan: 
timestamp: 2023-04-17T20:48:43.455Z 
src MAC: 54:BF:64:52:82:91
dst MAC: FF:FF:FF:FF:FF:FF
frame length: 60
src IP: 10.0.0.148
src IP: 10.0.0.138

0x0000 ff ff ff ff ff ff 54 bf 64 52 82 91 08 06 00 01  ......T.dR......
0x0010 08 00 06 04 00 01 54 bf 64 52 82 91 0a 00 00 94  ......T.dR......
0x0020 00 00 00 00 00 00 0a 00 00 8a 00 00 00 00 00 00  ................
0x0030 00 00 00 00 00 00 00 00 00 00 00 00              ............
```
```
stepan@stepan-Lenovo-Legion-5-15ARH05H:~/Documents/c++/ipk/proj2git/IPK_proj2$ sudo ./ipk-sniffer -i wlp4s0 --tcp
timestamp: 2023-04-17T20:50:41.991Z 
src MAC: 70:9C:D1:F5:96:FF
dst MAC: 20:E8:82:FD:40:20
frame length: 66
src IP: 10.0.0.10
dst IP: 142.250.27.188

src port: 46110

dst port: 5228

0x0000 20 e8 82 fd 40 20 70 9c d1 f5 96 ff 08 00 45 00   ...@ p.......E.
0x0010 00 34 2a 50 40 00 40 06 5b b4 0a 00 00 0a 8e fa  .4*P@.@.[.......
0x0020 1b bc b4 1e 14 6c 5f a6 79 bb a9 df 3c 5f 80 10  .....l_.y...<_..
0x0030 01 f5 b4 e6 00 00 01 01 08 0a aa c5 1f 87 61 d7  ..............a.
0x0040 ae f0                                            ..

```
```
stepan@stepan-Lenovo-Legion-5-15ARH05H:~/Documents/c++/ipk/proj2git/IPK_proj2$ sudo ./ipk-sniffer -i wlp4s0 --arp --udp -n 2
timestamp: 2023-04-17T21:04:42.603Z 
src MAC: 20:E8:82:FD:40:20
dst MAC: 70:9C:D1:F5:96:FF
frame length: 42
src IP: 10.0.0.138
src IP: 10.0.0.10

0x0000 70 9c d1 f5 96 ff 20 e8 82 fd 40 20 08 06 00 01  p..... ...@ ....
0x0010 08 00 06 04 00 01 20 e8 82 fd 40 20 0a 00 00 8a  ...... ...@ ....
0x0020 00 00 00 00 00 00 0a 00 00 0a                    ..........

timestamp: 2023-04-17T21:04:42.603Z 
src MAC: 70:9C:D1:F5:96:FF
dst MAC: 20:E8:82:FD:40:20
frame length: 42
src IP: 10.0.0.10
src IP: 10.0.0.138

0x0000 20 e8 82 fd 40 20 70 9c d1 f5 96 ff 08 06 00 01   ...@ p.........
0x0010 08 00 06 04 00 02 70 9c d1 f5 96 ff 0a 00 00 0a  ......p.........
0x0020 20 e8 82 fd 40 20 0a 00 00 8a                     ...@ ....
![Picture 2](/img/1.png "arp packet wireshark")
![Picture 3](/img/arp.png "arp packet wireshark")

```

## Bibliographie/sources
- the definitons of TCP and UDP are stubs from my IPK project number 1
- [link] https://www.winpcap.org/docs/docs_412/html/funcs_2pcap_8h.html
- [link] https://www.imperva.com/learn/application-security/osi-model/
