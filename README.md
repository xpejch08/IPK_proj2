# IPK Project2 ZETA variant
Implementation of a packet sniffer in c++
##Authors

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
3. I then check if the device provides ethernet headers as specified in the task
4. I then check for a packet filter derived from the input arguments
5. Using the pcap_loop function I sniff for packets on the desired device
6. Then I close the device using pcap_close

### The protocols I use to sniff
#### The OSI model
The Open Systems Interconnection model is a model used for decribing network communication. It describes the network protocols and how communication works between different devices. It is described in 7 layers
![Picture 1](/img/OSI.png "OSI model")

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
#### icmp4
#### icmp6
#### arp
#### ndp
#### igmp
#### mld


## Bibliographie/sources
- the definitons of TCP and UDP are stubs from my IPK project number 1
- [link] https://www.winpcap.org/docs/docs_412/html/funcs_2pcap_8h.html
- [link] https://www.imperva.com/learn/application-security/osi-model/
