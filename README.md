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

###

## Bibliographie/sources
- https://www.winpcap.org/docs/docs_412/html/funcs_2pcap_8h.html
