
# Changelog

- The program is a filter implementation of a packet sniffer written in c++ standard 20.
- I first implemented the basic structure and defined my c++ packetSniffer class.
- After that I defined the methods of the class.
- In the main function of the code I first create the sniffer obect and then it carries on to the main part.
- The program also checks for SIGINT/C-c all the time and ends the program gracefully by using pcap_close
- The code was tested multiple times on the virtual machine given with the task and locally on my network
- I cross refferenced the packets I found with wireshark to make sure they are sniffed correctly
- I wasn't able to find any problems or errors while running the code
- I programmed the code locally and on github before I read that it should be done one the school git so the school git isn't in a very nice state
