# tcp_analyzer
Simple multithreaded TCP connections analyzer. Linked lists are used to store SYN_packets and 
Failed_connetions. For each NIC a dedicated thread is used to run pcap_loop() indefinitely.
Could analyze TCP connections on a specific NIC or on all active interfaces. 

"Usage: sudo ./tcp_analyzer -i <interface> | -a" 

