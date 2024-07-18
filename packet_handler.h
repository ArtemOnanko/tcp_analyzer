#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H 1


void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);


#endif
