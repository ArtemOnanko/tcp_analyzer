#include "tcp_analyzer.h"
#include "packet_handler.h"
#include "helpers.h"

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    struct ip *ip_hdr = (struct ip *)(packet + 14); // Assuming Ethernet
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr->ip_hl * 4);
    
    // Fetch syn_list and fail_list wrapped in a list_pair_t 
    list_pair_t *lp = (list_pair_t *)user_data;

    if (tcp_hdr->syn && !tcp_hdr->ack)
    {
        add_syn_packet(ip_hdr->ip_src, ip_hdr->ip_dst, tcp_hdr->source, tcp_hdr->dest, &(lp->syn_list));
    }
    else if (tcp_hdr->syn && tcp_hdr->ack)
    {
	//remove after response
        remove_syn_packet(ip_hdr->ip_dst, ip_hdr->ip_src, tcp_hdr->dest, tcp_hdr->source, &(lp->syn_list));
	print_success(ip_hdr->ip_dst, ip_hdr->ip_src, tcp_hdr->dest, tcp_hdr->source);
    }
    else if (tcp_hdr->rst)
    {
	//remove after response
        remove_syn_packet(ip_hdr->ip_dst, ip_hdr->ip_src, tcp_hdr->dest, tcp_hdr->source, &(lp->syn_list));
	print_failure(ip_hdr->ip_dst, ip_hdr->ip_src, tcp_hdr->dest, tcp_hdr->source, add_failed_connection(ip_hdr->ip_dst, ip_hdr->ip_src, tcp_hdr->source, &(lp->fail_list)));
    }

    check_syn_timeouts(&(lp->syn_list), &(lp->fail_list));
   // printf("Syn list len = %d\n", get_len_syn_list(&(lp->syn_list)));
   // printf("Fail list len = %d\n", get_len_fail_list(&(lp->fail_list)));
}
