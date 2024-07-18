#ifndef HELPERS_H
#define HELPERS_H 1

typedef struct syn_packet
{
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    time_t timestamp;
    uint16_t retry_count;
    struct syn_packet *next;
} syn_packet_t;

typedef struct failed_connection
{
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t dst_port;
    uint16_t fail_count;
    struct failed_connection *next;
} failed_connection_t;

uint16_t expected_syn_delay(uint16_t retry_count);
uint16_t add_failed_connection(struct in_addr src_ip, struct in_addr dst_ip, uint16_t dst_port, failed_connection_t **fail_list);
void add_syn_packet(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port, syn_packet_t **syn_list);
void remove_syn_packet(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port, syn_packet_t **syn_list);
void check_syn_timeouts(syn_packet_t **syn_list, failed_connection_t **fail_list);
void print_success(struct in_addr ip_src, struct in_addr ip_dst, uint16_t source, uint16_t dest);
void print_failure(struct in_addr ip_src, struct in_addr ip_dst, uint16_t source, uint16_t dest, uint16_t fail_count);
int get_len_syn_list(syn_packet_t **syn_list);
int get_len_fail_list(failed_connection_t **fail_list);

#endif
