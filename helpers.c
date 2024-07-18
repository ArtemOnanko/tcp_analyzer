#include "tcp_analyzer.h"
#include "helpers.h"

// syn_packet_t *syn_list = NULL;
// failed_connection_t *fail_list = NULL;

const int SYN_TIMEOUT = 64;

// Default Kernel settings for Debian: 1 1 1 1 1 2 4 8 16 32 64 (131 seconds)
const uint16_t tcp_syn_linear_timeouts = 4;
const uint16_t tcp_syn_retries = 6;

uint16_t expected_syn_delay(uint16_t retry_count)
{
	uint16_t res;
	// Consider 1 second delay for linear_timeouts SYN retries (+1 second for robustness)
	if (retry_count < tcp_syn_linear_timeouts)
	{
		//	printf ("Count is %d, expected delay is 2 second\n", retry_count);
		return 2;
	}
	// Consider 2^n seconds delay for later SYN retries (+1 second for robustness)
	else if (retry_count <= tcp_syn_linear_timeouts + tcp_syn_retries)
	{
		res = pow(2, retry_count - tcp_syn_linear_timeouts) + 1;
		//	printf ("Count is %d, expected delay is %d second\n", retry_count, res);
		return res;
	}
	// Set delay to 1 second to trigger the "Connection timed out" situation (> 131 seconds)
	else
		return 1;
}

void print_success(struct in_addr ip_src, struct in_addr ip_dst, uint16_t source, uint16_t dest)
{
	char printable_srcip[INET_ADDRSTRLEN];
	char printable_dstip[INET_ADDRSTRLEN];
	strcpy(printable_srcip, inet_ntoa(ip_src));
	strcpy(printable_dstip, inet_ntoa(ip_dst));
	printf("SUCCESS %s:%d -> %s:%d\n",
		   printable_srcip,
		   ntohs(source),
		   printable_dstip,
		   ntohs(dest));
}

void print_failure(struct in_addr ip_src, struct in_addr ip_dst, uint16_t source, uint16_t dest, uint16_t fail_count)
{
	char printable_srcip[INET_ADDRSTRLEN];
	char printable_dstip[INET_ADDRSTRLEN];
	strcpy(printable_srcip, inet_ntoa(ip_src));
	strcpy(printable_dstip, inet_ntoa(ip_dst));
	printf("FAILED %s:%d -> %s:%d (%d times)\n",
		   printable_srcip,
		   ntohs(source),
		   printable_dstip,
		   ntohs(dest),
		   fail_count);
}

uint16_t add_failed_connection(struct in_addr src_ip, struct in_addr dst_ip, uint16_t dst_port, failed_connection_t **fail_list)
{
	//	char printable_srcip[INET_ADDRSTRLEN];
	//    	char printable_dstip[INET_ADDRSTRLEN];
	//    	strcpy(printable_srcip, inet_ntoa(src_ip));
	//   	strcpy(printable_dstip, inet_ntoa(dst_ip));

	failed_connection_t **current = fail_list;
	while (*current)
	{
		failed_connection_t *entry = *current;
		// Increment count in a stored failed_connection entry
		if (entry->src_ip.s_addr == src_ip.s_addr && entry->dst_ip.s_addr == dst_ip.s_addr &&
			entry->dst_port == dst_port)
		{
			entry->fail_count++;
			//		printf("Increment count to %d in failed_connection entry:%s -> %s:%d.\n",
			//				entry->fail_count, printable_srcip,
			//				printable_srcip,
			//				ntohs(dst_port));
			return entry->fail_count;
		}
		current = &entry->next;
	}
	// Add new failed_connection entry
	failed_connection_t *new_failed_connection = (failed_connection_t *)malloc(sizeof(failed_connection_t));
	new_failed_connection->src_ip = src_ip;
	new_failed_connection->dst_ip = dst_ip;
	new_failed_connection->dst_port = dst_port;
	new_failed_connection->fail_count = 1;
	new_failed_connection->next = *fail_list;
	*fail_list = new_failed_connection;
	//	printf("Add failed_connection entry to the fail_list:%s -> %s:%d.\n",
	//			printable_srcip,
	//			printable_dstip,
	//			ntohs(dst_port));
	return 1; // new_failed_connection->fail_count = 1
}

void add_syn_packet(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port, syn_packet_t **syn_list)
{
	//	char printable_srcip[INET_ADDRSTRLEN];
	//    	char printable_dstip[INET_ADDRSTRLEN];
	//    	strcpy(printable_srcip, inet_ntoa(src_ip));
	//   	strcpy(printable_dstip, inet_ntoa(dst_ip));

	syn_packet_t **current = syn_list;
	while (*current)
	{
		syn_packet_t *entry = *current;
		// Increment retry_count in syn_packet if match exacly (clients try several retransmissions case)
		if (entry->src_ip.s_addr == src_ip.s_addr && entry->dst_ip.s_addr == dst_ip.s_addr &&
			entry->src_port == src_port && entry->dst_port == dst_port)
		{
			entry->retry_count++;
			entry->timestamp = time(NULL);
			//		printf("Update time and Increment retry_count to %d in SYN packet:%s:%d -> %s:%d.\n",
			//				entry->retry_count,
			//				printable_srcip,
			//				ntohs(src_port),
			//				printable_dstip,
			//				ntohs(dst_port));
			return;
		}
		current = &entry->next;
	}
	syn_packet_t *new_packet = (syn_packet_t *)malloc(sizeof(syn_packet_t));
	new_packet->src_ip = src_ip;
	new_packet->dst_ip = dst_ip;
	new_packet->src_port = src_port;
	new_packet->dst_port = dst_port;
	new_packet->retry_count = 0;
	new_packet->timestamp = time(NULL);
	new_packet->next = *syn_list;
	*syn_list = new_packet;
	//	printf("Add SYN packet:%s:%d -> %s:%d.\n",
	//			printable_srcip,
	//			ntohs(src_port),
	//			printable_dstip,
	//			ntohs(dst_port));
}

void remove_syn_packet(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port, syn_packet_t **syn_list)
{
	char printable_srcip[INET_ADDRSTRLEN];
	char printable_dstip[INET_ADDRSTRLEN];
	strcpy(printable_srcip, inet_ntoa(src_ip));
	strcpy(printable_dstip, inet_ntoa(dst_ip));

	syn_packet_t **current = syn_list;
	while (*current)
	{
		syn_packet_t *entry = *current;
		if (entry->src_ip.s_addr == src_ip.s_addr && entry->dst_ip.s_addr == dst_ip.s_addr &&
			entry->src_port == src_port && entry->dst_port == dst_port)
		{
			*current = entry->next;
			//  printf("Remove SYN packet:%s:%d -> %s:%d.\n", printable_srcip, ntohs(src_port), printable_dstip, ntohs(dst_port));
			free(entry);
			return;
		}
		current = &entry->next;
	}
}

void check_syn_timeouts(syn_packet_t **syn_list, failed_connection_t **fail_list)
{
	time_t now = time(NULL);
	syn_packet_t **current = syn_list;
	while (*current)
	{
		syn_packet_t *entry = *current;
		// Works fine with standard linux clients
		if (now - entry->timestamp > expected_syn_delay(entry->retry_count))
		// Const SYN_TIMEOUT is more reliable but less intercative way
		// if (now - entry->timestamp > SYN_TIMEOUT )
		{
			//	printf("Passed time %ld > Expected Delay %d, SYN packet to %s:%d timed out.\n", (now - entry->timestamp), SYN_TIMEOUT, inet_ntoa(entry->dst_ip), ntohs(entry->dst_port));
			print_failure(entry->src_ip, entry->dst_ip, entry->src_port, entry->dst_port, add_failed_connection(entry->src_ip, entry->dst_ip, entry->dst_port, fail_list));
			*current = entry->next;
			free(entry);
		}
		else
			current = &entry->next;
	}
}

int get_len_syn_list(syn_packet_t **syn_list)
{
	int len = 0;
	syn_packet_t **current = syn_list;
	while (*current)
	{
		syn_packet_t *entry = *current;
		len++;
		current = &entry->next;
	}
	return len;
}

int get_len_fail_list(failed_connection_t **fail_list)
{
	int len = 0;
	failed_connection_t **current = fail_list;
	while (*current)
	{
		failed_connection_t *entry = *current;
		len++;
		current = &entry->next;
	}
	return len;
}
