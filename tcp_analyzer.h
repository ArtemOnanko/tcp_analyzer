#ifndef TCP_ANALYZER_H
#define TCP_ANALYZER_H 1

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h> // for pow()
#include "helpers.h"

typedef struct list_pair
{
	syn_packet_t *syn_list;
	failed_connection_t *fail_list;
} list_pair_t;

typedef struct
{
	char *dev_name;
} thread_args_t;

#endif
