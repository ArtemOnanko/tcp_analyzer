#include "tcp_analyzer.h"
#include "packet_handler.h"

void *capture_packets(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    const char *filter_exp = "tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) != 0";
    list_pair_t list_pair = {.syn_list = NULL, .fail_list = NULL}; // syn_list and fail_list pair

    // Open the device
    //printf("Opening device %s\n" ,args->dev_name);
    handle = pcap_open_live(args->dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", args->dev_name, errbuf);
        free(args);
        pthread_exit(NULL);
    }

    // Compile and set the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        free(args);
        pthread_exit(NULL);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        free(args);
        pthread_exit(NULL);
    }

    // pass struct list_pair* to packet_handle
    pcap_loop(handle, 0, packet_handler, (unsigned char *)&list_pair);
    pcap_close(handle);
    free(args);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    pthread_t thread_id;
    int opt;
    int all_interfaces = 0;

    // Command line options
    while ((opt = getopt(argc, argv, "i:a")) != -1)
    {
        switch (opt)
        {
        case 'i':
            // Single interface mode
            alldevs = malloc(sizeof(pcap_if_t));
            alldevs->name = optarg;
            alldevs->flags = PCAP_IF_UP;
            alldevs->next = NULL;
            break;
        case 'a':
            // All interfaces mode
            all_interfaces = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -i <interface> | -a\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (all_interfaces)
    {
        // Find all interfaces
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else if (alldevs == NULL)
    {
        fprintf(stderr, "Interface not specified. Use -i <interface> or -a for all interfaces\n");
        exit(EXIT_FAILURE);
    }

    // Create a thread for each device
    for (d = alldevs; d != NULL; d = d->next)
    {
        // Working only with active physical NICs (and loopback)
        // if(d->flags & PCAP_IF_UP && !(d->flags & PCAP_IF_LOOPBACK) && strcmp(d->name, "any"))
        if (d->flags & PCAP_IF_UP && strcmp(d->name, "any"))
        {
            thread_args_t *args = malloc(sizeof(thread_args_t));
            args->dev_name = d->name;
            if (pthread_create(&thread_id, NULL, capture_packets, (void *)args) != 0)
            {
                fprintf(stderr, "Error creating thread for device %s\n", d->name);
                free(args);
            }
        }
    }

    // Waite here indefinitely  instead of joining
    for (;;)
        pause();

    if (all_interfaces)
    {
        pcap_freealldevs(alldevs);
    }
    pthread_exit(NULL);
    exit(EXIT_SUCCESS);
}
