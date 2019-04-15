#define IPHDR_SIZE sizeof(struct ip)
#define ICMPHDR_SIZE sizeof(struct icmp)
#define TCPHDR_SIZE sizeof(struct tcphdr)
#define UDPHDR_SIZE sizeof(struct udphdr)
#define PLUGIN_SEND_LOCK           imbw_recursive_mutex_lock(&imbw_plugin_send_mutex)
#define PLUGIN_SEND_UNLOCK         imbw_recursive_mutex_unlock(&imbw_plugin_send_mutex)


extern pthread_mutex_t imbw_plugin_send_mutex;
extern char    *imbw_plugin_send_buf;
extern int      imbw_plugin_s;
extern imbw_sniff_struct imbw_sniff;
extern imbw_packet_struct imbw_packet;
extern unsigned long imbw_rx,
                imbw_tx;
