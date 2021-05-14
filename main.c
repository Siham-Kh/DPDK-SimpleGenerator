/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250 // what's this?
#define BUF_SIZE 2048
#define BURST_SIZE 10
#define N_RX_Q 3		// hardcode number of rx and tx queues for now
#define N_TX_Q 3
#define RX_RING_SIZE 1024 // descriptors include ring size? TX_RING_SIZE = 1024? how to choose queue size?
#define TX_RING_SIZE 1024

#define MODE_CLIENT 1 // Force this to be a client (can be applied from app_argument())

#define TX_PACKET_LENGTH 862
#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define UDP_SRC_PORT 6666
#define UDP_DST_PORT 6666

#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define RTE_BE_TO_CPU_16(be_16_v)  (be_16_v)
#define RTE_CPU_TO_BE_16(cpu_16_v) (cpu_16_v)
#else
#define RTE_BE_TO_CPU_16(be_16_v) \
        (uint16_t) ((((be_16_v) & 0xFF) << 8) | ((be_16_v) >> 8))
#define RTE_CPU_TO_BE_16(cpu_16_v) \
        (uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8))
#endif


#define TIMER_RESOLUTION_CYCLES 20000000ULL /* around 10ms at 2 Ghz */
static struct rte_timer timer0;

// Values to pass in cmd
uint32_t IP_SRC_ADDR = 0xa0a1402; // Hardcode src addr
uint32_t IP_DST_ADDR = 0xa0a1401; // Hardcode dst addr
// DST MAC address of NIC 
struct rte_ether_addr dst_eth_addr = {
	.addr_bytes = {0xec, 0x0d, 0x9a, 0x9b, 0xc4, 0x32 }
}; 

uint16_t count = 0;
uint16_t burstId = 0;

/* port configuration by default*/
static const struct rte_eth_conf port_conf_default = { 		// edit all default configuration here prior to assigning it to port. WTB offloads?
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

static unsigned int get_queue_lcore(){
	unsigned int lcore_id = rte_lcore_id();

	switch (lcore_id){
		case 1:
			return 0;
		case 2: 
			return 1;
		case 3:
			return 2;
		default:
			rte_exit(EXIT_FAILURE, "Error with Queue mapping to lcore \n");
	}
}

static void process_received_packet(struct rte_mbuf *m){
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct rte_ether_addr src = eth_hdr->s_addr;
	struct rte_ether_addr dst = eth_hdr->d_addr;

	printf("**** from MAC : %02X:%02X:%02X:%02X:%02X:%02X \n", src.addr_bytes[0],src.addr_bytes[1],src.addr_bytes[2],src.addr_bytes[3],src.addr_bytes[4],src.addr_bytes[5]);
	printf("**** to MAC: %02X:%02X:%02X:%02X:%02X:%02X \n", dst.addr_bytes[0],dst.addr_bytes[1],dst.addr_bytes[2],dst.addr_bytes[3],dst.addr_bytes[4],dst.addr_bytes[5]);

	// Extract data from frame
	// rte_pktmbuf_adj(bufs[i], (uint16_t)sizeof(struct ether_hdr));
	// printf(("**** Data received: %s\n",); 
}

static void construct_headers(uint8_t port, struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr, struct rte_ether_hdr *eth_hdr)
{
	uint16_t pkt_data_len = (uint16_t) (TX_PACKET_LENGTH - (sizeof(struct rte_ether_hdr) +
                                                    sizeof(struct rte_ipv4_hdr) +
                                                    sizeof(struct rte_udp_hdr)));

	
	
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* Construct heders for packet */
	struct rte_ether_addr my_addr; // SRC MAC address of NIC 	
	int retval = rte_eth_macaddr_get(port, &my_addr);
    if (retval != 0)
        return retval;

	rte_ether_addr_copy(&my_addr, &eth_hdr->s_addr); // Set local MAC
	rte_ether_addr_copy(&dst_eth_addr,&eth_hdr->d_addr);

	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	//Initialize UDP header.
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
	udp_hdr->dst_port = rte_cpu_to_be_16(UDP_DST_PORT);
	udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_len);
	udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

	//Initialize IP header.
	pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->version_ihl   = IP_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = RTE_CPU_TO_BE_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(IP_SRC_ADDR);
	ip_hdr->dst_addr = rte_cpu_to_be_32(IP_DST_ADDR);

 	//Compute IP header checksum.
	ptr16 = (unaligned_uint16_t*) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	//Reduce 32 bit checksum to 16 bits and complement it.
        ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
                (ip_cksum & 0x0000FFFF);
        if (ip_cksum > 65535)
                ip_cksum -= 65535;
        ip_cksum = (~ip_cksum) & 0x0000FFFF;
        if (ip_cksum == 0)
                ip_cksum = 0xFFFF;
        ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}


send_packet(uint8_t port, struct rte_mempool *mbuf_pool, uint8_t n){

	struct rte_mbuf *pkt;
	struct rte_mbuf *pkts_burst[1];
	pkt = rte_mbuf_raw_alloc(mbuf_pool);
	if(pkt == NULL) {printf("truoble at rte_mbuf_raw_alloc\n"); return;}
	rte_pktmbuf_reset_headroom(pkt);
	pkt->data_len = TX_PACKET_LENGTH;
	
	struct rte_ether_hdr eth_hdr;	/**< ETH header of packets to transmit. */
	static struct rte_ipv4_hdr pkt_ip_hdr;  /**< IP header of packets to transmit. */
	static struct rte_udp_hdr pkt_udp_hdr; /**< UDP header of packets to transmit. */
	construct_headers(port, &pkt_ip_hdr, &pkt_udp_hdr, &eth_hdr);

	// char* message = (char*)rte_pktmbuf_prepend(m, sizeof(*message));  // empty packe for now
	// message = "hello";

	// copy header to packet in mbuf
	rte_memcpy(rte_pktmbuf_mtod_offset(pkt,char *,0), &eth_hdr,(size_t)sizeof(eth_hdr));
	rte_memcpy(rte_pktmbuf_mtod_offset(pkt,char *,sizeof(struct rte_ether_hdr)), &pkt_ip_hdr,(size_t)sizeof(pkt_ip_hdr));
	rte_memcpy(rte_pktmbuf_mtod_offset(pkt,char *, sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr)), &pkt_udp_hdr,(size_t)sizeof(pkt_udp_hdr));
	
	// Add some pkt fields
	pkt->nb_segs = 1;
	pkt->pkt_len = pkt->data_len;
	pkt->ol_flags = 0;

	// Actually send the packet
	pkts_burst[0] = pkt;
	unsigned int QueueId = get_queue_lcore();
	const uint16_t nb_tx = rte_eth_tx_burst(port, QueueId, pkts_burst, 1);
	count++;
	rte_mbuf_raw_free(pkt);
}


static __rte_noreturn void
lcore_sender(struct rte_mempool *mbuf_pool){

	const uint8_t nb_ports = rte_eth_dev_count_avail();  // All lcores send to all ports ( we can pin a specific queue/port for each lcore
	uint8_t port;
	
	for (;;) {

		for (port = 0; port < nb_ports; port++) {
			burstId ++;
			printf(">> sending burst %d %d\n", burstId);
			send_packet(port, mbuf_pool, BURST_SIZE);
		}
	}
}


static __rte_noreturn void
lcore_receieve()
{	
	unsigned int lcore_id = rte_lcore_id();
	const uint8_t nb_ports = rte_eth_dev_count_avail();  // All lcores send to all ports ( we can pin a specific queue/port for each lcore
	uint8_t port;
	
    /* Run until the application is quit or killed. */

	for (;;) {

		for (port = 0; port < nb_ports; port++) {  
			
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[1];
			unsigned int QueueId = get_queue_lcore();
			const uint16_t nb_rx = rte_eth_rx_burst(port, QueueId, bufs, BURST_SIZE);  // Pin rx queue per lcore per port in the future, here we assume we have just one

			if (unlikely(nb_rx == 0))
				continue;

			burstId ++;
			count = count + nb_rx;
			printf("new  burst from queue 0 so far = %d\n", count);
	
			for (int i = 0; i < nb_rx; i++){

				printf("> process packet %d from burst $d\n", i+1, burstId);
				process_received_packet(bufs[i]);
				rte_pktmbuf_free(bufs[i]);
				
				// printf(">>>>>>>>>>> send packet %d from burst %d\n", i+1, burstId);
				// send_packet(port, mbuf_pool);
			}
		}
	}
}



static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)

{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = N_RX_Q, tx_rings = N_TX_Q;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }
	/* Check if a hardware offload is supported on this device */
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)		// Get supported dev configuration (including offloads) with rte_eth_dev_info_get and apply the ones u like to port with rte_eth_dev_configure
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);  // start with 1 rx and 1 tx
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);  // descriptors include ring size? TX_RING_SIZE = 1024? how to choose queue size?
    if (retval != 0)
        return retval;
	
	/* Get Numa node used for this NIC */
	unsigned int numa = rte_eth_dev_socket_id(port);

    /* Allocate and set up #RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool); // this is the choice of numa node. How to pick? 
        if (retval < 0)
            return retval;
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;
    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;
    return 0;
}


static int
lcore_hello(__rte_unused void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("hello from core %u\n", lcore_id);
	return 0;
}

/* timer0 callback */
static void
timer0_cb(__rte_unused struct rte_timer *tim,
	  __rte_unused void *arg)
{
	static unsigned counter = 0;
	unsigned lcore_id = rte_lcore_id();

	printf("<><><><>%s() After 1s:  %u\n", __func__, count);
	count = 0;
	// printf(">>>>>>>>>>> sending burst %d %d\n", burstId);
	
	
	/* this timer is automatically reloaded until we decide to
	 * stop it, when counter reaches 100 exectuations */
	if ((counter ++) == 100)
		rte_timer_stop(tim);
}

static __rte_noreturn int
lcore_mainloop_timer(__rte_unused void *arg)
{
	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
	unsigned lcore_id;

	lcore_id = rte_lcore_id();
	printf("Starting mainloop on core %u\n", lcore_id);

	while (1) {
		/*
		 * Call the timer handler on each core: as we don't
		 * need a very precise timer, so only call
		 * rte_timer_manage() every ~10ms (at 2Ghz). In a real
		 * application, this will enhance performances as
		 * reading the HPET timer is not efficient.
		 */
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
}


// /* Parse the argument given in the command line of the application */
// static int parse_app_args(int argc, char **argv){
// 	int opt;
// 	char **argvopt;
// 	int option_index;
// 	char *prgname = argv[0];

// 	argvopt = argv;
// 	port_pair_params = NULL;

// 	while ((opt = getopt_long(argc, argvopt, short_options,
// 				  lgopts, &option_index)) != EOF) {

// 		switch (opt) {
// 		/* portmask */
// 		case 'p':
// 			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
// 			if (l2fwd_enabled_port_mask == 0) {
// 				printf("invalid portmask\n");
// 				l2fwd_usage(prgname);
// 				return -1;
// 			}
// 			break;

// 		/* nqueue */
// 		case 'q':
// 			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
// 			if (l2fwd_rx_queue_per_lcore == 0) {
// 				printf("invalid queue number\n");
// 				l2fwd_usage(prgname);
// 				return -1;
// 			}
// 			break;

// 		/* timer period */
// 		case 'T':
// 			timer_secs = l2fwd_parse_timer_period(optarg);
// 			if (timer_secs < 0) {
// 				printf("invalid timer period\n");
// 				l2fwd_usage(prgname);
// 				return -1;
// 			}
// 			timer_period = timer_secs;
// 			break;

// 		/* long options */
// 		case CMD_LINE_OPT_PORTMAP_NUM:
// 			ret = l2fwd_parse_port_pair_config(optarg);
// 			if (ret) {
// 				fprintf(stderr, "Invalid config\n");
// 				l2fwd_usage(prgname);
// 				return -1;
// 			}
// 			break;

// 		default:
// 			l2fwd_usage(prgname);
// 			return -1;
// 		}
// 	}

// 	if (optind >= 0)
// 		argv[optind-1] = prgname;

// 	ret = optind-1;
// 	optind = 1; /* reset getopt lib */
// 	return ret;
// }


int
main(int argc, char **argv)
{
	struct rte_mempool *mbuf_pool, *send_pool;
    unsigned nb_ports;
    uint16_t portid;
    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;
	
    // initialize App arguments if any
    // retA = parse_app_args(argc, argv);
    // if (retA != 0) {
    //     rte_exit(EXIT_FAILURE, "Error with APP arguments\n");
    // }

	/* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: no ports available\n");
    
	unsigned int lcore_id = rte_socket_id();
	
	/* Creates a new mempool in memory to hold the received mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");


	/* Creates a new mempool in memory to hold the send mbufs. */
 	send_pool = rte_pktmbuf_pool_create("SEND_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, BUF_SIZE, rte_socket_id());
    if (send_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	
	/* Initialize all ports. */
    RTE_ETH_FOREACH_DEV(portid)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);


	/* Check number of ports: note this can be done from app argument function too: not working though */
	if (rte_lcore_count() == 1)
        printf("\nWARNING: Only one core available.. No performance expected\n");
	

	// /* init RTE timer library */
	// rte_timer_subsystem_init();

	// /* init timer structures */
	// rte_timer_init(&timer0);

	// 	/* load timer0, every second, on main lcore, reloaded automatically */
	// 	uint64_t hz = rte_get_timer_hz();
	// 	rte_timer_reset(&timer0, hz, PERIODICAL, lcore_id, timer0_cb, NULL);

	/* App processing */
	if (MODE_CLIENT == 0) {

	   /* Call receiver */
		lcore_receieve(mbuf_pool);
    } else {

		/* Call sender */
		rte_eal_mp_remote_launch(lcore_sender, mbuf_pool, CALL_MAIN);	// use main core for stats printing (CALL_MAIN otherwise)
	}

	/* Start the timer on the main loop */
	// lcore_mainloop_timer(NULL);


	/* Wait for all cores to terminate */
	rte_eal_mp_wait_lcore();
	return 0;
}
