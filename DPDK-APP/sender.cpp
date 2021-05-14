// check later:  https://github.com/deeptir18/dpdk-netperf/blob/main/netperf.c

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define N_RX_Q 4
#define N_TX_Q 4



static const struct rte_eth_conf port_conf_default = { 		// edit all default configuration here prior to assigning it to port. WTB offloads?
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};
/* basicfwd.c: Basic DPDK skeleton forwarding example. */
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
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
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)		// Get supported dev configuration (including offloads) with rte_eth_dev_info_get and apply the ones u like to port with rte_eth_dev_configure
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);  // start with 1 rx and 1 tx
    if (retval != 0)
        return retval;	
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);  // descriptors include ring size? TX_RING_SIZE = 1024? how to choose queue size?
    if (retval != 0)
        return retval;
	
    /* Allocate and set up 1 RX queue per Ethernet port. */
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
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __rte_noreturn void
lcore_server(void)
{	
	unsigned int lcore_id = rte_lcore_id();
	const uint8_t nb_ports = rte_eth_dev_count();  // All lcores send to all ports ( we can pin a specific queue/port for each lcore
	uint8_t port;
	
    /* Run until the application is quit or killed. */

	for (;;) {

		for (port = 0; port < nb_ports; port++) {  
			
			/* Construct packets */
			struct rte_mbuf *bufs[BURST_SIZE];
			for (buf = nb_tx; buf < BURST_SIZE; buf++){
				
			}
		
			/* Send burst of TX packets, to second port of pair. */
			const uint16_t nb_tx = rte_eth_tx_burst(port, queueId, bufs, nb_rx);
			/* Free any unsent packets. */
			if (unlikely(nb_tx < BURST_SIZE)) {  // if what's sent is less than generated --> clean
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

static __rte_noreturn void
lcore_client(void)
{	
	unsigned int lcore_id = rte_lcore_id();
	const uint8_t nb_ports = rte_eth_dev_count();  // All lcores send to all ports ( we can pin a specific queue/port for each lcore
	uint8_t port;
	
    /* Run until the application is quit or killed. */

	for (;;) {

		for (port = 0; port < nb_ports; port++) {  
			
			/* Construct packets */
			printf("Sending packets ... [Press Ctrl+C to exit]\n");
			struct rte_mbuf *bufs[BURST_SIZE];
			for (buf = nb_tx; buf < BURST_SIZE; buf++){
				
			}
		
			/* Send burst of TX packets, to second port of pair. */
			const uint16_t nb_tx = rte_eth_tx_burst(port, queueId, bufs, nb_rx);
			/* Free any unsent packets. */
			if (unlikely(nb_tx < BURST_SIZE)) {  // if what's sent is less than generated --> clean
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

static int 
queue_perLcore(unsigned int lcore_id)	// IS this RSS? can I offload it instead? https://haryachyy.wordpress.com/2019/01/18/learning-dpdk-symmetric-rss/
{
	
}

static int parse_app_args(int argc, char *argv[]) 
{
	
}


/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;
	
    // initialize App arguments
    retA = parse_app_args(argc, argv);
    if (retA != 0) {
        return retA;
    }

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: no ports available\n");
    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    RTE_ETH_FOREACH_DEV(portid)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                    portid);



    if (rte_lcore_count() == 1)
        printf("\nWARNING: Only one core available.. No performance expected\n");
	
	if (mode == MODE_CLIENT) {
	   /* Call client on all available cores. */
		rte_eal_mp_remote_launch(lcore_client, NULL, CALL_MAIN);	// to skip the main core use SKIP_MAIN
    } else {
	   /* Call server on all available cores. */
		rte_eal_mp_remote_launch(lcore_server, NULL, CALL_MAIN);	// to skip the main core use SKIP_MAIN
    }

	/* Wait for all lcores to finish. */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    return 0;
}



