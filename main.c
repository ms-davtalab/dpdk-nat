/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32


//add by leal
 
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"


#define HASH_ENTRIES 1024
#define MAX_NB_PORT 16

/*
 * Work-around of a compilation error with ICC on invocations of the
 * rte_be_to_cpu_16() function.
 */
#ifdef __GCC__
#define RTE_BE_TO_CPU_16(be_16_v)  rte_be_to_cpu_16((be_16_v))
#define RTE_CPU_TO_BE_16(cpu_16_v) rte_cpu_to_be_16((cpu_16_v))
#else
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define RTE_BE_TO_CPU_16(be_16_v)  (be_16_v)
#define RTE_CPU_TO_BE_16(cpu_16_v) (cpu_16_v)
#else
#define RTE_BE_TO_CPU_16(be_16_v) \
	(uint16_t) ((((be_16_v) & 0xFF) << 8) | ((be_16_v) >> 8))
#define RTE_CPU_TO_BE_16(cpu_16_v) \
	(uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8))
#endif
#endif /* __GCC__ */


struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
} __attribute__((__packed__));

struct ipv4_and_port {
    uint32_t ip;
    uint16_t port;
};

int sum_recive_pkts=0;
int sum_recive_tcp=0;
int sum_recive_udp=0;
int sum_recive_icmp=0;
int sum_recive_x=0;
//Global variable
int DEBUG=1;
int inside_port_num=0;
int outside_port_num=1;
struct rte_mbuf *pkts_to_send[MAX_NB_PORT][BURST_SIZE];
int num_pkts_to_send[MAX_NB_PORT];
typedef struct rte_hash lookup_struct_t;
static lookup_struct_t *ipv4_lookup_struct[2];
static lookup_struct_t *arp_lookup;

uint32_t public_ip[2];

struct ipv4_and_port inside_table[HASH_ENTRIES];
struct ipv4_and_port outside_table[HASH_ENTRIES];

struct ether_addr my_nic_mac[MAX_NB_PORT];
uint32_t my_nic_ip[MAX_NB_PORT];
struct ether_addr arp_cache[HASH_ENTRIES];

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif



//end add by leal

static unsigned nb_ports;


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN,
				.hw_ip_checksum = 1, },
};



/*
static int
check_my_nic_mac(struct ether_addr addr){
    int i,j,k;
    
    for(i=0; i<MAX_NB_PORT; i++){
        k=1;
        for(j=0; j<6; j++){
            if(addr.addr_bytes[j]!=my_nic_mac.addr_bytes[j]){
                k=0;
            }
        }
        if(k==1) // all bytes of my_nic_mac same as addr
            return 1;
    }
    return 0;
}
*/
static int
check_my_ip(uint32_t ip_addr){
    int i;
    /*if(DEBUG>0){
    	char *buf;
    	sprintf(buf, "%d.%d.%d.%d", (ip_addr >> 24) & 0xFF,
		(ip_addr >> 16) & 0xFF, (ip_addr >> 8) & 0xFF,
		ip_addr & 0xFF);
    	printf("MYIP: %s\n",buf);
    }*/
    for(i=0; i<MAX_NB_PORT; i++){
        if(ip_addr==my_nic_ip[i]){
        		if(DEBUG>0){
        			printf("%s\n", "MYIP> True");
        		}
                return 1;
        }  
    }
    if(DEBUG>0){
        printf("%s\n", "MYIP> False");
    }
    return 0;
}



/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	my_nic_mac[port]=addr;
	num_pkts_to_send[port]=0;
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	//rte_eth_promiscuous_enable(port);
	//rte_eth_add_rx_callback(port, 0, do_nat, NULL);

	return 0;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static  __attribute__((noreturn)) void
lcore_main(void)
{
	struct rte_mbuf *pkt;
	uint8_t port;
	uint8_t send_port;
    uint16_t eth_type;
    uint16_t arp_op;
	uint16_t arp_pro;
	uint32_t cksum;
	
	unsigned i;
    int ret;
    struct ipv4_5tuple myflow;
    
    struct ether_hdr *eth_h;
    struct ether_addr eth_addr;
    struct arp_hdr  *arp_h;
    struct ipv4_hdr *ipv4_h;
    struct icmp_hdr *icmp_h;
    uint32_t ip_addr;
    struct tcp_hdr *tcp_h;
    struct udp_hdr *udp_h;
    uint16_t temp_l4port;
            
    int l2_len;        
            
            
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0)){
			    usleep(1);
				continue;
			}
			
			sum_recive_pkts+=nb_rx;
			
			
			
			
			
			
			
			
			
			
			
			
    
	
	        for (i = 0; i < nb_rx; i++){
				
				pkt=bufs[i];
	
	            eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	            if(0 && DEBUG){
	                ether_addr_dump("  ETH:  src=", &eth_h->s_addr);
			        ether_addr_dump(" dst=", &eth_h->d_addr);
	            }
			
			    eth_type = RTE_BE_TO_CPU_16(eth_h->ether_type);
			    l2_len = sizeof(struct ether_hdr);

	            if(eth_type == ETHER_TYPE_ARP){
	                arp_h = (struct arp_hdr *) ((char *)eth_h + l2_len);
			        arp_op = RTE_BE_TO_CPU_16(arp_h->arp_op);
			        arp_pro = RTE_BE_TO_CPU_16(arp_h->arp_pro);
			        if (DEBUG > 0) {
				        printf("  ARP:  hrd=%d proto=0x%04x hln=%d "
				               "pln=%d op=%u (%s)\n",
				               RTE_BE_TO_CPU_16(arp_h->arp_hrd),
				               arp_pro, arp_h->arp_hln,
				               arp_h->arp_pln, arp_op,
				               arp_op_name(arp_op));
			        }
			        if ((RTE_BE_TO_CPU_16(arp_h->arp_hrd) !=
			             ARP_HRD_ETHER) ||
			            (arp_pro != ETHER_TYPE_IPv4) ||
			            (arp_h->arp_hln != 6) ||
			            (arp_h->arp_pln != 4)
			            ) {
				        rte_pktmbuf_free(pkt);
				        if (DEBUG > 0)
					        printf("\n");
				        continue;
			        }
			        if (DEBUG > 0) {
				        ether_addr_copy(&arp_h->arp_data.arp_sha, &eth_addr);
				        ether_addr_dump("        sha=", &eth_addr);
				        ip_addr = arp_h->arp_data.arp_sip;
				        ipv4_addr_dump(" sip=", ip_addr);
				        printf("\n");
				        ether_addr_copy(&arp_h->arp_data.arp_tha, &eth_addr);
				        ether_addr_dump("        tha=", &eth_addr);
				        ip_addr = arp_h->arp_data.arp_tip;
				        ipv4_addr_dump(" tip=", ip_addr);
				        printf("\n");
			        }
			        if (arp_op != ARP_OP_REQUEST) {
				        rte_pktmbuf_free(pkt);
				        continue;
			        }
			        if(check_my_ip(arp_h->arp_data.arp_tip)==1){
				        /*
				         * Build ARP reply.
				         */

				        /* Use source MAC address as destination MAC address. */
				        ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
				        /* Set source MAC address with MAC address of TX port */
				        ether_addr_copy(&my_nic_mac[port], &eth_h->s_addr);

				        arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
				        ether_addr_copy(&arp_h->arp_data.arp_tha, &eth_addr);
				        ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
				        ether_addr_copy(&eth_h->s_addr, &arp_h->arp_data.arp_sha);

				        /* Swap IP addresses in ARP payload */
				        ip_addr = arp_h->arp_data.arp_sip;
				        arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
				        arp_h->arp_data.arp_tip = ip_addr;
				        pkts_to_send[port][num_pkts_to_send[port]++] = pkt;
				        if (DEBUG > 0) {
				        	printf("%s\n", "Build ARP reply");
				        }
				        continue;
				    }
		        }
	                
	            
	            if(likely(eth_type==ETHER_TYPE_IPv4)){
	                ipv4_h = (struct ipv4_hdr *)(eth_h + 1);



	                /*Dynamic MAC<=>IP learning*/
	                ret = rte_hash_lookup(arp_lookup, (void *) &ipv4_h->src_addr);
	                if(ret<0){
	                	ret = rte_hash_add_key (arp_lookup,
                                        (void *) &ipv4_h->src_addr);
                        if (ret < 0) {
                                rte_exit(EXIT_FAILURE, "Unable to add entry Dynamic MAC<=>IP learning\n");
                        }
                        arp_cache[ret] = eth_h->s_addr;
	                	if(DEBUG>0){
	                		printf("ARP> Learned new MAC\n");
	                	}
	                }
	                else{
	                	if(DEBUG>0){
	                		printf("ARP> Detect learned MAC.@%d\n", ret);
	                		char chr_buf[16];
							ipv4_addr_to_dot(ipv4_h->src_addr, chr_buf);
	                		ether_addr_dump(chr_buf, &arp_cache[ret]);
	                	}
	                }


	                myflow.ip_src=ipv4_h->src_addr;
	                myflow.ip_dst=ipv4_h->dst_addr;
	                myflow.proto=ipv4_h->next_proto_id;
	                switch (ipv4_h->next_proto_id) {
	                    case 1://IPPROTO_ICMP:
	                    		sum_recive_icmp++;
	                            if(check_my_ip(ipv4_h->dst_addr)==1){ /*PING MY NIC*/
	                                /*
									 * Check if packet is a ICMP echo request.
									 */
									icmp_h = (struct icmp_hdr *) ((char *)ipv4_h +
												      sizeof(struct ipv4_hdr));
									if (! ((ipv4_h->next_proto_id == IPPROTO_ICMP) &&
									       (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST) &&
									       (icmp_h->icmp_code == 0))) {
										/*
										if(DEBUG>0){
						        			printf("%s\n", "  ICMP: Drop\n");
						        		}
										rte_pktmbuf_free(pkt);
										continue;
										*/
										myflow.port_dst = 0;
                                    	myflow.port_src = 0;
										break;
									}

									if (DEBUG > 0)
										printf("  ICMP: echo request seq id=%d\n",
										       rte_be_to_cpu_16(icmp_h->icmp_seq_nb));

									/*
									 * Prepare ICMP echo reply to be sent back.
									 * - switch ethernet source and destinations addresses,
									 * - use the request IP source address as the reply IP
									 *    destination address,
									 * - if the request IP destination address is a multicast
									 *   address:
									 *     - choose a reply IP source address different from the
									 *       request IP source address,
									 *     - re-compute the IP header checksum.
									 *   Otherwise:
									 *     - switch the request IP source and destination
									 *       addresses in the reply IP header,
									 *     - keep the IP header checksum unchanged.
									 * - set IP_ICMP_ECHO_REPLY in ICMP header.
									 * ICMP checksum is computed by assuming it is valid in the
									 * echo request and not verified.
									 */
									ether_addr_copy(&eth_h->s_addr, &eth_addr);
									ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
									ether_addr_copy(&eth_addr, &eth_h->d_addr);
									ip_addr = ipv4_h->src_addr;
									if (is_multicast_ipv4_addr(ipv4_h->dst_addr)) {
										uint32_t ip_src;

										ip_src = rte_be_to_cpu_32(ip_addr);
										if ((ip_src & 0x00000003) == 1)
											ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
										else
											ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
										ipv4_h->src_addr = rte_cpu_to_be_32(ip_src);
										ipv4_h->dst_addr = ip_addr;
										ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
									} else {
										ipv4_h->src_addr = ipv4_h->dst_addr;
										ipv4_h->dst_addr = ip_addr;
									}
									icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
									cksum = ~icmp_h->icmp_cksum & 0xffff;
									cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
									cksum += htons(IP_ICMP_ECHO_REPLY << 8);
									cksum = (cksum & 0xffff) + (cksum >> 16);
									cksum = (cksum & 0xffff) + (cksum >> 16);
									icmp_h->icmp_cksum = ~cksum;
									pkts_to_send[port][num_pkts_to_send[port]++] = pkt;
								
	                                /*XXX is it true?*/
	                                //rte_pktmbuf_free(pkt);
	                                continue;
	                            }
	                            else{
	                                myflow.port_dst = 0;
                                    myflow.port_src = 0;
                                }
	                            break;
                        case IPPROTO_TCP:
                        		sum_recive_tcp++;
                                tcp_h = (struct tcp_hdr *)((unsigned char *)ipv4_h +
                                                        sizeof(struct ipv4_hdr));

                                myflow.port_dst = tcp_h->dst_port;
                                myflow.port_src = tcp_h->src_port;
                                break;
                        case IPPROTO_UDP:
                        		sum_recive_udp++;
                                udp_h = (struct udp_hdr *)((unsigned char *)ipv4_h +
                                                        sizeof(struct ipv4_hdr));
                                myflow.port_dst = udp_h->dst_port;
                                myflow.port_src = udp_h->src_port;
                                break;
                        default:
                        		sum_recive_x++;
                                myflow.port_dst = 0;
                                myflow.port_src = 0;
                                break;
                    }
	                if(DEBUG){
	                	char ip_src_buf[16];
						char ip_dst_buf[16];
						ipv4_addr_to_dot(myflow.ip_src, ip_src_buf);
						ipv4_addr_to_dot(myflow.ip_dst, ip_dst_buf);

	                    printf("FLOW> sIP:%s, dIP:%s, sPort:%d, dPort:%d, proto:%s\n", ip_src_buf, ip_dst_buf, rte_cpu_to_be_16(myflow.port_src), rte_cpu_to_be_16(myflow.port_dst), ip_proto_name(myflow.proto));
	                }
	                
	                /*Checking for flow*/
	                
                	if(port==outside_port_num){
                		ret = rte_hash_lookup(ipv4_lookup_struct[outside_port_num], (const void *)&myflow);
		                if(ret<0){
	                		if(DEBUG){
	                			rte_pktmbuf_free(pkt);
	                            printf("DROP>Can't find init flow(recive flow from outside).\n");
	                        }
	                    }
	                    else{ //UNDO NAT
	                    	
	                    	ipv4_h->hdr_checksum = 0;
	                    	ipv4_h->dst_addr = outside_table[ret].ip;
	                    	switch (ipv4_h->next_proto_id) {
	                        	case IPPROTO_TCP:
	                                tcp_h->cksum = 0;
	                                tcp_h->cksum = rte_ipv4_udptcp_cksum(ipv4_h, tcp_h);
	                                break;
	                        	case IPPROTO_UDP:
	                        		udp_h->dgram_cksum = 0;
	                                udp_h->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_h, udp_h);
	                                break;
	                        }
	                    	
	                    	ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
	                    	if(DEBUG){
	                			rte_pktmbuf_free(pkt);
	                            printf("NAT>UNDO.%d\n", outside_table[ret].ip);
	                        }
	                    }
                	}
                	else{
                		ret = rte_hash_lookup(ipv4_lookup_struct[inside_port_num], (const void *)&myflow);
                		if(ret<0){
	                		ret = rte_hash_add_key (ipv4_lookup_struct[inside_port_num],
	                                    (void *) &myflow);
	                        if (ret < 0) {
	                                rte_exit(EXIT_FAILURE, "Unable to add entry (inside)\n");
	                        }
	                        inside_table[ret].ip = public_ip[0];
	                        inside_table[ret].port = myflow.port_src;
	                        if(DEBUG){
	                            printf("FLOW>New flow add to inside db.@%d\n",ret);
	                        }


	                        myflow.ip_src = ipv4_h->dst_addr;
	                		myflow.ip_dst = public_ip[0];
	                		/*swap src_port and dst_port*/
	                		temp_l4port = myflow.port_dst;
	                		myflow.port_dst = myflow.port_src;
                            myflow.port_src = temp_l4port;

	                        ret = rte_hash_add_key (ipv4_lookup_struct[outside_port_num],
	                                    (void *) &myflow);
	                        if (ret < 0) {
	                                rte_exit(EXIT_FAILURE, "Unable to add entry (outside)\n");
	                        }
	                        outside_table[ret].ip = ipv4_h->src_addr;
	                        outside_table[ret].port = myflow.port_src;

	                        ipv4_h->hdr_checksum = 0;
	                        ipv4_h->src_addr = public_ip[0];
	                        switch (ipv4_h->next_proto_id) {
	                        	case IPPROTO_TCP:
	                                tcp_h->cksum = 0;
	                                tcp_h->cksum = rte_ipv4_udptcp_cksum(ipv4_h, tcp_h);
	                                break;
	                        	case IPPROTO_UDP:
	                        		udp_h->dgram_cksum = 0;
	                                udp_h->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_h, udp_h);
	                                break;
	                        }
	                        ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
	                        if(DEBUG){
	                            printf("NAT>First do\n");
	                        }
	                    }
	                    else{//DO NAT
	                    	ipv4_h->hdr_checksum = 0;
	                        ipv4_h->src_addr = inside_table[ret].ip;
	                        switch (ipv4_h->next_proto_id) {
	                        	case IPPROTO_TCP:
	                                tcp_h->cksum = 0;
	                                tcp_h->cksum = rte_ipv4_udptcp_cksum(ipv4_h, tcp_h);
	                                break;
	                        	case IPPROTO_UDP:
	                        		udp_h->dgram_cksum = 0;
	                                udp_h->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_h, udp_h);
	                                break;
	                        }
	                        ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
		                    if(DEBUG){
	                            printf("NAT>Do\n");
	                        }
		                }
                	}
	                    
	                
	                
	                /*TODO: Must be sent to LPM*/
	                ret = rte_hash_lookup(arp_lookup, (void *) &ipv4_h->dst_addr);
	                if(ret<0){
	                	rte_pktmbuf_free(pkt);
	                	if(DEBUG){
                            printf("DROP>Can't find MAC address.\n");
                        }
	                }
	                else{
	                	ether_addr_copy(&arp_cache[ret],&eth_h->d_addr);
	                	ether_addr_copy(&my_nic_mac[port^1],&eth_h->s_addr);
	                	pkts_to_send[port^1][num_pkts_to_send[port^1]++] = pkt;
	                }
	                
	            }
	            
	        }
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			for(send_port=0; send_port < nb_ports; send_port++) {
				printf("SENDING> port:%d, num_pkts:%d\n",send_port,num_pkts_to_send[send_port]);
				if(num_pkts_to_send[send_port]>0){
					const uint16_t nb_tx = rte_eth_tx_burst(send_port, 0,
							pkts_to_send[send_port], num_pkts_to_send[send_port]);
					if (unlikely(nb_tx < num_pkts_to_send[send_port])) {
						uint16_t buf;
						printf("DROP>cant sent (tx_burst).%d\n", num_pkts_to_send[send_port]-nb_tx);
						for (buf = nb_tx; buf < num_pkts_to_send[send_port]; buf++){
							rte_pktmbuf_free(bufs[buf]);
							rte_pktmbuf_free(pkts_to_send[send_port][buf]);
						}
					}
					num_pkts_to_send[send_port]=0;
				}
			}
			printf("SENDING> pkts:%d, tcp:%d, udp:%d, icmp:%d, unkwown:%d\n", sum_recive_pkts, sum_recive_tcp, sum_recive_udp, sum_recive_icmp, sum_recive_x);
			printf("-------------------end-loop-----------------------\n");
		}
	}
}



/*add by leal*/
static void
setup_hash(void)
{
     struct rte_hash_parameters ipv4_hash_params = {
		.name = NULL,
		.entries = HASH_ENTRIES,
		.key_len = sizeof(struct ipv4_5tuple),
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
	};
	char s[64];
	snprintf(s, sizeof(s), "ipv4_hash_0");
	ipv4_hash_params.name = s;
	ipv4_hash_params.socket_id = 1;
    ipv4_lookup_struct[0] = rte_hash_create(&ipv4_hash_params);
    if (ipv4_lookup_struct[0] == NULL)
        rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", 1); 

    snprintf(s, sizeof(s), "ipv4_hash_1");
	ipv4_hash_params.name = s;
	ipv4_lookup_struct[1] = rte_hash_create(&ipv4_hash_params);
    if (ipv4_lookup_struct[1] == NULL)
        rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", 1); 
                            

    snprintf(s, sizeof(s), "ipv4_hash_arp");
    ipv4_hash_params.name = s;
	ipv4_hash_params.socket_id = 1;
	ipv4_hash_params.key_len = sizeof(uint32_t);
    arp_lookup = rte_hash_create(&ipv4_hash_params);
    if (arp_lookup == NULL)
        rte_exit(EXIT_FAILURE, "Unable to create the arp hash\n");  

    /*Public IP (for testing remove it)*/
    public_ip[0]=IPV4(10, 20, 30, 30);//25995456;//10.20.30.30
    public_ip[1]=IPV4(10, 20, 30, 40);//25995457;//10.20.30.40
    my_nic_ip[0]=IPV4(192, 168, 130, 1);//25340096;//-1062698495;//192.168.130.1
    my_nic_ip[1]=IPV4(192, 168, 140, 1);//25995456;//-1062695935;//192.168.140.1
    /*Public IP */  
}
/*end by leal*/


/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t portid;

	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			"App uses only 1 lcore\n");










    /*add by leal*/
   
    setup_hash();
    
    
    
    /*end by leal*/



















	/* call lcore_main on master core only */
	lcore_main();
	return 0;
}
