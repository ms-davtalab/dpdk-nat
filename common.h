#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

static const char *
arp_op_name(uint16_t arp_op)
{
	switch (arp_op ) {
	case ARP_OP_REQUEST:
		return "ARP Request";
	case ARP_OP_REPLY:
		return "ARP Reply";
	case ARP_OP_REVREQUEST:
		return "Reverse ARP Request";
	case ARP_OP_REVREPLY:
		return "Reverse ARP Reply";
	case ARP_OP_INVREQUEST:
		return "Peer Identify Request";
	case ARP_OP_INVREPLY:
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

static const char *
ip_proto_name(uint16_t ip_proto)
{
	static const char * ip_proto_names[] = {
		"IP6HOPOPTS", /**< IP6 hop-by-hop options */
		"ICMP",       /**< control message protocol */
		"IGMP",       /**< group mgmt protocol */
		"GGP",        /**< gateway^2 (deprecated) */
		"IPv4",       /**< IPv4 encapsulation */

		"UNASSIGNED",
		"TCP",        /**< transport control protocol */
		"ST",         /**< Stream protocol II */
		"EGP",        /**< exterior gateway protocol */
		"PIGP",       /**< private interior gateway */

		"RCC_MON",    /**< BBN RCC Monitoring */
		"NVPII",      /**< network voice protocol*/
		"PUP",        /**< pup */
		"ARGUS",      /**< Argus */
		"EMCON",      /**< EMCON */

		"XNET",       /**< Cross Net Debugger */
		"CHAOS",      /**< Chaos*/
		"UDP",        /**< user datagram protocol */
		"MUX",        /**< Multiplexing */
		"DCN_MEAS",   /**< DCN Measurement Subsystems */

		"HMP",        /**< Host Monitoring */
		"PRM",        /**< Packet Radio Measurement */
		"XNS_IDP",    /**< xns idp */
		"TRUNK1",     /**< Trunk-1 */
		"TRUNK2",     /**< Trunk-2 */

		"LEAF1",      /**< Leaf-1 */
		"LEAF2",      /**< Leaf-2 */
		"RDP",        /**< Reliable Data */
		"IRTP",       /**< Reliable Transaction */
		"TP4",        /**< tp-4 w/ class negotiation */

		"BLT",        /**< Bulk Data Transfer */
		"NSP",        /**< Network Services */
		"INP",        /**< Merit Internodal */
		"SEP",        /**< Sequential Exchange */
		"3PC",        /**< Third Party Connect */

		"IDPR",       /**< InterDomain Policy Routing */
		"XTP",        /**< XTP */
		"DDP",        /**< Datagram Delivery */
		"CMTP",       /**< Control Message Transport */
		"TPXX",       /**< TP++ Transport */

		"ILTP",       /**< IL transport protocol */
		"IPv6_HDR",   /**< IP6 header */
		"SDRP",       /**< Source Demand Routing */
		"IPv6_RTG",   /**< IP6 routing header */
		"IPv6_FRAG",  /**< IP6 fragmentation header */

		"IDRP",       /**< InterDomain Routing*/
		"RSVP",       /**< resource reservation */
		"GRE",        /**< General Routing Encap. */
		"MHRP",       /**< Mobile Host Routing */
		"BHA",        /**< BHA */

		"ESP",        /**< IP6 Encap Sec. Payload */
		"AH",         /**< IP6 Auth Header */
		"INLSP",      /**< Integ. Net Layer Security */
		"SWIPE",      /**< IP with encryption */
		"NHRP",       /**< Next Hop Resolution */

		"UNASSIGNED",
		"UNASSIGNED",
		"UNASSIGNED",
		"ICMPv6",     /**< ICMP6 */
		"IPv6NONEXT", /**< IP6 no next header */

		"Ipv6DSTOPTS",/**< IP6 destination option */
		"AHIP",       /**< any host internal protocol */
		"CFTP",       /**< CFTP */
		"HELLO",      /**< "hello" routing protocol */
		"SATEXPAK",   /**< SATNET/Backroom EXPAK */

		"KRYPTOLAN",  /**< Kryptolan */
		"RVD",        /**< Remote Virtual Disk */
		"IPPC",       /**< Pluribus Packet Core */
		"ADFS",       /**< Any distributed FS */
		"SATMON",     /**< Satnet Monitoring */

		"VISA",       /**< VISA Protocol */
		"IPCV",       /**< Packet Core Utility */
		"CPNX",       /**< Comp. Prot. Net. Executive */
		"CPHB",       /**< Comp. Prot. HeartBeat */
		"WSN",        /**< Wang Span Network */

		"PVP",        /**< Packet Video Protocol */
		"BRSATMON",   /**< BackRoom SATNET Monitoring */
		"ND",         /**< Sun net disk proto (temp.) */
		"WBMON",      /**< WIDEBAND Monitoring */
		"WBEXPAK",    /**< WIDEBAND EXPAK */

		"EON",        /**< ISO cnlp */
		"VMTP",       /**< VMTP */
		"SVMTP",      /**< Secure VMTP */
		"VINES",      /**< Banyon VINES */
		"TTP",        /**< TTP */

		"IGP",        /**< NSFNET-IGP */
		"DGP",        /**< dissimilar gateway prot. */
		"TCF",        /**< TCF */
		"IGRP",       /**< Cisco/GXS IGRP */
		"OSPFIGP",    /**< OSPFIGP */

		"SRPC",       /**< Strite RPC protocol */
		"LARP",       /**< Locus Address Resoloution */
		"MTP",        /**< Multicast Transport */
		"AX25",       /**< AX.25 Frames */
		"4IN4",       /**< IP encapsulated in IP */

		"MICP",       /**< Mobile Int.ing control */
		"SCCSP",      /**< Semaphore Comm. security */
		"ETHERIP",    /**< Ethernet IP encapsulation */
		"ENCAP",      /**< encapsulation header */
		"AES",        /**< any private encr. scheme */

		"GMTP",       /**< GMTP */
		"IPCOMP",     /**< payload compression (IPComp) */
		"UNASSIGNED",
		"UNASSIGNED",
		"PIM",        /**< Protocol Independent Mcast */
	};

	if (ip_proto < sizeof(ip_proto_names) / sizeof(ip_proto_names[0]))
		return ip_proto_names[ip_proto];
	switch (ip_proto) {
#ifdef IPPROTO_PGM
	case IPPROTO_PGM:  /**< PGM */
		return "PGM";
#endif
	case IPPROTO_SCTP:  /**< Stream Control Transport Protocol */
		return "SCTP";
#ifdef IPPROTO_DIVERT
	case IPPROTO_DIVERT: /**< divert pseudo-protocol */
		return "DIVERT";
#endif
	case IPPROTO_RAW: /**< raw IP packet */
		return "RAW";
	default:
		break;
	}
	return "UNASSIGNED";
}

static void
ipv4_addr_to_dot(uint32_t be_ipv4_addr, char *buf)
{
	uint32_t ipv4_addr;

	ipv4_addr = rte_be_to_cpu_32(be_ipv4_addr);
	sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
		(ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
		ipv4_addr & 0xFF);
}

static void
ether_addr_dump(const char *what, const struct ether_addr *ea)
{
	char buf[ETHER_ADDR_FMT_SIZE];

	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, ea);
	if (what)
		printf("%s : ", what);
	printf("%s\n", buf);
}

static void
ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
	char buf[16];

	ipv4_addr_to_dot(be_ipv4_addr, buf);
	if (what)
		printf("%s", what);
	printf("%s", buf);
}

/*static void
arp_request(uint32_t ip_addr){
	struct rte_mbuf *created_pkt;
    struct ether_hdr *eth_hdr;
    struct arp_hdr *arp_hdr;
    
    size_t pkt_size;
    if (res->ip.family == AF_INET)
            get_string(res, ip_str, INET_ADDRSTRLEN);
    else
            cmdline_printf(cl, "Wrong IP format. Only IPv4 is supported\n");
    bond_ip = BOND_IP_1 | (BOND_IP_2 << 8) |
                            (BOND_IP_3 << 16) | (BOND_IP_4 << 24);
    created_pkt = rte_pktmbuf_alloc(mbuf_pool);
    pkt_size = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    created_pkt->data_len = pkt_size;
    created_pkt->pkt_len = pkt_size;
    eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
    rte_eth_macaddr_get(BOND_PORT, &eth_hdr->s_addr);
    memset(&eth_hdr->d_addr, 0xFF, ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    arp_hdr = (struct arp_hdr *)((char *)eth_hdr + sizeof(struct ether_hdr));
    arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    arp_hdr->arp_hln = ETHER_ADDR_LEN;
    arp_hdr->arp_pln = sizeof(uint32_t);
    arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);
    rte_eth_macaddr_get(BOND_PORT, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = bond_ip;
    memset(&arp_hdr->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_tip =
                      ((unsigned char *)&res->ip.addr.ipv4)[0]        |
                     (((unsigned char *)&res->ip.addr.ipv4)[1] << 8)  |
                     (((unsigned char *)&res->ip.addr.ipv4)[2] << 16) |
                     (((unsigned char *)&res->ip.addr.ipv4)[3] << 24);
    rte_eth_tx_burst(BOND_PORT, 0, &created_pkt, 1);
    rte_delay_ms(100);
}
*/

/*
static uint16_t
do_nat(uint8_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	
	return nb_pkts;
}
*/