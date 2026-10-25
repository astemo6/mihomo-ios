/* lwIP options for the native core's TUN stack (docs/native-core-design.md).
   Raw API, NO_SYS, single-threaded: the engine feeds packets and drives timers
   from one queue. Memory is sized for the Network Extension budget: the whole
   stack (heap + pools) must stay in low single-digit MB. */
#ifndef NC_LWIPOPTS_H
#define NC_LWIPOPTS_H

#define NO_SYS 1
#define LWIP_TIMERS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_CALLBACK_API 1

/* Memory */
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#define MEM_ALIGNMENT 8
#define MEM_SIZE (384 * 1024)
#define MEMP_NUM_PBUF 96
#define PBUF_POOL_SIZE 96
#define PBUF_POOL_BUFSIZE 2048
#define MEMP_NUM_TCP_PCB 96
#define MEMP_NUM_TCP_PCB_LISTEN 48
#define MEMP_NUM_TCP_SEG 128
#define MEMP_NUM_UDP_PCB 48
#define MEMP_NUM_RAW_PCB 8
#define MEMP_NUM_NETBUF 0
#define MEMP_NUM_NETCONN 0
#define MEMP_NUM_TCPIP_MSG_API 0
#define MEMP_NUM_TCPIP_MSG_INPKT 0
#define MEMP_NUM_SYS_TIMEOUT 16
#define MEMP_NUM_ARP_QUEUE 0
#define MEMP_NUM_IGMP_GROUP 0
#define MEMP_NUM_REASSDATA 0
#define LWIP_NUM_NETIF_CLIENT_DATA 0

/* Features */
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_ICMP 1
#define LWIP_ICMP6 1
#define LWIP_RAW 1
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define IP_FORWARD 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0
#define LWIP_IPV6_FRAG 0
#define LWIP_IPV6_REASS 0
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_DHCP6 0
#define LWIP_ND6_QUEUEING 0
#define LWIP_STATS 0
#define LWIP_DEBUG 0
#define LWIP_NETIF_HOSTNAME 0
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK 0
#define LWIP_LOOPBACK 0
#define TCP_LISTEN_BACKLOG 1
#define LWIP_TCP_SACK_OUT 0
#define LWIP_TCP_TIMESTAMPS 0
#define LWIP_WND_SCALE 0

/* TCP tuning: MSS follows the interface MTU (4064) at runtime; window sizes are
   kept modest on purpose — per-connection buffers are the memory enemy here. */
#define TCP_MSS 1460
#define TCP_WND (16 * TCP_MSS)
#define TCP_SND_BUF (16 * TCP_MSS)
#define TCP_SND_QUEUELEN 32
#define TCP_OVERSIZE TCP_MSS
#define TCP_MAXRTX 8
#define TCP_SYNMAXRTX 4

/* Checksums in software (no offload inside a packet tunnel). */
#define CHECKSUM_GEN_IP 1
#define CHECKSUM_GEN_UDP 1
#define CHECKSUM_GEN_TCP 1
#define CHECKSUM_GEN_ICMP 1
#define CHECKSUM_GEN_ICMP6 1
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_UDP 1
#define CHECKSUM_CHECK_TCP 1
#define CHECKSUM_CHECK_ICMP 1
#define CHECKSUM_CHECK_ICMP6 1

#define LWIP_TCPIP_CORE_LOCKING 0
#define LWIP_SINGLE_NETIF 1
#define PBUF_LINK_HLEN 0
#define IP_SOF_BROADCAST 0
#define LWIP_BROADCAST_PING 0
#define LWIP_MULTICAST_PING 0

#endif
