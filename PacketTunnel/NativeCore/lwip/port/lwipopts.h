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

/* Memory — byte accounting in docs/nativecore-memory-budget.md (nc-memory audit).
   Static total of heap + pools below is ≈1.9 MB (fix/nc-stack-pool-capacity;
   was ≈540 KB). Per-connection TCP payload (windows) is drawn from the shared
   heap/pool, not allocated per PCB. */
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#define MEM_ALIGNMENT 8
/* fix/nc-stack-pool-capacity: 320K → 1M (+704 KB). Heap consumers here are
   PBUF_RAM send copies (bounded by TCP_SND_BUF per conn, back-pressured by the
   Swift outbox cap) and small structs; 1M holds ~44 full send windows
   concurrently. Device evidence (build 545, clean single-app sessions): the
   old sizing starved app-launch bursts — a feed refresh opens 30–60 flows at
   once, the pools below ran dry and the unlucky flows stalled past the apps'
   image timeouts (Xiaohongshu covers blank, YouTube home skeleton) while the
   same traffic completed instantly with the tunnel off. */
#define MEM_SIZE (1024 * 1024)
#define MEMP_NUM_PBUF 320
/* fix/nc-stack-pool-capacity: 80 → 320 (× 2048 B = 640 KB of pool payload).
   The pool is shared by TUN + WireGuard netifs and all TCP/UDP payload;
   320 × 2048 B absorbs bursts of ~28 full receive windows (was ~7). */
#define PBUF_POOL_SIZE 320
#define PBUF_POOL_BUFSIZE 2048
/* feat/nc-wg: +32 TCP / +16 UDP PCBs for WireGuard client flows (nc_wg.c), ~8 KB.
   fix/nc-stack-pool-capacity: 128 → 384 — NC_MAX_TCP_CONNS (288) + listeners
   (24) + TIME_WAIT churn headroom. */
#define MEMP_NUM_TCP_PCB 384
/* nc-memory: 48 → 24 (−24 × ~104 B ≈ −2.4 KB). Listening PCBs are one per
   listen port on the stack queue; nothing here opens dozens of listeners. */
#define MEMP_NUM_TCP_PCB_LISTEN 24
/* fix/nc-stack-pool-capacity: 128 → 1024. Segments are the tightest shared
   pool under burst load: 128 across ~50 concurrent flows is 2–3 per flow, so
   simultaneous downloads dropped/queued segments and crawled; 1024 gives a
   50-flow burst ~20 per flow (a full window is 16). */
#define MEMP_NUM_TCP_SEG 1024
#define MEMP_NUM_UDP_PCB 64
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
/* e2e-real-3: one UDP pcb per client flow, all bound to the same local dst:port (198.18.0.2:53, a QUIC server:443).
   Without SO_REUSE every bind after the first returns ERR_USE → only the first DNS socket ever got answers.
   udp_input still picks the fully matching connected pcb first. */
#define SO_REUSE 1
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
/* feat/nc-wg: WireGuard devices are extra netifs (nc_wg.c); TUN stays the default netif.
   Scopes off: no link-local traffic on either kind of netif, keep ip6_addr_t as before. */
#define LWIP_SINGLE_NETIF 0
#define LWIP_IPV6_SCOPES 0
#define PBUF_LINK_HLEN 0
#define IP_SOF_BROADCAST 0
#define LWIP_BROADCAST_PING 0
#define LWIP_MULTICAST_PING 0

#endif
