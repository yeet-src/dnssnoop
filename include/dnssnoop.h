#ifndef __DNSSNOOP_H__
#define __DNSSNOOP_H__

#include <vmlinux.h>

#define ETH_P_IP 0x0800

#define COMMAND_BUF_SIZE 256
#define THREAD_NAME_BUF_SIZE 32
#define DOMAIN_NAME_BUF_SIZE 256
#define CGROUP_NAME_BUF_SIZE 512

#define RINGBUF_SIZE 1024
#define LRU_HASH_SIZE 1024

#define DNS_FLAG_QR_QUERY 0
#define DNS_FLAG_QR_REPLY 1

#define DNS_FLAG_RCODE_NO_ERR 0

// this is the size that `test_snprintf.c` in the kernel tree uses
#define IP_BUF_SIZE 64

#define DNS_FLAG_QR(flags) (((u16) (flags) & 0x8000) >> 15)
#define DNS_FLAG_OPCODE(flags) (((u16) (flags) & 0x7800) >> 11)
#define DNS_FLAG_AA(flags) (((u16) (flags) & 0x0400) >> 10)
#define DNS_FLAG_TC(flags) (((u16) (flags) & 0x0200) >> 9)
#define DNS_FLAG_RD(flags) (((u16) (flags) & 0x0100) >> 8)
#define DNS_FLAG_RA(flags) (((u16) (flags) & 0x0080) >> 7)
#define DNS_FLAG_Z(flags) (((u16) (flags) & 0x0040) >> 6)
#define DNS_FLAG_AD(flags) (((u16) (flags) & 0x0020) >> 5)
#define DNS_FLAG_CD(flags) (((u16) (flags) & 0x0010) >> 4)
#define DNS_FLAG_RCODE(flags) ((u16) (flags) & 0x000F)

struct query_state_key {
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u16 tx_id;
};

struct dnshdr {
  u16 id;
  u16 flags;
  u16 q_count;
  u16 ans_count;
  u16 auth_count;
  u16 add_count;
};

struct inflight_dns_query {
  // userspace tid, kernel pid
  pid_t tid;
  // userspace pid, kernel tgid
  pid_t pid;
  u64 cgroup_id;
  u64 start_time;
  u16 transaction_id;
  char command[COMMAND_BUF_SIZE];
  char thread_name[THREAD_NAME_BUF_SIZE];
  char domain_name[DOMAIN_NAME_BUF_SIZE];
  char cgroup[CGROUP_NAME_BUF_SIZE];
} __attribute__((packed));

struct dns_query {
  // userspace tid, kernel pid
  pid_t tid;
  // userspace pid, kernel tgid
  pid_t pid;
  u64 cgroup_id;
  u64 latency_ns;
  u16 transaction_id;
  char command[COMMAND_BUF_SIZE];
  char thread_name[THREAD_NAME_BUF_SIZE];
  char domain_name[DOMAIN_NAME_BUF_SIZE];
  char cgroup_name[CGROUP_NAME_BUF_SIZE];
  char remote_ip[IP_BUF_SIZE];
  u16 remote_port;
  char local_ip[IP_BUF_SIZE];
  u16 local_port;
} __attribute__((packed));

#define READ_FROM_PACKET(type, var, data, data_len)  \
  do {                                               \
    if (data_len < sizeof(type)) {                   \
      return 0;                                      \
    }                                                \
    bpf_probe_read_kernel(&var, sizeof(type), data); \
    data_len -= sizeof(type);                        \
    data += sizeof(type);                            \
  } while (0)

#define DECODE_PACKETS_UDP(sk_buff_addr, ip, udp, data, data_len, use_eth) \
  do {                                                                     \
    struct sk_buff skb = {};                                               \
    bpf_probe_read_kernel(&skb, sizeof(struct sk_buff), sk_buff_addr);     \
    data_len = skb.len;                                                    \
    data = (void*) (long) skb.data;                                        \
    if (use_eth) {                                                         \
      struct ethhdr eth = {};                                              \
      READ_FROM_PACKET(struct ethhdr, eth, data, data_len);                \
      if (eth.h_proto != bpf_htons(ETH_P_IP)) {                            \
        return EXIT_FAILURE;                                               \
      }                                                                    \
    }                                                                      \
    if (data_len < sizeof(struct iphdr)) {                                 \
      return EXIT_FAILURE;                                                 \
    }                                                                      \
    data_len -= sizeof(struct iphdr);                                      \
    bpf_probe_read_kernel(&ip, sizeof(struct iphdr), data);                \
    u8 ip_ihl = ip.ihl;                                                    \
    data_len += sizeof(struct iphdr);                                      \
    if (data_len < ip_ihl << 2) {                                          \
      return EXIT_FAILURE;                                                 \
    }                                                                      \
    data += ip_ihl << 2;                                                   \
    data_len -= ip_ihl << 2;                                               \
    if (ip.protocol != IPPROTO_UDP) {                                      \
      return EXIT_FAILURE;                                                 \
    }                                                                      \
    data_len -= sizeof(struct udphdr);                                     \
    bpf_probe_read_kernel(&udp, sizeof(struct udphdr), data);              \
    data += sizeof(struct udphdr);                                         \
  } while (0)

#define DECODE_PACKETS_UDP_SKB(skb, ip, udp, data, data_len, use_eth) \
  do {                                                                     \
    data_len = skb.len;                                                    \
    data = (void*) (long) skb.data;                                        \
    if (use_eth) {                                                         \
      struct ethhdr eth = {};                                              \
      READ_FROM_PACKET(struct ethhdr, eth, data, data_len);                \
      if (eth.h_proto != bpf_htons(ETH_P_IP)) {                            \
        return EXIT_FAILURE;                                               \
      }                                                                    \
    }                                                                      \
    if (data_len < sizeof(struct iphdr)) {                                 \
      return EXIT_FAILURE;                                                 \
    }                                                                      \
    data_len -= sizeof(struct iphdr);                                      \
    bpf_probe_read_kernel(&ip, sizeof(struct iphdr), data);                \
    u8 ip_ihl = ip.ihl;                                                    \
    data_len += sizeof(struct iphdr);                                      \
    if (data_len < ip_ihl << 2) {                                          \
      return EXIT_FAILURE;                                                 \
    }                                                                      \
    data += ip_ihl << 2;                                                   \
    data_len -= ip_ihl << 2;                                               \
    if (ip.protocol != IPPROTO_UDP) {                                      \
      return EXIT_FAILURE;                                                 \
    }                                                                      \
    data_len -= sizeof(struct udphdr);                                     \
    bpf_probe_read_kernel(&udp, sizeof(struct udphdr), data);              \
    data += sizeof(struct udphdr);                                         \
  } while (0)
#endif
