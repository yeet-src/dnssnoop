#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <yeet/yeet.h>

#include "dnssnoop.h"

RINGBUF_CHANNEL(dns_queries_rb, RINGBUF_SIZE * sizeof(struct dns_query), dns_query);

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct conn_key);
  __type(value, struct dns_query_internal);
  __uint(max_entries, LRU_HASH_SIZE);
} conns_map SEC(".maps");

struct dns_query_internal empty = {};

SEC("tracepoint/net/net_dev_xmit")
int trace_egress(struct trace_event_raw_net_dev_xmit* ctx)
{
  void* buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip = {};
  struct udphdr udp = {};
  void* data = NULL;
  u32 data_len = 0;

  DECODE_PACKETS_UDP(buff_addr, ip, udp, data, data_len, true);

  struct dnshdr dns = {};
  READ_FROM_PACKET(struct dnshdr, dns, data, data_len);

  dns.id = bpf_ntohs(dns.id);
  dns.flags = bpf_ntohs(dns.flags);
  dns.q_count = bpf_ntohs(dns.q_count);
  dns.ans_count = bpf_ntohs(dns.ans_count);
  dns.auth_count = bpf_ntohs(dns.auth_count);
  dns.add_count = bpf_ntohs(dns.add_count);

  if (DNS_FLAG_Z(dns.flags) != 0 || DNS_FLAG_QR(dns.flags) != DNS_QUERY_CODE) {
    return EXIT_FAILURE;
  }

  struct conn_key key = {};
  key.saddr = ip.saddr;
  key.daddr = ip.daddr;
  key.sport = udp.source;
  key.dport = udp.dest;

  bpf_map_update_elem(&conns_map, &key, &empty, BPF_ANY);

  struct task_struct* cur_tsk = (struct task_struct*) bpf_get_current_task();
  if (!cur_tsk) {
    return EXIT_FAILURE;
  }

  struct dns_query_internal* cached = bpf_map_lookup_elem(&conns_map, &key);
  if (!cached) {
    return EXIT_FAILURE;
  }
  bpf_probe_read_kernel_str(&cached->name, NAME_BUF_SIZE, data);

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  cached->pid = pid;

  pid_t tgid = bpf_get_current_pid_tgid();
  cached->tgid = tgid;

  cached->id = dns.id;
  cached->start_time = bpf_ktime_get_ns();

  cached->cgroup_id = bpf_get_current_cgroup_id();
  const char* name = BPF_CORE_READ(cur_tsk, cgroups, subsys[memory_cgrp_id], cgroup, kn, name);
  if (bpf_probe_read_kernel_str(&cached->cgroup, CGROUP_BUF_SIZE, name) < 0) {
    bpf_map_delete_elem(&conns_map, &key);
    return EXIT_FAILURE;
  }

  bpf_get_current_comm(cached->comm, COMM_BUF_SIZE);
  bpf_map_update_elem(&conns_map, &key, cached, BPF_ANY);
  return EXIT_SUCCESS;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_ingress(struct trace_event_raw_net_dev_template* ctx)
{
  void* buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip = {};
  struct udphdr udp = {};
  void* data = NULL;
  u32 data_len = 0;
  int err;

  DECODE_PACKETS_UDP(buff_addr, ip, udp, data, data_len, false);

  struct conn_key key = {};
  key.saddr = ip.daddr;
  key.sport = udp.dest;
  key.daddr = ip.saddr;
  key.dport = udp.source;

  struct dns_query_internal* cached = bpf_map_lookup_elem(&conns_map, &key);
  if (!cached) {
    return EXIT_FAILURE;
  }

  struct dns_query* out = bpf_ringbuf_reserve(&dns_queries_rb, sizeof(struct dns_query), 0);
  if (!out) {
    return EXIT_FAILURE;
  }

  out->id = cached->id;
  out->pid = cached->pid;
  out->tgid = cached->tgid;
  out->cgroup_id = cached->cgroup_id;
  out->latency_ns = bpf_ktime_get_ns() - cached->start_time;

  bpf_probe_read_kernel_str(&out->name, NAME_BUF_SIZE, cached->name);
  bpf_probe_read_kernel_str(&out->comm, COMM_BUF_SIZE, cached->comm);
  bpf_probe_read_kernel_str(&out->cgroup, CGROUP_BUF_SIZE, cached->cgroup);

  bpf_ringbuf_submit(out, 0);
  return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL");
