#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <yeet/yeet.h>

#include "dnssnoop.h"

RINGBUF_CHANNEL(dns_queries_rb, RINGBUF_SIZE * sizeof(struct dns_query), dns_query);

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct query_state_key);
  __type(value, struct inflight_dns_query);
  __uint(max_entries, LRU_HASH_SIZE);
} query_state SEC(".maps");

#define DNS_MAX_DOMAIN_LEN 256
#define SCRATCH_BUF_LEN 256
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u8[SCRATCH_BUF_LEN]);
  __uint(max_entries, 1);
} scratch_buf SEC(".maps");

struct inflight_dns_query empty = {};

static s64 format_dns_record_to_domain_name(char* name, u32 name_len, const void* record, const u32 record_len)
{
  if (record == NULL || name == NULL) {
    return -1;
  }

  void* read_cursor = (void*) record;
  void* read_end_ptr = (void*) record + record_len - 1;
  void* write_cursor = (void*) name;
  void* write_end_ptr = (void*) name + name_len - 1;

  u8 this_segment_len = *(u8*) (read_cursor++);
  for (int i = 0; i < DNS_MAX_DOMAIN_LEN && read_cursor <= read_end_ptr && write_cursor < write_end_ptr; i++) {
    if (this_segment_len == 0) {
      this_segment_len = *(u8*) (read_cursor++);

      if (this_segment_len == 0) {
        *(u8*) (write_cursor++) = '\0';
        return write_cursor - (void*) name;
      }

      *(u8*) (write_cursor++) = '.';
    } else {
      this_segment_len--;
      *(u8*) (write_cursor++) = *(u8*) (read_cursor++);
    }
  }

  *(u8*) write_cursor = '\0';
  return -1;
}

SEC("tracepoint/net/net_dev_xmit")
int trace_egress(struct trace_event_raw_net_dev_xmit* ctx)
{
  void* data = NULL;
  u32 data_len = 0;
  void* sk_buff_addr = BPF_CORE_READ(ctx, skbaddr);

  struct iphdr ip_header = {};
  struct udphdr udp_header = {};

  int index = 0;
  void* buf = bpf_map_lookup_elem(&scratch_buf, &index);
  if (!buf) {
    return EXIT_FAILURE;
  }

  struct sk_buff* skb = buf;
  bpf_probe_read_kernel(skb, sizeof(struct sk_buff), sk_buff_addr);
  DECODE_PACKETS_UDP_SKB((*skb), ip_header, udp_header, data, data_len, true);

  if (ip_header.version != 4) {
    return EXIT_FAILURE;
  }

  if (udp_header.dest != bpf_htons(53)) {
    return EXIT_FAILURE;
  }

  struct dnshdr dns = {};
  READ_FROM_PACKET(struct dnshdr, dns, data, data_len);

  dns.id = bpf_ntohs(dns.id);
  dns.flags = bpf_ntohs(dns.flags);
  dns.q_count = bpf_ntohs(dns.q_count);
  dns.ans_count = bpf_ntohs(dns.ans_count);
  dns.auth_count = bpf_ntohs(dns.auth_count);
  dns.add_count = bpf_ntohs(dns.add_count);

  if (DNS_FLAG_QR(dns.flags) != DNS_FLAG_QR_QUERY) {
    return EXIT_FAILURE;
  }

  struct query_state_key key = {};
  key.saddr = ip_header.saddr;
  key.daddr = ip_header.daddr;
  key.sport = udp_header.source;
  key.dport = udp_header.dest;
  key.tx_id = dns.id;

  bpf_map_update_elem(&query_state, &key, &empty, BPF_ANY);

  struct task_struct* cur_tsk = (struct task_struct*) bpf_get_current_task();
  if (!cur_tsk) {
    return EXIT_FAILURE;
  }

  struct inflight_dns_query* state = bpf_map_lookup_elem(&query_state, &key);
  if (!state) {
    return EXIT_FAILURE;
  }

  u8* record = buf;
  u32 record_len = __builtin_elementwise_min(SCRATCH_BUF_LEN, data_len);
  bpf_probe_read_kernel(record, record_len, data);
  s64 len = format_dns_record_to_domain_name(state->domain_name, DOMAIN_NAME_BUF_SIZE, record, record_len);

  if (len < 0) {
    bpf_map_delete_elem(&query_state, &key);
    return EXIT_FAILURE;
  }

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  state->tid = pid;

  pid_t tgid = bpf_get_current_pid_tgid();
  state->pid = tgid;

  state->transaction_id = dns.id;
  state->start_time = bpf_ktime_get_ns();

  state->cgroup_id = bpf_get_current_cgroup_id();
  const char* cgroup_name = BPF_CORE_READ(cur_tsk, cgroups, subsys[memory_cgrp_id], cgroup, kn, name);
  if (bpf_probe_read_kernel_str(&state->cgroup, CGROUP_NAME_BUF_SIZE, cgroup_name) < 0) {
    bpf_map_delete_elem(&query_state, &key);
    return EXIT_FAILURE;
  }

  u64 arg_start = BPF_CORE_READ(cur_tsk, mm, arg_start);
  u64 arg_end = BPF_CORE_READ(cur_tsk, mm, arg_end);
  u64 arg_len = arg_end - arg_start;

  if (!arg_start || !arg_end || arg_start >= arg_end) {
    return EXIT_FAILURE;
  }

  u64 arg_copy_len = __builtin_elementwise_min(arg_len, COMMAND_BUF_SIZE);
  bpf_probe_read_user(&state->command, arg_copy_len, (char*) arg_start);
  for (int i = 0; i < arg_copy_len; i++) {
    if (state->command[i] == '\0') {
      state->command[i] = ' ';
    }
  }

  if (arg_len > arg_copy_len) {
    state->command[COMMAND_BUF_SIZE - 1] = '\0';
    state->command[COMMAND_BUF_SIZE - 2] = '>';
    state->command[COMMAND_BUF_SIZE - 3] = '.';
    state->command[COMMAND_BUF_SIZE - 4] = '.';
    state->command[COMMAND_BUF_SIZE - 5] = '.';
    state->command[COMMAND_BUF_SIZE - 6] = '<';
  }

  bpf_get_current_comm(state->thread_name, THREAD_NAME_BUF_SIZE);

  bpf_map_update_elem(&query_state, &key, state, BPF_ANY);
  return EXIT_SUCCESS;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_ingress(struct trace_event_raw_net_dev_template* ctx)
{
  void* sk_buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip_header = {};
  struct udphdr udp_header = {};
  void* data = NULL;
  u32 data_len = 0;

  int index = 0;
  void* buf = bpf_map_lookup_elem(&scratch_buf, &index);
  if (!buf) {
    return EXIT_FAILURE;
  }

  struct sk_buff* skb = buf;
  bpf_probe_read_kernel(skb, sizeof(struct sk_buff), sk_buff_addr);
  DECODE_PACKETS_UDP_SKB((*skb), ip_header, udp_header, data, data_len, false);

  if (ip_header.version != 4) {
    return EXIT_FAILURE;
  }

  if (udp_header.source != bpf_htons(53)) {
    return EXIT_FAILURE;
  }

  struct dnshdr dns = {};
  READ_FROM_PACKET(struct dnshdr, dns, data, data_len);

  dns.id = bpf_ntohs(dns.id);
  dns.flags = bpf_ntohs(dns.flags);
  dns.q_count = bpf_ntohs(dns.q_count);
  dns.ans_count = bpf_ntohs(dns.ans_count);
  dns.auth_count = bpf_ntohs(dns.auth_count);
  dns.add_count = bpf_ntohs(dns.add_count);

  if (DNS_FLAG_QR(dns.flags) != DNS_FLAG_QR_REPLY) {
    return EXIT_FAILURE;
  }

  if (DNS_FLAG_RCODE(dns.flags) != DNS_FLAG_RCODE_NO_ERR) {
    return EXIT_FAILURE;
  }

  struct query_state_key key = {};
  key.saddr = ip_header.daddr;
  key.sport = udp_header.dest;
  key.daddr = ip_header.saddr;
  key.dport = udp_header.source;
  key.tx_id = dns.id;

  struct inflight_dns_query* state = bpf_map_lookup_elem(&query_state, &key);
  if (!state) {
    return EXIT_FAILURE;
  }

  struct dns_query* out = bpf_ringbuf_reserve(&dns_queries_rb, sizeof(struct dns_query), 0);
  if (!out) {
    return EXIT_FAILURE;
  }

  out->transaction_id = state->transaction_id;
  out->tid = state->tid;
  out->pid = state->pid;
  out->cgroup_id = state->cgroup_id;
  out->latency_ns = bpf_ktime_get_ns() - state->start_time;

  u32 sa = ip_header.saddr;
  u8 sa_octets[] = {
    sa & 0xff,
    sa >> 8 & 0xff,
    sa >> 16 & 0xff,
    sa >> 24 & 0xff,
  };
  BPF_SNPRINTF(out->remote_ip, IP_BUF_SIZE, "%pI4", sa_octets);
  out->remote_port = bpf_ntohs(udp_header.source);

  u32 da = ip_header.daddr;
  u8 da_octets[] = {
    da & 0xff,
    da >> 8 & 0xff,
    da >> 16 & 0xff,
    da >> 24 & 0xff,
  };
  BPF_SNPRINTF(out->local_ip, IP_BUF_SIZE, "%pI4", da_octets);
  out->local_port = bpf_ntohs(udp_header.dest);

  bpf_probe_read_kernel_str(&out->domain_name, DOMAIN_NAME_BUF_SIZE, state->domain_name);
  bpf_probe_read_kernel_str(&out->command, COMMAND_BUF_SIZE, state->command);
  bpf_probe_read_kernel_str(&out->thread_name, THREAD_NAME_BUF_SIZE, state->thread_name);
  bpf_probe_read_kernel_str(&out->cgroup_name, CGROUP_NAME_BUF_SIZE, state->cgroup);

  bpf_ringbuf_submit(out, 0);
  return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL");
