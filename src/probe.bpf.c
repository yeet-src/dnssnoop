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

static s64 format_dns_record_to_domain_name(char* name, u32 name_len, const void* record, void* data_end)
{
  if (record == NULL || name == NULL) {
    return -1;
  }

  void* read_cursor = (void*) record;
  void* read_end_ptr = data_end;
  void* write_cursor = (void*) name;
  void* write_end_ptr = (void*) name + name_len - 1;

  u8 this_segment_len = *(u8*) (read_cursor++);
  for (int i = 0; i < DNS_MAX_DOMAIN_LEN && read_cursor < read_end_ptr && write_cursor < write_end_ptr; i++) {
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

static const void* process_questions(char* name, u32 name_len, const void* questions, void* data_end)
{
  return questions;
}

// `ip` is in network byte order
static inline bool is_localhost(u32 ip)
{
  return (ip & 0xFF) == 127;
}

int handle_packet(const char ie, struct __sk_buff const* const skb)
{
  void* data_end = (void*) (__u64) skb->data_end;
  void* data = (void*) (__u64) skb->data;

  if (skb->protocol != bpf_htons(ETH_P_IP)) {
    return 0;
  }

  // "Parse" ethernet header.
  struct ethhdr* ethernet_header;
  ethernet_header = data;
  if ((void*) (ethernet_header + 1) > data_end) {
    return 0;
  }

  // "Parse" IP header
  struct iphdr* ip_header;
  ip_header = (struct iphdr*) (ethernet_header + 1);
  if ((void*) (ip_header + 1) > data_end) {
    return 0;
  }

  if (ip_header->protocol != 0x11) {
    return 0;
  }

  // Deduplicate requests/responses on localhost, only process on egress.
  if (ie == 'i' && (is_localhost(ip_header->saddr) || is_localhost(ip_header->daddr))) {
    return 0;
  }

  // "Parse" UDP header.
  struct udphdr* udp_header;
  udp_header = ((void*) ip_header) + (ip_header->ihl * 4);
  if ((void*) (udp_header + 1) > data_end) {
    return 0;
  }

  if (udp_header->source != bpf_htons(53) && udp_header->dest != bpf_htons(53)) {
    return 0;
  }

  // "Parse" DNS header.
  struct dnshdr* dns_header = (struct dnshdr*) (udp_header + 1);
  if ((void*) (dns_header + 1) >= data_end) {
    return 0;
  }

  void* dns_body = (void*) (dns_header + 1);
  size_t dns_body_len = data_end - (void*) dns_body;

  if ((void*) dns_body + dns_body_len > data_end) {
    return 0;
  }

  bool is_query = DNS_FLAG_QR(dns_header->flags) == DNS_FLAG_QR_QUERY;

  if (is_query) {
    // Queries
    struct query_state_key key = {};
    key.client_addr = ip_header->saddr;
    key.server_addr = ip_header->daddr;
    key.client_port = udp_header->source;
    key.server_port = udp_header->dest;
    key.tx_id = dns_header->id;

    // New query, ensure map doesn't have stale data.
    bpf_map_update_elem(&query_state, &key, &empty, BPF_ANY);

    struct task_struct* cur_tsk = (struct task_struct*) bpf_get_current_task();
    if (!cur_tsk) {
      return EXIT_FAILURE;
    }

    struct inflight_dns_query* state = bpf_map_lookup_elem(&query_state, &key);
    if (!state) {
      return EXIT_FAILURE;
    }

    s64 len = format_dns_record_to_domain_name(state->domain_name, DOMAIN_NAME_BUF_SIZE, dns_body, data_end);

    if (len < 0) {
      bpf_map_delete_elem(&query_state, &key);
      return EXIT_FAILURE;
    }

    pid_t pid = bpf_get_current_pid_tgid();
    state->tid = pid;
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;
    state->pid = tgid;

    // uid_t uid = bpf_get_current_uid_gid();
    // state->uid = uid;
    // gid_t gid = bpf_get_current_uid_gid() >> 32;
    // state->gid = gid;

    state->transaction_id = dns_header->id;
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

    // bpf_get_current_comm(state->thread_name, THREAD_NAME_BUF_SIZE);

    bpf_map_update_elem(&query_state, &key, state, BPF_ANY);
  } else {
    // Responses
    struct query_state_key key = {};
    key.client_addr = ip_header->daddr;
    key.server_addr = ip_header->saddr;
    key.client_port = udp_header->dest;
    key.server_port = udp_header->source;
    key.tx_id = dns_header->id;

    if (DNS_FLAG_RCODE(bpf_ntohs(dns_header->flags)) != DNS_FLAG_RCODE_NO_ERR) {
      return 0;
    }

    struct inflight_dns_query* state = bpf_map_lookup_elem(&query_state, &key);
    if (!state) {
      return 0;
    }

    // Build complete `struct dnsquery` output message.
    struct dns_query* out = bpf_ringbuf_reserve(&dns_queries_rb, sizeof(struct dns_query), 0);
    if (!out) {
      return 0;
    }

    out->transaction_id = state->transaction_id;
    out->tid = state->tid;
    out->pid = state->pid;
    out->uid = state->uid;
    out->gid = state->gid;
    out->cgroup_id = state->cgroup_id;
    out->latency_ns = bpf_ktime_get_ns() - state->start_time;

    BPF_SNPRINTF(out->remote_ip, IP_BUF_SIZE, "%pI4", &ip_header->saddr);
    out->remote_port = bpf_ntohs(udp_header->source);

    BPF_SNPRINTF(out->local_ip, IP_BUF_SIZE, "%pI4", &ip_header->daddr);
    out->local_port = bpf_ntohs(udp_header->dest);

    bpf_probe_read_kernel_str(&out->domain_name, DOMAIN_NAME_BUF_SIZE, state->domain_name);
    bpf_probe_read_kernel_str(&out->command, COMMAND_BUF_SIZE, state->command);
    bpf_probe_read_kernel_str(&out->thread_name, THREAD_NAME_BUF_SIZE, state->thread_name);
    bpf_probe_read_kernel_str(&out->cgroup_name, CGROUP_NAME_BUF_SIZE, state->cgroup);

    bpf_ringbuf_submit(out, 0);

    // Remove query state.
    bpf_map_delete_elem(&query_state, &key);
  }

  return 0;
}

SEC("tc/egress")
int trace_egress(struct __sk_buff* sk)
{
  return handle_packet('e', sk);
}

SEC("tc/ingress")
int trace_ingress(struct __sk_buff* sk)
{
  return handle_packet('i', sk);
}

LICENSE("Dual BSD/GPL");
