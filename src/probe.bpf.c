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
#define SCRATCH_BUF_LEN 1500
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u8[SCRATCH_BUF_LEN]);
  __uint(max_entries, 1);
} scratch_buf SEC(".maps");

struct inflight_dns_query empty = {};

static s64 format_dns_record_to_domain_name(char* name, u32 name_len, void** record, u32* record_len)
{
  if (record == NULL || name == NULL) {
    return -1;
  }

  void* read_cursor = (void*) *record;
  void* read_end_ptr = (void*) *record + *record_len - 1;
  void* write_cursor = (void*) name;
  void* write_end_ptr = (void*) name + name_len - 1;

  u8 this_segment_len = *(u8*) (read_cursor++);
  for (int i = 0; i < DNS_MAX_DOMAIN_LEN && read_cursor <= read_end_ptr && write_cursor < write_end_ptr; i++) {
    if (this_segment_len == 0) {
      this_segment_len = *(u8*) (read_cursor++);

      if (this_segment_len == 0) {
        *(u8*) (write_cursor++) = '\0';

        // adjust `record` to remove the portion we've read
        *record_len -= read_cursor - *record;
        *record = read_cursor;

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

static bool process_dns_questions(
    struct inflight_dns_query* state,
    const struct dnshdr header,
    void* body,
    void** body_cursor,
    u32* body_len)
{
  for(int i = 0; i < header.q_count; i++) {
    // TODO: this overwrites the query name with whatever is last. (Is that better/worse than our
    //       current first only approach?)
    if (format_dns_record_to_domain_name(state->name, NAME_BUF_SIZE, body_cursor, body_len) > 0) {
      return false;
    }

    bpf_dbg_printk("query name: %s", state->name);

    // return true;

    // type
    *body_cursor += 2;
    // class
    *body_cursor += 2;
  }


  return true;
}

static bool process_dns_answers(
    struct inflight_dns_query* state,
    const struct dnshdr header,
    void* body,
    void** body_cursor,
    u32* body_len)
{
  return false;
}

static bool process_dns_authority(
    struct inflight_dns_query* state,
    const struct dnshdr header,
    void* body,
    void** body_cursor,
    u32* body_len)
{
  return false;
}

static bool process_dns_additional(
    struct inflight_dns_query* state,
    const struct dnshdr header,
    void* body,
    void** body_cursor,
    u32* body_len)
{
  return false;
}

static bool process_dns_body(
    struct inflight_dns_query* state,
    struct dnshdr header,
    void* body,
    u32 body_len)
{
  void* body_cursor = body;
  if (!process_dns_questions(state, header, body, &body_cursor, &body_len)) {
    return false;
  }

  // HACK: to make it work as-is
  return true;

  if (!process_dns_answers(state, header, body, &body_cursor, &body_len)) {
    return false;
  }
  if (!process_dns_authority(state, header, body, &body_cursor, &body_len)) {
    return false;
  }
  if (!process_dns_additional(state, header, body, &body_cursor, &body_len)) {
    return false;
  }

  return true;
}

SEC("tracepoint/net/net_dev_xmit")
int trace_egress(struct trace_event_raw_net_dev_xmit* ctx)
{
  void* data = NULL;
  u32 data_len = 0;
  void* sk_buff_addr = BPF_CORE_READ(ctx, skbaddr);

  if (data_len > SCRATCH_BUF_LEN) {
    bpf_printk("Warning: Jumbo frames not supported by dnssnoop. Ignoring.");
    return EXIT_FAILURE;
  }

  struct iphdr ip = {};
  struct udphdr udp_header = {};

  int index = 0;
  void* buf = bpf_map_lookup_elem(&scratch_buf, &index);
  if (!buf) {
    return EXIT_FAILURE;
  }

  struct sk_buff* skb = buf;
  bpf_probe_read_kernel(skb, sizeof(struct sk_buff), sk_buff_addr);
  DECODE_PACKETS_UDP_SKB((*skb), ip, udp_header, data, data_len, true);

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
  key.saddr = ip.saddr;
  key.daddr = ip.daddr;
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

  // read out full body
  u8* body = buf;
  // already checked, verifier doesn't understand that
  u32 body_len = __builtin_elementwise_min(SCRATCH_BUF_LEN, data_len);
  bpf_probe_read_kernel(body, body_len, data);

  if (process_dns_body(state, dns, body, body_len)) {
    bpf_map_delete_elem(&query_state, &key);
    return EXIT_FAILURE;
  }

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  state->pid = pid;

  pid_t tgid = bpf_get_current_pid_tgid();
  state->tgid = tgid;

  state->id = dns.id;
  state->start_time = bpf_ktime_get_ns();

  state->cgroup_id = bpf_get_current_cgroup_id();
  const char* cgroup_name = BPF_CORE_READ(cur_tsk, cgroups, subsys[memory_cgrp_id], cgroup, kn, name);
  if (bpf_probe_read_kernel_str(&state->cgroup, CGROUP_BUF_SIZE, cgroup_name) < 0) {
    bpf_map_delete_elem(&query_state, &key);
    return EXIT_FAILURE;
  }

  bpf_get_current_comm(state->comm, COMM_BUF_SIZE);
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

  out->id = state->id;
  out->pid = state->pid;
  out->tgid = state->tgid;
  out->cgroup_id = state->cgroup_id;
  out->latency_ns = bpf_ktime_get_ns() - state->start_time;

  bpf_probe_read_kernel_str(&out->name, NAME_BUF_SIZE, state->name);
  bpf_probe_read_kernel_str(&out->comm, COMM_BUF_SIZE, state->comm);
  bpf_probe_read_kernel_str(&out->cgroup, CGROUP_BUF_SIZE, state->cgroup);

  bpf_ringbuf_submit(out, 0);
  return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL");
