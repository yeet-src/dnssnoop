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

struct cursor {
  struct bpf_dynptr* buf;
  u32 offset;
};

////////////////////////////////////////////////////////////////////////////////
// DNS Parsing
////////////////////////////////////////////////////////////////////////////////

struct segment_ctx {
  struct cursor* name;
  struct cursor* record;
  bool success;
};

////////////////////////////////////////////////////////////////////////////////
// Jump DNS Name
////////////////////////////////////////////////////////////////////////////////

static int jump_name_segment(u32 i, void* ctx)
{
  struct segment_ctx* c = ctx;

  // Read out segment length byte.
  u8* segment_len_ptr = bpf_dynptr_slice(c->record->buf, c->record->offset, NULL, 1);
  if (segment_len_ptr == NULL) {
    return BPF_LOOP_BREAK;
  }
  c->record->offset++;
  u8 segment_len = *segment_len_ptr;

  // A segment of 0 length, marks the end of this name.
  if (segment_len == 0) {
    c->success = true;
    return BPF_LOOP_BREAK;
  }

  if (segment_len & 0b11000000) {

    if (segment_len & 0b00111111) {
      bpf_printk("[dnssnoop] Protocol Error: Non-zero segment len after pointer marker: %d", segment_len);
      return BPF_LOOP_BREAK;
    }

    // Read out segment offset byte.
    u8* segment_offset_ptr = bpf_dynptr_slice(c->record->buf, c->record->offset, NULL, 1);
    if (segment_offset_ptr == NULL) {
      return BPF_LOOP_BREAK;
    }
    c->record->offset++;
    u8 segment_offset = *segment_offset_ptr;

    c->success = true;
    return BPF_LOOP_BREAK;
  }

  // Adjust offset to next segment.
  c->record->offset += segment_len;

  return BPF_LOOP_CONTINUE;
}

static bool jump_dns_name(struct cursor* record)
{
  struct segment_ctx ctx = { NULL, record, false };
  bpf_loop(DNS_MAX_SEGMENTS, jump_name_segment, (void*) &ctx, 0);

  if (ctx.success) {
    return 0;
  } else {
    return -1;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Read DNS Name
////////////////////////////////////////////////////////////////////////////////

static int read_name_segment(u32 i, void* ctx)
{
  struct segment_ctx* c = ctx;
  char buf[DNS_MAX_SEGMENT_LEN];

  // Read out segment length byte.
  u8* segment_len_ptr = bpf_dynptr_slice(c->record->buf, c->record->offset, NULL, 1);
  if (segment_len_ptr == NULL) {
    return BPF_LOOP_BREAK;
  }
  c->record->offset++;
  u8 segment_len = *segment_len_ptr;

  // A segment of 0 length, marks the end of this name.
  if (segment_len == 0) {
    c->success = true;
    return BPF_LOOP_BREAK;
  }

  if (segment_len & 0b11000000) {
    if (segment_len & 0b00111111) {
      bpf_printk("[dnssnoop] Protocol Error: Non-zero segment len after pointer marker: %d", segment_len);
      return BPF_LOOP_BREAK;
    }

    // Read out segment offset byte.
    u8* segment_offset_ptr = bpf_dynptr_slice(c->record->buf, c->record->offset, NULL, 1);
    if (segment_offset_ptr == NULL) {
      return BPF_LOOP_BREAK;
    }
    c->record->offset++;
    u8 segment_offset = *segment_offset_ptr;

    // TODO: parse pointed segment

    c->success = true;
    return BPF_LOOP_BREAK;
  }

  if (segment_len > DNS_MAX_SEGMENT_LEN) {
    return BPF_LOOP_BREAK;
  }

  // Copy from record to local buf.
  if (0 != bpf_dynptr_read(buf, segment_len, c->record->buf, c->record->offset, 0)) {
    return BPF_LOOP_BREAK;
  }
  c->record->offset += segment_len;

  // Copy from local buf to name.
  if (0 != bpf_dynptr_write(c->name->buf, c->name->offset, buf, segment_len, 0)) {
    return BPF_LOOP_BREAK;
  }
  c->name->offset += segment_len;

  // Terminate Segment with '.'.
  if (0 != bpf_dynptr_write(c->name->buf, c->name->offset, ".", 1, 0)) {
    return BPF_LOOP_BREAK;
  }
  c->name->offset++;

  return BPF_LOOP_CONTINUE;
}

static s64 format_dns_name_to_string(char* name, u32 name_len, struct cursor* record)
{
  if (name == NULL) {
    return -1;
  }

  struct bpf_dynptr dyn_name;
  if (bpf_dynptr_from_mem(name, name_len, 0, &dyn_name) != 0) {
    return -1;
  }
  struct cursor name_cursor = { &dyn_name, 0 };

  struct segment_ctx ctx = { &name_cursor, record, false };
  bpf_loop(DNS_MAX_SEGMENTS, read_name_segment, (void*) &ctx, 0);

  if (!ctx.success) {
    return -1;
  }

  if (0 != bpf_dynptr_write(&dyn_name, ctx.name->offset - 1, "\0", 1, 0)) {
    return -1;
  }

  u32 bytes_written = ctx.name->offset;

  return bytes_written;
}

////////////////////////////////////////////////////////////////////////////////
// Process DNS Sections
////////////////////////////////////////////////////////////////////////////////

static inline bool process_dns_questions(
    struct inflight_dns_query* state,
    const struct dnshdr* header,
    struct cursor* body)
{
  if (bpf_ntohs(header->q_count) > 1) {
    bpf_printk("[dnssnoop] DNS query contains more than one question (%d), results may be misleading.", bpf_ntohs(header->q_count));
  }
  // HACK: limited to one question:
  for (int i = 0; i < bpf_ntohs(header->q_count) && i < 1; i++) {
    if (format_dns_name_to_string(state->domain_name, DOMAIN_NAME_BUF_SIZE, body) < 0) {
      bpf_printk("[dnssnoop] Failed to format domain name.");
      return false;
    }

    // Type, just skip for now.
    body->offset += 2;

    // Class, just skip for now.
    body->offset += 2;
  }

  return true;
}

static inline bool process_dns_answers(
    struct inflight_dns_query* state,
    const struct dnshdr* header,
    struct cursor* body)
{
  int addresses_recorded = 0;
  for (int i = 0; i < bpf_ntohs(header->ans_count) && i < 10; i++) {
    if (jump_dns_name(body)) {
      bpf_printk("[dnssnoop] Failed to jump domain name.");
      return false;
    }

    // Type
    u16* type_ptr = bpf_dynptr_slice(body->buf, body->offset, NULL, 2);
    if (type_ptr == NULL) {
      return false;
    }
    body->offset += 2;
    u8 type = bpf_ntohs(*type_ptr);

    // Class
    u16* class_ptr = bpf_dynptr_slice(body->buf, body->offset, NULL, 2);
    if (class_ptr == NULL) {
      return false;
    }
    u16 class = bpf_ntohs(*class_ptr);
    body->offset += 2;

    // TTL, just skip for now.
    body->offset += 4;

    // RDLength
    u16* rd_len_ptr = bpf_dynptr_slice(body->buf, body->offset, NULL, 2);
    if (rd_len_ptr == NULL) {
      return false;
    }
    body->offset += 2;
    u16 rd_len = bpf_ntohs(*rd_len_ptr);

    // RData, based on type.
    if (type == 0x01) {
      if (rd_len != 4) {
        return false;
      }
      u32* rd_ptr = bpf_dynptr_slice(body->buf, body->offset, NULL, 4);
      if (rd_ptr == NULL) {
        return false;
      }
      if (addresses_recorded < RESOLVED_ADDRESSES_MAX) {
        BPF_SNPRINTF(state->resolved_addresses[addresses_recorded++], IP_BUF_SIZE, "%pI4", rd_ptr);
      }
    }
    body->offset += rd_len;
  }

  return true;
}

static bool process_dns_authority(
    struct inflight_dns_query* state,
    const struct dnshdr* header,
    struct cursor* body)
{
  return false;
}

static bool process_dns_additional(
    struct inflight_dns_query* state,
    const struct dnshdr* header,
    struct cursor* body)
{
  return false;
}

////////////////////////////////////////////////////////////////////////////////
// Process DNS Body
////////////////////////////////////////////////////////////////////////////////

static bool process_dns_body(
    struct inflight_dns_query* state,
    struct dnshdr* header,
    struct bpf_dynptr* body_ptr)
{
  struct cursor body = { body_ptr, 0 };
  if (!process_dns_questions(state, header, &body)) {
    return false;
  }
  if (!process_dns_answers(state, header, &body)) {
    return false;
  }

  // Not yet implemented:

  // if (!process_dns_authority(state, header, &body)) {
  //   return false;
  // }
  // if (!process_dns_additional(state, header, &body)) {
  //   return false;
  // }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// Process Raw Network Packet
////////////////////////////////////////////////////////////////////////////////

// `ip` is in network byte order
static inline bool is_localhost(u32 ip)
{
  return (ip & 0xFF) == 127;
}

int handle_packet(const char ie, struct __sk_buff* skb)
{
  void* data_end = (void*) (__u64) skb->data_end;
  void* data = (void*) (__u64) skb->data;

  if (skb->protocol != bpf_htons(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  // "Parse" ethernet header.
  struct ethhdr* ethernet_header;
  ethernet_header = data;
  if ((void*) (ethernet_header + 1) > data_end) {
    return TC_ACT_OK;
  }

  // "Parse" IP header
  struct iphdr* ip_header;
  ip_header = (struct iphdr*) (ethernet_header + 1);
  if ((void*) (ip_header + 1) > data_end) {
    return TC_ACT_OK;
  }

  if (ip_header->protocol != 0x11) {
    return TC_ACT_OK;
  }

  // Deduplicate requests/responses on localhost, only process on egress.
  if (ie == 'i' && (is_localhost(ip_header->saddr) && is_localhost(ip_header->daddr))) {
    return TC_ACT_OK;
  }

  // "Parse" UDP header.
  struct udphdr* udp_header;
  udp_header = ((void*) ip_header) + (ip_header->ihl * 4);
  if ((void*) (udp_header + 1) > data_end) {
    return TC_ACT_OK;
  }

  if (udp_header->source != bpf_htons(53) && udp_header->dest != bpf_htons(53)) {
    return TC_ACT_OK;
  }

  // "Parse" DNS header.
  struct dnshdr* dns_header = (struct dnshdr*) (udp_header + 1);
  if ((void*) (dns_header + 1) >= data_end) {
    return TC_ACT_OK;
  }

  void* dns_body = (void*) (dns_header + 1);
  size_t dns_body_len = data_end - (void*) dns_body;

  if ((void*) dns_body + dns_body_len > data_end) {
    return TC_ACT_OK;
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
      return TC_ACT_OK;
    }

    struct inflight_dns_query* state = bpf_map_lookup_elem(&query_state, &key);
    if (!state) {
      return TC_ACT_OK;
    }

    pid_t pid = bpf_get_current_pid_tgid();
    state->tid = pid;
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;
    state->pid = tgid;

    state->transaction_id = dns_header->id;
    state->start_time = bpf_ktime_get_ns();

    state->cgroup_id = bpf_get_current_cgroup_id();
    const char* cgroup_name = BPF_CORE_READ(cur_tsk, cgroups, subsys[memory_cgrp_id], cgroup, kn, name);
    if (bpf_probe_read_kernel_str(&state->cgroup, CGROUP_NAME_BUF_SIZE, cgroup_name) < 0) {
      bpf_map_delete_elem(&query_state, &key);
      return TC_ACT_OK;
    }

    u64 arg_start = BPF_CORE_READ(cur_tsk, mm, arg_start);
    u64 arg_end = BPF_CORE_READ(cur_tsk, mm, arg_end);
    u64 arg_len = arg_end - arg_start;

    if (!arg_start || !arg_end || arg_start >= arg_end) {
      return TC_ACT_OK;
    }

    u64 arg_copy_len = min(arg_len, COMMAND_BUF_SIZE);
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
      return TC_ACT_OK;
    }

    struct inflight_dns_query* state = bpf_map_lookup_elem(&query_state, &key);
    if (!state) {
      return TC_ACT_OK;
    }

    struct bpf_dynptr dyn_dns_body;
    if (bpf_dynptr_from_skb(skb, 0, &dyn_dns_body)) {
      return TC_ACT_OK;
    }
    if (bpf_dynptr_adjust(&dyn_dns_body, dns_body - data, data_end - data)) {
      return TC_ACT_OK;
    }

    // Process DNS response body.
    // Note: This formats strings into `state`. Ideally it would format directly into `out`, but
    // the verifier doesn't like that and I couldn't find a way to work around it.
    if (!process_dns_body(state, dns_header, &dyn_dns_body)) {
      bpf_map_delete_elem(&query_state, &key);
      return TC_ACT_OK;
    }

    // Build complete `struct dnsquery` output message.
    struct dns_query* out = bpf_ringbuf_reserve(&dns_queries_rb, sizeof(struct dns_query), 0);
    if (!out) {
      return TC_ACT_OK;
    }
    out->transaction_id = state->transaction_id;
    out->tid = state->tid;
    out->pid = state->pid;
    out->cgroup_id = state->cgroup_id;
    out->latency_ns = bpf_ktime_get_ns() - state->start_time;

    BPF_SNPRINTF(out->remote_ip, IP_BUF_SIZE, "%pI4", &ip_header->saddr);
    out->remote_port = bpf_ntohs(udp_header->source);

    BPF_SNPRINTF(out->local_ip, IP_BUF_SIZE, "%pI4", &ip_header->daddr);
    out->local_port = bpf_ntohs(udp_header->dest);

    bpf_probe_read_kernel_str(&out->domain_name, DOMAIN_NAME_BUF_SIZE, state->domain_name);
    bpf_probe_read_kernel(&out->resolved_addresses, IP_BUF_SIZE * 16, state->resolved_addresses);
    bpf_probe_read_kernel_str(&out->command, COMMAND_BUF_SIZE, state->command);
    bpf_probe_read_kernel_str(&out->cgroup_name, CGROUP_NAME_BUF_SIZE, state->cgroup);

    // Submit
    bpf_dbg_printk("[dnssnoop] Submitting DNS query result: %s", state->domain_name);
    bpf_ringbuf_submit(out, 0);

    // Remove query state.
    bpf_map_delete_elem(&query_state, &key);
  }

  return TC_ACT_OK;
}

////////////////////////////////////////////////////////////////////////////////
// Handlers
////////////////////////////////////////////////////////////////////////////////

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
