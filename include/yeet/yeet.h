#ifndef YEET_H
#define YEET_H

#ifdef BPF_DEBUG
#define bpf_dbg_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_dbg_printk(fmt, args...)
#endif

#define EXPORT_BTF_STRUCT(struct_type)   \
  struct struct_type dummy_##struct_type \
      __attribute__((section("dummy"), unused)) = {0}

#define RINGBUF_CHANNEL(ringbuf_name, size, struct_type) \
  struct                                                 \
  {                                                      \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                  \
    __uint(max_entries, size);                           \
  } ringbuf_name SEC(".maps");                           \
  EXPORT_BTF_STRUCT(struct_type)

#define EXIT_FAILURE -1
#define EXIT_SUCCESS 0

#define ONES(x) ((1L << (x)) - 1)

#define LICENSE(license) char LICENSE[] SEC("license") = license;

#endif