#ifndef __MAPS_H__
#define __MAPS_H__

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#define MAX_STACK_ADDRESSES 1024 // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH 20 // max depth of each stack trace to track

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct {                                                        \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

// stack traces: the value is 1 big byte array of the stack addresses
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES); // store stack traces

struct makechan_event_key {
    int64_t goroutine_id;
    uint64_t ktime; // To make this struct unique
};

struct makechan_event {
    int stack_id;
    int chan_size;
};

BPF_HASH(makechan_events, struct makechan_event_key, struct makechan_event, 10240);

typedef enum {
    unknown_chansend = 0,
    chansend1 = 1,
    selectnbsend = 2,
    reflect_chansend = 3
} chansend_function;

struct chansend_event_key {
    int64_t goroutine_id;
    uint64_t ktime; // To make this struct unique
};

struct chansend_event {
    int stack_id;
    bool success;
    chansend_function function;
};

BPF_HASH(chansend_events, struct chansend_event_key, struct chansend_event, 10240);

typedef enum {
    unknown_chanrecv = 0,
    chanrecv1 = 1,
    chanrecv2 = 2
} chanrecv_function;

struct chanrecv_event_key {
    int64_t goroutine_id;
    uint64_t ktime; // To make this struct unique
};

struct chanrecv_event {
    int stack_id;
    bool selected;
    bool received;
    chanrecv_function function;
};

BPF_HASH(chanrecv_events, struct chanrecv_event_key, struct chanrecv_event, 10240);

struct closechan_event_key {
    int64_t goroutine_id;
    uint64_t ktime; // To make this struct unique
};

struct closechan_event {
    int stack_id;
};

BPF_HASH(closechan_events, struct closechan_event_key, struct closechan_event, 10240);

struct newproc1_event_key {
    int64_t goroutine_id;
    uint64_t ktime; // To make this struct unique
};

struct newproc1_event {
    int stack_id;
};

BPF_HASH(newproc1_events, struct newproc1_event_key, struct newproc1_event, 10240);

struct goexit1_event_key {
    int64_t goroutine_id;
    uint64_t ktime; // To make this struct unique
};

struct goexit1_event {
    int stack_id;
};

BPF_HASH(goexit1_events, struct goexit1_event_key, struct goexit1_event, 10240);

#endif /* __MAPS_H__ */
