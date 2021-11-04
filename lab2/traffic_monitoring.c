/*
 * INFO:
 * 
 * 1. Create the RESTRICTED C
 *  1.1. The headers are available in the /usr/include/linux 
 *  1.2. Define the eBPF map, that will contain the count of pkts
 *       and the amount of traffic of L3.
 * 
 * 
 * 
 */ 

// Definition of struct __sk_buff, the
// parameter passed to our eBPF program
#include <linux/bpf.h> 

// Definition of valid return codes for eBPF
// programs attached to the TC hook (e.g.
// TC_ACT_OK)
#include <linux/pkt_cls.h> 

// Definition of struct ethhdr
#include <linux/if_ether.h>
// Definition of struct iphdr
#include <linux/ip.h> 
 // Definition of struct tcphdr
#include <linux/tcp.h>
 // Definition of struct udphdr
#include <linux/udp.h>

// 1.2. Define a structure containing the values for each entry of the map
struct l3proto_value {
    long count;
    long bytes;
} __attribute__((packed));
// __attribute__((packed)) guarantees that the compiler doesn't add padding
// inside the struct to optimize access. Padding can sometimes cause errors with
// the eBPF verifier.

// Define a hash map with key of type uint16_t (the size of the ethertype),
// value of type struct l3proto_value and a max size of 1024 elements
BPF_HASH(l3protos_counter, uint16_t, struct l3proto_value, 1024);

int monitor(struct __sk_buff *ctx) {
    // Retrieve pointers to the begin and end of the packet buffer
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Interpret the first part of the packet as an ethernet header
    struct ethhdr *eth = data;

    // Every time we access the packet buffer the eBPF verifier requires us to
    // explicitly check that the address we are accessing doesn't exceed the
    // buffer limits
    if (data + sizeof(*eth) > data_end) {
        // The packet is malformed, the TC_ACT_SHOT return code instructs the
        // kernel to drop it
        return TC_ACT_SHOT;
    }

    // Prepare a new entry for the map in case the protocol has not been added yet
    struct l3proto_value new_value = {
    .count = 0,
    .bytes = 0
    };

    // The lookup_or_try_init is syntactic sugar provided by BCC, it looks for
    // an element and if it doesn't exist creates a new entry and initializes it
    // with the value provided (internally it relies on the
    // bpf_map_lookup_elem() and bpf_map_update_elem() eBPF helpers)
    struct l3proto_value *value = l3protos_counter.lookup_or_try_init(&eth->h_proto, &new_value);
    
    // In the same way as with packet buffer every time we want to de-reference
    // a pointer the verifier requires us to check if it is valid (in this case
    // value could be NULL if the eBPF map was full)
    if (!value) {
        return TC_ACT_OK;
    }

    // Our eBPF program could be executed concurrently on multiple cores of the
    // machine, the __sync_fetch_and_add() instruction guarantees an atomic
    // operation
    __sync_fetch_and_add(&value->count, 1);
    __sync_fetch_and_add(&value->bytes, (data_end - data));

    // The bpf_trace_printk() helper can be used to print debug messages to the
    // kernel trace pipe. The pipe is accessible reading file
    // /sys/kernel/debug/tracing/trace_pipe. BCC provides the function
    // trace_readline() on the BPF object
    bpf_trace_printk("Processed packet with l3proto %d\n", ntohs(eth->h_proto));
    
    // The TC_ACT_OK return code lets the packet proceed up in the network stack
    // for ingress packets or out of a net device for egress ones
    return TC_ACT_OK;
}
