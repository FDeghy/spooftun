// SPDX-License-Identifier: MIT
// Fixed-peer kernel forwarding. Input on the owned veth must already have
// software segmentation and checksum completion; the loader enforces this.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline
#define NEXT (-1)
#define DROP 2
#define MAX_IP_LEN 1500
#define ntohs(x) __builtin_bswap16((__u16)(x))
#define htons(x) __builtin_bswap16((__u16)(x))
#define ntohl(x) __builtin_bswap32((__u32)(x))
#define htonl(x) __builtin_bswap32((__u32)(x))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

struct settings {
    __u32 local_ip, peer_ip, wire_local_ip, wire_src_ip, wire_peer_ip;
    __u32 wire_peer_src, physical_ifindex, veth_ifindex, mtu, tx_flags;
    __u16 local_port, remote_port, wire_local_port, wire_remote_port;
    __u8 wire_dst_mac[6], wire_src_mac[6], local_dst_mac[6], local_src_mac[6];
};
struct tcp_header {
    __u16 source, dest;
    __u32 seq, ack;
    __u8 offset, flags;
    __u16 window, check, urgent;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct settings);
} config SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*pull_data)(struct __sk_buff *, __u32) = (void *)BPF_FUNC_skb_pull_data;
static long (*adjust_room)(struct __sk_buff *, __s32, __u32, __u64) = (void *)BPF_FUNC_skb_adjust_room;
static long (*store_bytes)(struct __sk_buff *, __u32, const void *, __u32, __u64) = (void *)BPF_FUNC_skb_store_bytes;
static long (*redirect)(__u32, __u64) = (void *)BPF_FUNC_redirect;

INLINE void count(__u32 index) {
    __u64 *value = map_lookup(&stats, &index);
    if (value) (*value)++;
}
INLINE int dropped(void) { count(2); return DROP; }
INLINE __u32 fold(__u32 sum) {
    sum = (sum & 65535) + (sum >> 16);
    return (sum & 65535) + (sum >> 16);
}
INLINE __u32 address_sum(__u32 address) {
    __u32 value = ntohl(address);
    return (value >> 16) + (value & 65535);
}
INLINE __u16 ip_checksum(struct iphdr *ip) {
    __u32 sum = 0;
    __u8 *p = (__u8 *)ip;
#pragma clang loop unroll(full)
    for (int i = 0; i < 20; i += 2) sum += ((__u32)p[i] << 8) + p[i + 1];
    return htons(~fold(sum));
}
// Input is linearized only after the narrow tuple match. The limit keeps
// verifier work and malformed-input CPU bounded. Odd final bytes are padded.
INLINE int payload_sum(struct __sk_buff *skb, __u32 start, __u32 length, __u32 *sum) {
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    if (length > MAX_IP_LEN || start > 54) return -1;
    __u32 result = 0;
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_IP_LEN / 2; i++) {
        __u32 offset = i * 2;
        if (offset >= length) break;
        __u8 *p = data + start + offset;
        if ((void *)(p + 1) > end) return -1;
        result += (__u32)p[0] << 8;
        if (offset + 1 < length) {
            if ((void *)(p + 2) > end) return -1;
            result += p[1];
        }
    }
    *sum = result;
    return 0;
}
INLINE int rewrite(struct __sk_buff *skb, int outgoing) {
    __u32 zero = 0;
    struct settings *c = map_lookup(&config, &zero);
    if (!c) return NEXT;
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + ETH_HLEN;
    if ((void *)(ip + 1) > end || eth->h_proto != htons(ETH_P_IP) || ip->version != 4) return NEXT;
    if (ip->protocol != (outgoing ? 17 : 6)) return NEXT;
    if (ip->saddr != (outgoing ? c->local_ip : c->wire_peer_src) ||
        ip->daddr != (outgoing ? c->peer_ip : c->wire_local_ip)) return NEXT;
    // Noninitial fragments have no ports: preserve unrelated fragmented TCP.
    // A selected first fragment is dropped below, preventing its reassembly.
    if (ip->frag_off & htons(0x1fff)) return NEXT;
    __u32 ihl = (__u32)ip->ihl * 4;
    if (ihl < 20 || ihl > 60) return dropped();
    struct udphdr *ports = data + ETH_HLEN + ihl;
    if ((void *)(ports + 1) > end) return dropped();
    if (ports->source != (outgoing ? c->local_port : c->wire_remote_port) ||
        ports->dest != (outgoing ? c->remote_port : c->wire_local_port)) return NEXT;
    if (ip->frag_off & htons(0x2000)) return dropped();
    __u32 total = ntohs(ip->tot_len);
    if (ihl != 20 || c->mtu > MAX_IP_LEN || c->mtu < 40 || skb->gso_segs > 1 ||
        total < (outgoing ? 28 : 40) || total > c->mtu ||
        (outgoing && total + 12 > c->mtu) || skb->len < ETH_HLEN + total)
        return dropped();
    // Only make headers writable on the normal path. Payload pages can remain
    // nonlinear because checksum conversion touches no payload bytes.
    if (pull_data(skb, outgoing ? 42 : 54)) return dropped();
    data = (void *)(long)skb->data;
    end = (void *)(long)skb->data_end;
    ip = data + ETH_HLEN;
    if ((void *)(ip + 1) > end) return dropped();
    struct iphdr header = *ip;
    if (ip_checksum(&header) != 0) return dropped();
    __u32 payload = 0, length = total - (outgoing ? 28 : 40);
    if (outgoing) {
        struct udphdr *udp = data + 34;
        if ((void *)(udp + 1) > end || ntohs(udp->len) != total - 20) return dropped();
        if (udp->check) {
            // Complete UDP checksum minus its pseudoheader and UDP header.
            // Ones-complement subtraction preserves the payload sum without
            // visiting payload bytes for normal kernel UDP/WireGuard traffic.
            __u32 removed = address_sum(header.saddr) + address_sum(header.daddr) +
                17 + 2 * (total - 20) + ntohs(udp->source) + ntohs(udp->dest);
            payload = ((~ntohs(udp->check)) & 65535) + ((~fold(removed)) & 65535);
        } else {
            // UDP without a checksum has no payload sum to reuse.
            if (pull_data(skb, 0) || payload_sum(skb, 42, length, &payload)) return dropped();
        }
    } else {
        struct tcp_header *tcp = data + 34;
        if ((void *)(tcp + 1) > end || tcp->offset != 0x50) return dropped();
        // Subtract the old pseudoheader and checksum-free TCP header from
        // the existing checksum. This preserves any checksum error rather
        // than recomputing a valid checksum over potentially corrupted data.
        // adjust_room below clears CHECKSUM_UNNECESSARY; stores maintain
        // CHECKSUM_COMPLETE, and the restored UDP checksum is always enabled.
        // Thus UDP socket validation rejects invalid incoming TCP checksums.
        __u32 removed = 0;
        __u8 *p = (__u8 *)tcp;
#pragma clang loop unroll(full)
        for (int i = 0; i < 20; i += 2) {
            if (i != 16) removed += ((__u32)p[i] << 8) + p[i + 1];
        }
        removed += address_sum(header.saddr) + address_sum(header.daddr) + 6 + total - 20;
        payload = ((~ntohs(tcp->check)) & 65535) + ((~fold(removed)) & 65535);
    }
    if (adjust_room(skb, outgoing ? 12 : -12, BPF_ADJ_ROOM_NET, 0)) return dropped();
    header.tot_len = htons(outgoing ? total + 12 : total - 12);
    header.protocol = outgoing ? 6 : 17;
    header.saddr = outgoing ? c->wire_src_ip : c->peer_ip;
    header.daddr = outgoing ? c->wire_peer_ip : c->local_ip;
    header.check = 0;
    header.check = ip_checksum(&header);
    struct ethhdr ethernet = {.h_proto = htons(ETH_P_IP)};
    __builtin_memcpy(ethernet.h_dest, outgoing ? c->wire_dst_mac : c->local_dst_mac, 6);
    __builtin_memcpy(ethernet.h_source, outgoing ? c->wire_src_mac : c->local_src_mac, 6);
    if (store_bytes(skb, 0, &ethernet, sizeof(ethernet), BPF_F_RECOMPUTE_CSUM) ||
        store_bytes(skb, 14, &header, sizeof(header), BPF_F_RECOMPUTE_CSUM)) return dropped();
    __u32 sum = payload + address_sum(header.saddr) + address_sum(header.daddr);
    if (outgoing) {
        struct tcp_header tcp = {.source = c->wire_local_port, .dest = c->wire_remote_port,
            .seq = htonl(1), .offset = 0x50, .flags = c->tx_flags, .window = htons(65535)};
        sum += 6 + length + 20 + ntohs(tcp.source) + ntohs(tcp.dest) + 1 +
            0x5000 + tcp.flags + 65535;
        tcp.check = htons(~fold(sum));
        if (store_bytes(skb, 34, &tcp, sizeof(tcp), BPF_F_RECOMPUTE_CSUM)) return dropped();
    } else {
        struct udphdr udp = {.source = c->remote_port, .dest = c->local_port,
            .len = htons(length + 8)};
        sum += 17 + 2 * (length + 8) + ntohs(udp.source) + ntohs(udp.dest);
        udp.check = htons(~fold(sum));
        if (!udp.check) udp.check = 65535;
        if (store_bytes(skb, 34, &udp, sizeof(udp), BPF_F_RECOMPUTE_CSUM)) return dropped();
    }
    count(outgoing ? 0 : 1);
    return redirect(outgoing ? c->physical_ifindex : c->veth_ifindex, 0);
}
SEC("tc") int tc_out(struct __sk_buff *skb) { return rewrite(skb, 1); }
SEC("tc") int tc_in(struct __sk_buff *skb) { return rewrite(skb, 0); }
char tc_license[] SEC("license") = "MIT";
