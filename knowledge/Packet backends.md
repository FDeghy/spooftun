# Packet backends

AF_PACKET and AF_XDP implement the receive/transmit contracts in [packet_io.go](../packet_io.go) and share [[Flows and sessions]]. Their wire formats are compatible; peers may choose different I/O backends.

| Backend | Packet path | Important limits |
| --- | --- | --- |
| AF_PACKET (default) | TPACKET_V3 mmap RX + classic BPF; batched `sendmmsg` or optional `PACKET_TX_RING` TX | Capture is a tap; Linux can also process matching frames. `CAP_NET_RAW` required. |
| AF_XDP | eBPF redirects matching traffic to per-RX-queue sockets/UMEM; Go parses and forwards it | Tries native zero-copy, native copy, then generic copy only for unsupported attach/bind errors. Permission/verifier/allocation errors fail startup. |
| TC | TCX eBPF rewrites/redirects between a dedicated veth and physical interface | Fixed IPv4 peer and application ports; Linux 6.6+; protocol 6 + fake TCP only. |

Sources: [packet_io.go](../packet_io.go), [tx.go](../tx.go), [tx_ring.go](../tx_ring.go), [xdp.go](../xdp.go), [kernel_tc.go](../kernel_tc.go), [bpf/tc.c](../bpf/tc.c).

## Worker and memory ownership

AF_PACKET accepts 1–64 receive workers. Each owns its RX ring, transmitter and delivery queue; `-ring-mb` is **per worker**. A kernel-allocated unique fanout group avoids sharing packets with another process. `flow` hashes the visible IPv4/port tuple, keeping one outer flow on one worker; `spread` distributes packets and can reorder delivery. Fanout sees the IP header before Ethernet restoration, unlike the normal capture filter. Client uplink remains one UDP reader/encoder/transmitter; server replies use the creating worker's transmitter. XDP and TC reject nondefault worker settings.

AF_XDP allocates 4 MiB UMEM per discovered RX queue, uses separate RX/TX pools, polls queues with one reader and serializes TX through the first queue. The single-buffer design caps interface MTU at 3826; live queue reconfiguration is unsupported. Hardware zero-copy execution is not established by the repository's veth tests.

Sources: [packet_workers.go](../packet_workers.go), [xdp.go](../xdp.go), [PACKET_BACKENDS.md](../PACKET_BACKENDS.md).

## TC ownership and endpoints

`runKernelTC` loads the embedded object, sets up owned veth/neighbor state, attaches programs and waits for signals. Applications use the synthetic peer (default `198.18.0.2`), not the client UDP listener. Both endpoints require fixed remote IPs; TC rejects noise, fake fragmentation and UDP GRO.

TC refuses existing conflicting attachments/routes and changes offloads only on its owned veths. SIGINT/SIGTERM detaches links and removes owned interfaces. SIGKILL can leave a veth: cleanup must identify the exact owned interface from its log. AF_XDP also refuses an existing XDP attachment. Do not replace unrelated owners.

Sources: [kernel_tc.go](../kernel_tc.go), [TC_BACKEND.md](../TC_BACKEND.md), [xdp.go](../xdp.go). See [[Design constraints]] and [[Development]].
