# spooftun

Linux UDP tunnel using raw Ethernet/IPv4 frames with configurable IP protocol numbers. AF_PACKET and AF_XDP forward application datagrams through userspace; TC rewrites a fixed peer's packets inside the kernel.

## Map

- [[Package and entry points]] — ownership and startup dispatch.
- [[Flows and sessions]] — application-to-wire path and return routing.
- [[Packet backends]] — I/O choices, resource ownership and parallelism.
- [[Design constraints]] — compatibility, buffer lifetimes and deployment limits.
- [[Development]] — commands, prerequisites and verification status.

These notes describe the inspected working tree on 2026-11-03, including the current AF_PACKET worker implementation. They summarize responsibilities rather than cataloging functions. Repository-relative source links work from this directory in an Obsidian vault rooted at the repository.

Sources: [README.md](../README.md), [main.go](../main.go), [go.mod](../go.mod).
