#!/bin/sh
# Regenerate the embedded little-endian eBPF object. clang with BPF target and
# Linux UAPI headers are build-time dependencies only. No libbpf or cgo needed.
set -eu
cd "$(dirname "$0")/.."
arch_include=${BPF_ARCH_INCLUDE:-/usr/include/$(uname -m)-linux-gnu}
"${CLANG:-clang}" -target bpfel -O2 -g -Wall -Wextra -Werror \
    -fdebug-prefix-map="$PWD"=. -I "$arch_include" \
    -c bpf/tc.c -o bpf/tc_bpfel.o
sha256sum bpf/tc.c bpf/tc_bpfel.o > bpf/tc.sha256
