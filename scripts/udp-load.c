// Linux UDP load generator for isolated-network performance measurements.
// Build: gcc -O2 -Wall -Wextra -Werror -o udp-load scripts/udp-load.c
// Receive: udp-load receive IP PORT   (SIGTERM prints the final JSON)
// Send:    udp-load send IP PORT PAYLOAD_SIZE DURATION_SECONDS RATE_MBPS
// Counts application payload bytes, excluding UDP/IP/Ethernet overhead.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

enum { MAX_PAYLOAD = 65507, RX_BUFFER = 65536, BATCH = 64,
       MAX_SEQUENCE = 16 * 1024 * 1024, SOCKET_BUFFER = 16 * 1024 * 1024 };
static volatile sig_atomic_t stopping;

static void on_signal(int number) { (void)number; stopping = 1; }

static int64_t monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

static void sleep_until(int64_t deadline) {
    struct timespec target = {deadline / INT64_C(1000000000),
                              deadline % INT64_C(1000000000)};
    int error;
    while (!stopping && (error = clock_nanosleep(CLOCK_MONOTONIC,
                                                TIMER_ABSTIME, &target, NULL))) {
        if (error != EINTR) {
            errno = error;
            perror("clock_nanosleep");
            exit(1);
        }
    }
}

static double number(const char *text, double minimum, double maximum) {
    char *end;
    errno = 0;
    double value = strtod(text, &end);
    if (errno || end == text || *end || !isfinite(value) ||
        value < minimum || value > maximum) {
        fprintf(stderr, "invalid numeric argument: %s\n", text);
        exit(2);
    }
    return value;
}

static int socket_buffer(int fd, int option) {
    int size = 0;
    socklen_t length = sizeof(size);
    if (getsockopt(fd, SOL_SOCKET, option, &size, &length) != 0) {
        perror("getsockopt buffer");
        exit(1);
    }
    return size;
}

static int open_socket(const char *ip, const char *port_text, bool receiver) {
    double port_number = number(port_text, 1, 65535);
    int port = (int)port_number;
    if ((double)port != port_number) {
        fprintf(stderr, "port must be an integer\n");
        exit(2);
    }
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        fprintf(stderr, "expected an IPv4 address: %s\n", ip);
        exit(2);
    }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    int size = SOCKET_BUFFER;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0) {
        perror("setsockopt buffer");
        exit(1);
    }
    // Keep shutdown bounded if a signal arrives just before a blocking syscall.
    struct timeval timeout = {.tv_usec = 100000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("setsockopt timeout");
        exit(1);
    }
    int result = receiver ? bind(fd, (struct sockaddr *)&address, sizeof(address))
                          : connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (result != 0) { perror(receiver ? "bind" : "connect"); exit(1); }
    return fd;
}

static void content(unsigned char *data, size_t size) {
    for (size_t i = 8; i < size; i++) data[i] = (unsigned char)(i * 31 + 7);
}

static int send_load(int fd, size_t size, double seconds, double rate_mbps) {
    size_t segments = MAX_PAYLOAD / size;
    if (segments > BATCH) segments = BATCH;
    size_t length = segments * size;
    unsigned char *data = malloc(length);
    if (!data) { perror("malloc send"); return 1; }
    struct iovec vectors[BATCH] = {0};
    struct mmsghdr messages[BATCH] = {0};
    for (size_t i = 0; i < segments; i++) {
        content(data + i * size, size);
        vectors[i].iov_base = data + i * size;
        vectors[i].iov_len = size;
        messages[i].msg_hdr.msg_iov = &vectors[i];
        messages[i].msg_hdr.msg_iovlen = 1;
    }
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(uint16_t))];
    } control = {0};
    struct iovec aggregate = {.iov_base = data, .iov_len = length};
    struct msghdr gso_message = {.msg_iov = &aggregate, .msg_iovlen = 1,
                                .msg_control = control.bytes,
                                .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *segment = CMSG_FIRSTHDR(&gso_message);
    segment->cmsg_level = IPPROTO_UDP;
    segment->cmsg_type = UDP_SEGMENT;
    segment->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t segment_size = (uint16_t)size;
    memcpy(CMSG_DATA(segment), &segment_size, sizeof(segment_size));

    bool gso = true;
    bool failed = false;
    uint64_t sent = 0;
    int64_t start = monotonic_ns();
    int64_t finish = start + (int64_t)(seconds * 1e9);
    int64_t next = start;
    int64_t interval = (int64_t)((double)length * 8e3 / rate_mbps);
    if (interval < 1) interval = 1;
    while (!stopping && monotonic_ns() < finish) {
        if (sent + segments > MAX_SEQUENCE) {
            fprintf(stderr, "sender sequence limit (%d) exceeded\n", MAX_SEQUENCE);
            failed = true;
            break;
        }
        for (size_t i = 0; i < segments; i++) {
            uint64_t sequence = htobe64(sent + i);
            memcpy(data + i * size, &sequence, sizeof(sequence));
            messages[i].msg_len = 0;
        }
        size_t accepted = 0;
        if (gso) {
            ssize_t result;
            do { result = sendmsg(fd, &gso_message, MSG_NOSIGNAL); }
            while (result < 0 && errno == EINTR && !stopping);
            if (result == (ssize_t)length) {
                accepted = segments;
            } else if (result < 0 && (errno == EINVAL || errno == ENOPROTOOPT ||
                                      errno == EOPNOTSUPP || errno == EIO)) {
                gso = false;
            } else {
                if (result < 0) perror("sendmsg UDP_SEGMENT");
                else fprintf(stderr, "short UDP_SEGMENT send\n");
                failed = !stopping;
                break;
            }
        }
        while (!gso && accepted < segments && !stopping) {
            int count = sendmmsg(fd, messages + accepted, segments - accepted,
                                 MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                if (count < 0) perror("sendmmsg");
                else fprintf(stderr, "sendmmsg made no progress\n");
                failed = true;
                break;
            }
            for (int i = 0; i < count; i++) {
                if (messages[accepted + (size_t)i].msg_len != size) {
                    fprintf(stderr, "short UDP sendmmsg datagram\n");
                    failed = true;
                }
            }
            accepted += (size_t)count;
        }
        sent += accepted;
        if (failed) break;
        next += interval;
        int64_t now = monotonic_ns();
        // Permit at most one batch of catch-up after scheduling delays.
        if (next < now - interval) next = now;
        if (next > finish) next = finish;
        if (next > now) sleep_until(next);
    }
    double elapsed = (double)(monotonic_ns() - start) / 1e9;
    printf("{\"role\":\"sender\",\"status\":\"%s\",\"sent_datagrams\":%" PRIu64
           ",\"sent_bytes\":%" PRIu64 ",\"duration_seconds\":%.9f,"
           "\"send_mbps\":%.6f,\"requested_mbps\":%.6f,\"payload_bytes\":%zu,"
           "\"batch_datagrams\":%zu,\"gso\":%s,\"socket_rcvbuf\":%d,"
           "\"socket_sndbuf\":%d}\n",
           failed ? "failed" : "passed", sent, sent * size, elapsed,
           (double)sent * size * 8 / elapsed / 1e6, rate_mbps, size, segments,
           gso ? "true" : "false", socket_buffer(fd, SO_RCVBUF),
           socket_buffer(fd, SO_SNDBUF));
    free(data);
    return failed ? 1 : 0;
}

static int receive_load(int fd) {
    int enabled = 1;
    bool gro = setsockopt(fd, IPPROTO_UDP, UDP_GRO, &enabled, sizeof(enabled)) == 0;
    if (!gro && errno != ENOPROTOOPT && errno != EINVAL && errno != EOPNOTSUPP) {
        perror("setsockopt UDP_GRO");
        return 1;
    }
    unsigned char *data = malloc((size_t)BATCH * RX_BUFFER);
    unsigned char *seen = calloc(MAX_SEQUENCE / 8, 1);
    unsigned char *expected = malloc(MAX_PAYLOAD);
    if (!data || !seen || !expected) { perror("malloc receive"); return 1; }
    content(expected, MAX_PAYLOAD);
    struct iovec vectors[BATCH] = {0};
    struct mmsghdr messages[BATCH] = {0};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control[BATCH];
    for (size_t i = 0; i < BATCH; i++) {
        vectors[i].iov_base = data + i * RX_BUFFER;
        vectors[i].iov_len = RX_BUFFER;
        messages[i].msg_hdr.msg_iov = &vectors[i];
        messages[i].msg_hdr.msg_iovlen = 1;
        messages[i].msg_hdr.msg_control = control[i].bytes;
    }
    uint64_t packets = 0, bytes = 0, duplicates = 0, out_of_order = 0;
    uint64_t corrupt = 0, overflows = 0, highest = 0;
    size_t payload_size = 0;
    bool failed = false;
    int64_t first = 0, last = 0, start = monotonic_ns();
    while (!stopping) {
        for (size_t i = 0; i < BATCH; i++) {
            messages[i].msg_hdr.msg_controllen = sizeof(control[i].bytes);
            messages[i].msg_hdr.msg_flags = 0;
        }
        int count = recvmmsg(fd, messages, BATCH, MSG_WAITFORONE, NULL);
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvmmsg");
            failed = true;
            break;
        }
        int64_t now = monotonic_ns();
        for (int i = 0; i < count; i++) {
            struct msghdr *message = &messages[i].msg_hdr;
            if (message->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
                corrupt++;
                continue;
            }
            size_t total = messages[i].msg_len;
            size_t segment_size = total;
            for (struct cmsghdr *c = CMSG_FIRSTHDR(message); c;
                 c = CMSG_NXTHDR(message, c)) {
                if (c->cmsg_level == IPPROTO_UDP && c->cmsg_type == UDP_GRO) {
                    int value = 0;
                    if (c->cmsg_len < CMSG_LEN(sizeof(value))) {
                        segment_size = 0;
                        break;
                    }
                    memcpy(&value, CMSG_DATA(c), sizeof(value));
                    segment_size = value > 0 ? (size_t)value : 0;
                }
            }
            if (!segment_size || segment_size > MAX_PAYLOAD || !total) {
                corrupt++;
                continue;
            }
            for (size_t offset = 0; offset < total; offset += segment_size) {
                size_t size = total - offset;
                if (size > segment_size) size = segment_size;
                unsigned char *packet = data + (size_t)i * RX_BUFFER + offset;
                if (size < 8 || (payload_size && size != payload_size) ||
                    memcmp(packet + 8, expected + 8, size - 8)) {
                    corrupt++;
                    continue;
                }
                uint64_t sequence;
                memcpy(&sequence, packet, sizeof(sequence));
                sequence = be64toh(sequence);
                if (sequence >= MAX_SEQUENCE) {
                    overflows++;
                    stopping = 1;
                    continue;
                }
                unsigned char mask = (unsigned char)(1u << (sequence & 7));
                if (seen[sequence / 8] & mask) { duplicates++; continue; }
                seen[sequence / 8] |= mask;
                if (packets && sequence < highest) out_of_order++;
                if (!packets || sequence > highest) highest = sequence;
                if (!packets) first = now;
                last = now;
                payload_size = size;
                packets++;
                bytes += size;
            }
        }
    }
    double elapsed = (double)(monotonic_ns() - start) / 1e9;
    double active = packets ? (double)(last - first) / 1e9 : 0;
    uint64_t missing = packets ? highest + 1 - packets : 0;
    failed = failed || corrupt || overflows;
    if (overflows) fprintf(stderr, "receiver sequence limit (%d) exceeded\n", MAX_SEQUENCE);
    if (corrupt) fprintf(stderr, "receiver found %" PRIu64 " corrupt datagrams/messages\n", corrupt);
    printf("{\"role\":\"receiver\",\"status\":\"%s\",\"received_datagrams\":%" PRIu64
           ",\"received_bytes\":%" PRIu64 ",\"duplicates\":%" PRIu64
           ",\"out_of_order\":%" PRIu64 ",\"corrupt\":%" PRIu64
           ",\"sequence_overflows\":%" PRIu64 ",\"missing_through_highest\":%" PRIu64
           ",\"duration_seconds\":%.9f,\"active_seconds\":%.9f,\"payload_bytes\":%zu,"
           "\"gro\":%s,\"socket_rcvbuf\":%d,\"socket_sndbuf\":%d}\n",
           failed ? "failed" : "passed", packets, bytes, duplicates, out_of_order,
           corrupt, overflows, missing, elapsed, active, payload_size,
           gro ? "true" : "false", socket_buffer(fd, SO_RCVBUF),
           socket_buffer(fd, SO_SNDBUF));
    free(expected);
    free(seen);
    free(data);
    return failed ? 1 : 0;
}

int main(int argc, char **argv) {
    bool receiver = argc == 4 && strcmp(argv[1], "receive") == 0;
    bool sender = argc == 7 && strcmp(argv[1], "send") == 0;
    if (!receiver && !sender) {
        fprintf(stderr, "usage: %s receive IP PORT\n"
                        "       %s send IP PORT PAYLOAD_SIZE DURATION_SECONDS RATE_MBPS\n",
                argv[0], argv[0]);
        return 2;
    }
    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) {
        perror("sigaction");
        return 1;
    }
    int fd = open_socket(argv[2], argv[3], receiver);
    int result;
    if (receiver) {
        result = receive_load(fd);
    } else {
        double size = number(argv[4], 8, MAX_PAYLOAD);
        if (size != (size_t)size) {
            fprintf(stderr, "payload size must be an integer\n");
            return 2;
        }
        result = send_load(fd, (size_t)size, number(argv[5], 0.001, 86400),
                           number(argv[6], 0.001, 1000000));
    }
    close(fd);
    return result;
}
