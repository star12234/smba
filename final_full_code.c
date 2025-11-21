/*
 * smb_live_named.c
 *
 * [Fixed Version]
 * - Missing SMB1 enum definitions added.
 * - Parses SMB2 CREATE to restore filenames.
 * - Captures live traffic.
 *
 * Compile: gcc -o smb_named smb_live_named.c -lpcap
 * Usage:   sudo ./smb_named <interface> <output_dir>
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Connection key identifying one SMB TCP connection. */
typedef struct conn_key {
    uint32_t cli_ip;
    uint16_t cli_port;
    uint32_t srv_ip;
    uint16_t srv_port;
} conn_key_t;

/* State for one direction of a TCP stream. */
typedef struct tcp_stream {
    uint32_t next_seq;
    int has_next_seq;
} tcp_stream_t;

/* Forward declaration */
typedef struct connection connection_t;

/* Pending SMB2 READ request */
typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;
    uint32_t length;
    struct pending_read *next;
} pending_read_t;

/* Pending SMB2 CREATE request */
typedef struct pending_create {
    uint64_t msg_id;
    char *name;
    struct pending_create *next;
} pending_create_t;

/* FileId to Filename Mapping */
typedef struct file_name_map {
    uint8_t file_id[16];
    char *name;
    struct file_name_map *next;
} file_name_map_t;

/* SMB stream state */
typedef struct smb_stream {
    uint8_t *buf;
    size_t buf_len;
    size_t buf_cap;
    pending_read_t *pending;
} smb_stream_t;

/* Connection Context */
struct connection {
    conn_key_t key;
    tcp_stream_t tcp[2];      /* [0]=client->server, [1]=server->client */
    smb_stream_t smb[2];
    pending_create_t *pending_creates;
    file_name_map_t *file_names;
    struct connection *next;
};

static connection_t *connections = NULL;

/* Open File Context */
typedef struct file_ctx {
    uint8_t file_id[16];
    FILE *fp;
    struct file_ctx *next;
} file_ctx_t;

static file_ctx_t *open_files = NULL;
static char *output_dir = NULL;

/* [FIXED] Missing SMB1 definitions added here */
enum smb1_commands {
    SMB1_COM_WRITE       = 0x0B,
    SMB1_COM_WRITE_ANDX  = 0x2F
};

/* SMB2 definitions */
enum smb2_commands {
    SMB2_CREATE = 0x0005,
    SMB2_READ   = 0x0008,
    SMB2_WRITE  = 0x0009
};

static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

/* Utility Functions */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

static connection_t *get_connection(const conn_key_t *key) {
    connection_t *c;
    for (c = connections; c; c = c->next) {
        if (conn_key_equal(&c->key, key))
            return c;
    }
    c = (connection_t *)calloc(1, sizeof(connection_t));
    if (!c) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    c->key = *key;
    c->next = connections;
    connections = c;
    return c;
}

static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed) return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) exit(EXIT_FAILURE);
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

static char *utf16le_to_utf8(const uint8_t *data, size_t byte_len) {
    size_t char_count = byte_len / 2;
    char *out = (char *)calloc(char_count + 1, 1);
    if (!out) return NULL;
    for (size_t i = 0; i < char_count; i++) {
        out[i] = (char)data[i * 2];
    }
    out[char_count] = '\0';
    return out;
}

static void sanitize_path(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    int skip_leading = 1;
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        char c = in[i];
        if (c == '\\') c = '/';
        if (i == 1 && in[1] == ':' ) continue;
        if (skip_leading && (c == '/' || c == '\\')) continue;
        skip_leading = 0;
        if (c == '.' && in[i + 1] == '.' ) {
            i += 1;
            if (in[i + 1] == '/' || in[i + 1] == '\\') i++;
            continue;
        }
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            continue;
        out[j++] = c;
    }
    out[j] = '\0';
}

static void ensure_parent_dirs(const char *full_path) {
    char tmp[1024];
    size_t len = strlen(full_path);
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, full_path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
}

static void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    file_ctx_t *ctx;
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0) break;
    }
    if (!ctx) {
        char path[1024];
        const file_name_map_t *m;
        const char *name = NULL;
        for (m = connections ? connections->file_names : NULL; m; m = m->next) {
            if (memcmp(m->file_id, file_id, 16) == 0) {
                name = m->name;
                break;
            }
        }
        if (name) {
            snprintf(path, sizeof(path), "%s/%s", output_dir, name);
            ensure_parent_dirs(path);
        } else {
            char hexname[33];
            for (int i = 0; i < 16; i++) sprintf(&hexname[i * 2], "%02x", file_id[i]);
            snprintf(path, sizeof(path), "%s/%s.bin", output_dir, hexname);
        }
        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        memcpy(ctx->file_id, file_id, 16);
        ctx->fp = fopen(path, "wb");
        if (!ctx->fp) {
            fprintf(stderr, "Failed to open %s\n", path);
            free(ctx);
            return;
        }
        printf("[INFO] Created new file: %s\n", path + strlen(output_dir) + 1);
        ctx->next = open_files;
        open_files = ctx;
    }
    fseeko(ctx->fp, (off_t)offset, SEEK_SET);
    fwrite(data, 1, len, ctx->fp);
    fflush(ctx->fp);
}

static void record_pending_read(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 48) return;
    uint32_t length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t offset = 0;
    for (int i = 0; i < 8; i++) offset |= ((uint64_t)body[8 + i]) << (8 * i);
    const uint8_t *file_id = body + 24;
    pending_read_t *pr = (pending_read_t *)calloc(1, sizeof(pending_read_t));
    if (!pr) return;
    pr->msg_id = msg_id;
    memcpy(pr->file_id, file_id, 16);
    pr->offset = offset;
    pr->length = length;
    pr->next = conn->smb[0].pending;
    conn->smb[0].pending = pr;
}

static void handle_read_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 16) return;
    uint16_t data_offset = body[2] | (body[3] << 8);
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    if (data_offset < 64) return;
    size_t data_start = (size_t)data_offset - 64;
    if (len < data_start + data_length) return;
    pending_read_t **prev_ptr = &conn->smb[0].pending;
    pending_read_t *pr = conn->smb[0].pending;
    while (pr) {
        if (pr->msg_id == msg_id) break;
        prev_ptr = &pr->next;
        pr = pr->next;
    }
    if (!pr) return;
    *prev_ptr = pr->next;
    write_file_chunk(pr->file_id, pr->offset, body + data_start, data_length);
    free(pr);
}

static void record_pending_create(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    /* Note: Standard SMB2 NameOffset is usually at 44, but some versions use 48.
     * If filename is not detected, try changing 44 to 48. */
    if (len < 52) return;
    
    /* Using 44 as standard offset (Header included). */
    /* If this fails, change body[44/45] to body[48/49] */
    uint16_t name_offset = body[44] | (body[45] << 8);
    uint16_t name_length = body[46] | (body[47] << 8);
    
    if (name_length == 0) return;
    if (name_offset < 64) return;
    size_t rel = (size_t)name_offset - 64;
    if (rel + name_length > len) return;
    const uint8_t *name_utf16 = body + rel;
    char *utf8 = utf16le_to_utf8(name_utf16, name_length);
    if (!utf8) return;
    
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t));
    if (!pc) { free(utf8); return; }
    pc->msg_id = msg_id;
    pc->name = utf8;
    pc->next = conn->pending_creates;
    conn->pending_creates = pc;
}

static void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name) {
    file_name_map_t *m;
    for (m = conn->file_names; m; m = m->next) {
        if (memcmp(m->file_id, file_id, 16) == 0) return;
    }
    char safe[512];
    sanitize_path(orig_name, safe, sizeof(safe));
    m = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    if (!m) return;
    memcpy(m->file_id, file_id, 16);
    m->name = strdup(safe);
    if (!m->name) { free(m); return; }
    m->next = conn->file_names;
    conn->file_names = m;
}

static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    pending_create_t **prev_ptr = &conn->pending_creates;
    pending_create_t *pc = conn->pending_creates;
    while (pc) {
        if (pc->msg_id == msg_id) break;
        prev_ptr = &pc->next;
        pc = pc->next;
    }
    if (!pc) return;
    if (len < 80) return;
    const uint8_t *file_id = body + 64;
    remember_file_name(conn, file_id, pc->name);
    *prev_ptr = pc->next;
    free(pc->name);
    free(pc);
}

static void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        if (len - offset < 64) break;
        const uint8_t *hdr = msg + offset;
        if (!(hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B')) break;
        uint16_t command = hdr[12] | (hdr[13] << 8);
        uint32_t flags = hdr[16] | (hdr[17] << 8) | (hdr[18] << 16) | (hdr[19] << 24);
        uint32_t next_cmd = hdr[20] | (hdr[21] << 8) | (hdr[22] << 16) | (hdr[23] << 24);
        uint64_t msg_id = 0;
        for (int i = 0; i < 8; i++) msg_id |= ((uint64_t)hdr[24 + i]) << (8 * i);
        int is_response = (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0;
        size_t body_len;
        if (next_cmd == 0) {
            body_len = (len > offset + 64) ? len - offset - 64 : 0;
        } else {
            if (next_cmd < 64 || offset + next_cmd > len) break;
            body_len = next_cmd - 64;
        }
        const uint8_t *body = hdr + 64;
        if (!is_response) {
            if (command == SMB2_READ && dir == 0) {
                record_pending_read(conn, msg_id, body, body_len);
            } else if (command == SMB2_WRITE && dir == 0) {
                if (body_len >= 32) {
                    uint16_t data_offset = body[2] | (body[3] << 8);
                    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
                    uint64_t file_offset = 0;
                    for (int i = 0; i < 8; i++) file_offset |= ((uint64_t)body[8 + i]) << (8 * i);
                    const uint8_t *file_id = body + 24;
                    if (data_offset >= 64) {
                        size_t data_start = (size_t)data_offset - 64;
                        if (body_len >= data_start + data_length) {
                            write_file_chunk(file_id, file_offset, body + data_start, data_length);
                        }
                    }
                }
            } else if (command == SMB2_CREATE && dir == 0) {
                record_pending_create(conn, msg_id, body, body_len);
            }
        } else {
            if (command == SMB2_READ && dir == 1) {
                handle_read_response(conn, msg_id, body, body_len);
            } else if (command == SMB2_CREATE && dir == 1) {
                handle_create_response(conn, msg_id, body, body_len);
            }
        }
        if (next_cmd == 0) break;
        offset += next_cmd;
    }
}

static void create_file_id_smb1(const connection_t *conn, uint16_t fid, uint8_t file_id[16]) {
    memset(file_id, 0, 16);
    file_id[0] = (uint8_t)(fid & 0xFF);
    file_id[1] = (uint8_t)((fid >> 8) & 0xFF);
    memcpy(&file_id[2], &conn->key.cli_ip, 4);
    uint16_t cli_port = htons(conn->key.cli_port);
    memcpy(&file_id[6], &cli_port, 2);
    memcpy(&file_id[8], &conn->key.srv_ip, 4);
    uint16_t srv_port = htons(conn->key.srv_port);
    memcpy(&file_id[12], &srv_port, 2);
}

static void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    if (len < 32) return;
    if (!(msg[0] == 0xFF && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B')) return;
    uint8_t command = msg[4];
    if (len < 33) return;
    uint8_t word_count = msg[32];
    const uint8_t *params = msg + 33;
    size_t params_len = (size_t)word_count * 2;
    if (len < 33 + params_len + 2) return;
    uint16_t byte_count = params[params_len] | (params[params_len + 1] << 8);
    const uint8_t *data_base = params + params_len + 2;
    if (data_base + byte_count > msg + len) return;
    if (dir != 0) return;
    if (command == SMB1_COM_WRITE_ANDX) {
        if (word_count < 12) return;
        uint16_t fid = params[6] | (params[7] << 8);
        uint16_t data_length = params[16] | (params[17] << 8);
        uint16_t data_offset = params[18] | (params[19] << 8);
        if (data_length == 0 || data_offset >= len) return;
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(file_id, 0, msg + data_offset, data_length);
    } else if (command == SMB1_COM_WRITE) {
        if (word_count < 5) return;
        uint16_t fid = params[0] | (params[1] << 8);
        uint16_t count = params[2] | (params[3] << 8);
        if (count == 0) return;
        size_t data_len = (count > byte_count) ? byte_count : count;
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(file_id, 0, data_base, data_len);
    }
}

static void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
    size_t pos = 0;
    while (s->buf_len - pos >= 4) {
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        if (s->buf_len - pos < total_len) break;
        const uint8_t *msg = s->buf + pos + 4;
        size_t msg_len = nbss_len;
        if (msg_len >= 4) {
            if (msg[0] == 0xFE) {
                parse_smb2_message(conn, dir, msg, msg_len);
            } else if (msg[0] == 0xFF) {
                parse_smb1_message(conn, dir, msg, msg_len);
            }
        }
        pos += total_len;
    }
    if (pos > 0) {
        memmove(s->buf, s->buf + pos, s->buf_len - pos);
        s->buf_len -= pos;
    }
}

static void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) {
    tcp_stream_t *ts = &conn->tcp[dir];
    if (len == 0) return;
    if (!ts->has_next_seq) {
        ts->next_seq = seq + len;
        ts->has_next_seq = 1;
        smb_feed_bytes(conn, dir, payload, len);
        return;
    }
    if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb_feed_bytes(conn, dir, payload, len);
    }
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen < 14) return;
    size_t offset = 14;
    uint16_t eth_type = (bytes[12] << 8) | bytes[13];
    if (eth_type == 0x8100 && h->caplen >= 18) {
        offset += 4;
        eth_type = (bytes[offset - 2] << 8) | bytes[offset - 1];
    }
    if (eth_type != 0x0800) return;
    const struct ip *ip = (const struct ip *)(bytes + offset);
    if (ip->ip_p != IPPROTO_TCP) return;
    uint32_t ip_hdr_len = ip->ip_hl * 4;
    const struct tcphdr *tcp = (const struct tcphdr *)((const uint8_t *)ip + ip_hdr_len);
    size_t ip_len = ntohs(ip->ip_len);
    size_t tcp_hdr_len = tcp->th_off * 4;
    if (ip_len < ip_hdr_len + tcp_hdr_len) return;
    size_t payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len;
    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139) return;
    conn_key_t key;
    int dir;
    if ((src_port == 445 || src_port == 139) && (dst_port != 445 && dst_port != 139)) {
        key.cli_ip = ip->ip_dst.s_addr; key.cli_port = dst_port;
        key.srv_ip = ip->ip_src.s_addr; key.srv_port = src_port;
        dir = 1;
    } else {
        key.cli_ip = ip->ip_src.s_addr; key.cli_port = src_port;
        key.srv_ip = ip->ip_dst.s_addr; key.srv_port = dst_port;
        dir = 0;
    }
    connection_t *conn = get_connection(&key);
    uint32_t seq = ntohl(tcp->th_seq);
    feed_tcp_payload(conn, dir, seq, payload, payload_len);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: sudo %s <interface> <output_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *dev = argv[1];
    output_dir = argv[2];
    if (access(output_dir, F_OK) != 0) {
        if (mkdir(output_dir, 0755) != 0) {
            perror("mkdir");
            return EXIT_FAILURE;
        }
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link type. Only Ethernet is supported.\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    printf("Monitoring on %s... Press Ctrl+C to stop.\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        fflush(ctx->fp);
        fclose(ctx->fp);
    }
    return EXIT_SUCCESS;
}