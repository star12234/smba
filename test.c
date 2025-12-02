/*
 * smb_live_named.c
 *
 * This version extends the smb_simple_live.c example by restoring the
 * original filenames for SMB2 file transfers.  In addition to capturing
 * SMB traffic from a live network interface and reassembling READ/WRITE
 * data into output files, it also parses SMB2 CREATE requests and
 * responses.  The CREATE request contains the target pathname in
 * UTF‑16LE, and the corresponding response returns the 16‑byte FileId
 * used for subsequent SMB2 operations.  By matching the messageId of
 * the request and response, this program builds a mapping from FileId
 * to the original pathname and uses that mapping when naming the
 * reconstructed files.  The mapping covers files opened via SMB2; when
 * no mapping is available, the program falls back to naming files with
 * the hexadecimal FileId.
 *
 * Usage: sudo ./smb_live_named <interface> <output_dir>
 *
 * The program requires root privileges to capture packets on a live
 * interface.  The output directory will be created if it does not
 * already exist.  Note that this program does not attempt to handle
 * SMB3 encryption or compression; encrypted or compressed streams will
 * appear as gibberish.  For clarity, SMB1 writes are still supported
 * but file names are not restored for SMB1 traffic.
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

/* Connection key identifying one SMB TCP connection.  We treat the
 * endpoint using port 445 or 139 as the server and the other as the
 * client.  Each connection maintains separate TCP state for
 * client→server (index 0) and server→client (index 1) directions. */
typedef struct conn_key {
    uint32_t cli_ip;
    uint16_t cli_port;
    uint32_t srv_ip;
    uint16_t srv_port;
} conn_key_t;

/* State for one direction of a TCP stream.  The next expected
 * sequence number is used to drop out‑of‑order segments – this is
 * simplistic and assumes a clean capture with no packet loss. */
typedef struct tcp_stream {
    uint32_t next_seq;
    int has_next_seq;
} tcp_stream_t;

/* Forward declaration of connection_t for use in filename mapping. */
typedef struct connection connection_t;

/* A pending SMB2 READ request awaiting a response.  We track the
 * messageId, FileId, and offset to match incoming responses. */
typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;
    uint32_t length;
    struct pending_read *next;
} pending_read_t;

/* A pending SMB2 CREATE request awaiting its corresponding response.
 * The msg_id is used to match the CREATE Response that carries the
 * FileId.  The name field holds the UTF‑8 pathname extracted from the
 * request. */
typedef struct pending_create {
    uint64_t msg_id;
    char *name;
    struct pending_create *next;
} pending_create_t;

/* Map a 16‑byte FileId to a sanitized filename.  When the SMB2
 * response returns the FileId, we record the mapping so that WRITE
 * requests and READ responses for the same FileId can be written to
 * files with meaningful names rather than hexadecimal identifiers. */
typedef struct file_name_map {
    uint8_t file_id[16];
    char *name;
    struct file_name_map *next;
} file_name_map_t;

/* SMB stream state for one direction.  Each direction has its own
 * buffer for accumulating bytes until complete NBSS frames are
 * available, and a list of pending READ requests.  The list of
 * pending CREATE requests and filename mappings are stored at the
 * connection level rather than per‑stream. */
typedef struct smb_stream {
    uint8_t *buf;
    size_t buf_len;
    size_t buf_cap;
    pending_read_t *pending;
} smb_stream_t;

/* Per‑connection context storing both TCP and SMB state.  In
 * addition to the TCP streams and SMB buffers, we maintain a list of
 * pending CREATE requests and a linked list of FileId→name mappings
 * for this connection. */
struct connection {
    conn_key_t key;
    tcp_stream_t tcp[2];      /* [0]=client→server, [1]=server→client */
    smb_stream_t smb[2];
    pending_create_t *pending_creates;
    file_name_map_t *file_names;
    struct connection *next;
};

/* Linked list of all connections. */
static connection_t *connections = NULL;

/* File context storing open file handles keyed by FileId.  This
 * structure ensures that subsequent writes to the same FileId seek to
 * the correct offset within the same file. */
typedef struct file_ctx {
    uint8_t file_id[16];
    FILE *fp;
    struct file_ctx *next;
} file_ctx_t;

static file_ctx_t *open_files = NULL;

/* Output directory supplied by the user. */
static char *output_dir = NULL;

/* SMB command codes we handle. */
enum smb2_commands {
    SMB2_CREATE = 0x0005,
    SMB2_READ   = 0x0008,
    SMB2_WRITE  = 0x0009
};

static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

/* SMB1 command codes used for write operations.  These constants are
 * defined here because SMB1 writes are still supported for completeness,
 * even though filename restoration is only implemented for SMB2. */
enum smb1_commands {
    SMB1_COM_WRITE       = 0x0B,
    SMB1_COM_WRITE_ANDX  = 0x2F
};

/* Utility: compare two connection keys for equality. */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

/* Find or create a connection context for the given key.  New
 * connections are inserted at the head of the global list. */
static connection_t *get_connection(const conn_key_t *key) {
    connection_t *c;
    for (c = connections; c; c = c->next) {
        if (conn_key_equal(&c->key, key))
            return c;
    }
    c = (connection_t *)calloc(1, sizeof(connection_t));
    if (!c) {
        fprintf(stderr, "Memory allocation failed for connection\n");
        exit(EXIT_FAILURE);
    }
    c->key = *key;
    c->next = connections;
    connections = c;
    return c;
}

/* Ensure that an SMB stream buffer has at least the given capacity. */
static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed)
        return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) {
        fprintf(stderr, "Realloc failed in ensure_capacity\n");
        exit(EXIT_FAILURE);
    }
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

/* Convert a UTF‑16LE string to a UTF‑8/ASCII C string by discarding
 * the high byte of each 16‑bit codepoint.  This simple conversion
 * suffices for common ASCII filenames; filenames containing non‑ASCII
 * characters will be partially transliterated.  The caller must
 * free the returned buffer. */
static char *utf16le_to_utf8(const uint8_t *data, size_t byte_len) {
    size_t char_count = byte_len / 2;
    char *out = (char *)calloc(char_count + 1, 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < char_count; i++) {
        out[i] = (char)data[i * 2];
    }
    out[char_count] = '\0';
    return out;
}

/* Sanitize a pathname by converting backslashes to forward slashes,
 * removing drive letters and leading separators, and eliminating
 * parent directory references.  The sanitized path is written to
 * out up to out_size bytes. */
static void sanitize_path(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    int skip_leading = 1;
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        char c = in[i];
        /* Convert Windows separators to POSIX. */
        if (c == '\\') c = '/';
        /* Skip drive letters like C: */
        if (i == 1 && in[1] == ':' ) continue;
        /* Remove leading separators */
        if (skip_leading && (c == '/' || c == '\\'))
            continue;
        skip_leading = 0;
        /* Eliminate parent directory references. */
        if (c == '.' && in[i + 1] == '.' ) {
            /* Skip ".." and the following slash, if present */
            i += 1;
            if (in[i + 1] == '/' || in[i + 1] == '\\') i++;
            continue;
        }
        /* Remove colon and other forbidden characters. */
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            continue;
        out[j++] = c;
    }
    out[j] = '\0';
}

/* Recursively create directories for the given full path.  The
 * implementation walks through the string and creates each parent
 * directory along the way.  It gracefully ignores existing
 * directories. */
static void ensure_parent_dirs(const char *full_path) {
    char tmp[1024];
    size_t len = strlen(full_path);
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, full_path);
    /* Start after the first character to avoid creating the root. */
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
}

/* Write a chunk of data to the file identified by FileId.  If a
 * mapping from FileId to a filename exists, that name is used;
 * otherwise the file is named using the hexadecimal FileId.  Each
 * FileId has a corresponding file_ctx_t structure that caches the
 * FILE pointer so that subsequent writes seek correctly. */
static void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    /* Look for an existing file context. */
    file_ctx_t *ctx;
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0)
            break;
    }
    if (!ctx) {
        /* No existing file – create a new one.  Determine the
         * filename based on a known FileId→name mapping if
         * available. */
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
            /* Ensure parent directories exist. */
            ensure_parent_dirs(path);
        } else {
            char hexname[33];
            for (int i = 0; i < 16; i++)
                sprintf(&hexname[i * 2], "%02x", file_id[i]);
            snprintf(path, sizeof(path), "%s/%s.bin", output_dir, hexname);
        }
        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        if (!ctx) {
            fprintf(stderr, "Memory allocation failed for file_ctx\n");
            return;
        }
        memcpy(ctx->file_id, file_id, 16);
        ctx->fp = fopen(path, "wb");
        if (!ctx->fp) {
            fprintf(stderr, "Failed to open output file %s\n", path);
            free(ctx);
            return;
        }
        printf("[INFO] Created new file: %s\n", path + strlen(output_dir) + 1);
        ctx->next = open_files;
        open_files = ctx;
    }
    /* Seek and write the data. */
    fseeko(ctx->fp, (off_t)offset, SEEK_SET);
    fwrite(data, 1, len, ctx->fp);
    /* Flush to disk immediately for reliability. */
    fflush(ctx->fp);
}

/* Record a pending SMB2 READ request so that the corresponding
 * response can be matched later. */
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

/* Match a SMB2 READ response to its corresponding pending request and
 * write the returned data to the appropriate file. */
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
        if (pr->msg_id == msg_id)
            break;
        prev_ptr = &pr->next;
        pr = pr->next;
    }
    if (!pr) return;
    /* Remove from list and write data. */
    *prev_ptr = pr->next;
    write_file_chunk(pr->file_id, pr->offset, body + data_start, data_length);
    free(pr);
}

/* Record a pending SMB2 CREATE request.  The msg_id allows us to
 * match the corresponding response containing the FileId.  The
 * pathname is extracted from the request and stored as UTF‑8. */
static void record_pending_create(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    /* NameOffset and NameLength are located at offsets 48–51 of the
     * CREATE request body.  NameOffset is relative to the beginning
     * of the SMB2 header (64 bytes before body).  See MS‑SMB2
     * section 2.2.14 for details. */
    if (len < 52) return;
    uint16_t name_offset = body[48] | (body[49] << 8);
    uint16_t name_length = body[50] | (body[51] << 8);
    if (name_length == 0) return;
    if (name_offset < 64) return;
    size_t rel = (size_t)name_offset - 64;
    if (rel + name_length > len) return;
    const uint8_t *name_utf16 = body + rel;
    char *utf8 = utf16le_to_utf8(name_utf16, name_length);
    if (!utf8) return;
    /* Store the pending create. */
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t));
    if (!pc) {
        free(utf8);
        return;
    }
    pc->msg_id = msg_id;
    pc->name = utf8;
    pc->next = conn->pending_creates;
    conn->pending_creates = pc;
}

/* Remember the mapping between a FileId and a sanitized filename.  If
 * the FileId has already been mapped, this call is ignored. */
static void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name) {
    /* Check whether mapping already exists. */
    file_name_map_t *m;
    for (m = conn->file_names; m; m = m->next) {
        if (memcmp(m->file_id, file_id, 16) == 0)
            return;
    }
    /* Sanitize the path to avoid directory traversal and convert
     * backslashes. */
    char safe[512];
    sanitize_path(orig_name, safe, sizeof(safe));
    m = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    if (!m) return;
    memcpy(m->file_id, file_id, 16);
    m->name = strdup(safe);
    if (!m->name) {
        free(m);
        return;
    }
    m->next = conn->file_names;
    conn->file_names = m;
}

/* Handle an SMB2 CREATE response.  The response contains the FileId
 * associated with the handle.  Look up the pending CREATE request by
 * msg_id to obtain the original pathname and record the mapping. */
static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    /* Locate the corresponding pending create request. */
    pending_create_t **prev_ptr = &conn->pending_creates;
    pending_create_t *pc = conn->pending_creates;
    while (pc) {
        if (pc->msg_id == msg_id)
            break;
        prev_ptr = &pc->next;
        pc = pc->next;
    }
    if (!pc)
        return;
    /* According to MS‑SMB2 section 2.2.14, the FileId in a CREATE
     * response begins at offset 64 within the response body and spans
     * 16 bytes (8 bytes persistent + 8 bytes volatile). */
    if (len < 80)
        return;
    const uint8_t *file_id = body + 64;
    remember_file_name(conn, file_id, pc->name);
    /* Remove the pending create entry and free its memory. */
    *prev_ptr = pc->next;
    free(pc->name);
    free(pc);
}

/* SMB2/3 message parser.  Supports parsing multiple compounded commands
 * within a single SMB2 message by following the NextCommand field. */
static void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        if (len - offset < 64)
            break;
        const uint8_t *hdr = msg + offset;
        /* Validate SMB2 signature. */
        if (!(hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B'))
            break;
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
            if (next_cmd < 64 || offset + next_cmd > len)
                break;
            body_len = next_cmd - 64;
        }
        const uint8_t *body = hdr + 64;
        if (!is_response) {
            if (command == SMB2_READ && dir == 0) {
                record_pending_read(conn, msg_id, body, body_len);
            } else if (command == SMB2_WRITE && dir == 0) {
                /* SMB2 WRITE request: extract data and write to file */
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
                /* Record the pending CREATE request for filename restoration. */
                record_pending_create(conn, msg_id, body, body_len);
            }
        } else {
            if (command == SMB2_READ && dir == 1) {
                handle_read_response(conn, msg_id, body, body_len);
            } else if (command == SMB2_CREATE && dir == 1) {
                handle_create_response(conn, msg_id, body, body_len);
            }
        }
        if (next_cmd == 0)
            break;
        offset += next_cmd;
    }
}

/* Helper for SMB1 file identification.  Constructs a pseudo FileId
 * for SMB1 requests by combining the FID with connection information.
 * This ensures uniqueness across multiple connections. */
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

/* Parse a SMB1 message for WRITE operations.  Only SMB1 write
 * requests carry data; responses do not include file contents. */
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
    if (dir != 0) return; /* Only handle client→server writes */
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

/* Feed TCP payload bytes into SMB parser.  This function handles
 * NetBIOS Session Service (NBSS) framing, extracts complete SMB
 * messages, and dispatches them to the appropriate SMB1 or SMB2
 * parser. */
static void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
    size_t pos = 0;
    while (s->buf_len - pos >= 4) {
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        if (s->buf_len - pos < total_len)
            break;
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

/* Feed TCP payload into reassembly logic.  We drop out‑of‑order
 * segments for simplicity. */
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

/* Packet handler called by pcap_loop.  Decodes Ethernet, IPv4 and
 * TCP headers, identifies SMB traffic on ports 445/139 and feeds the
 * TCP payload to the reassembly logic. */
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    if (h->caplen < 14) return;
    size_t offset = 14;
    uint16_t eth_type = (bytes[12] << 8) | bytes[13];
    /* Skip VLAN tag if present. */
    if (eth_type == 0x8100 && h->caplen >= 18) {
        offset += 4;
        eth_type = (bytes[offset - 2] << 8) | bytes[offset - 1];
    }
    if (eth_type != 0x0800) return; /* Only handle IPv4 */
    const struct ip *ip = (const struct ip *)(bytes + offset);
    if (ip->ip_p != IPPROTO_TCP) return;
    uint32_t ip_hdr_len = ip->ip_hl * 4;
    if (h->caplen < offset + ip_hdr_len + sizeof(struct tcphdr)) return;
    const struct tcphdr *tcp = (const struct tcphdr *)((const uint8_t *)ip + ip_hdr_len);
    size_t ip_len = ntohs(ip->ip_len);
    size_t tcp_hdr_len = tcp->th_off * 4;
    if (ip_len < ip_hdr_len + tcp_hdr_len) return;
    size_t payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len;
    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);
    /* Filter only SMB ports 445 and 139. */
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139)
        return;
    conn_key_t key;
    int dir;
    if ((src_port == 445 || src_port == 139) && (dst_port != 445 && dst_port != 139)) {
        /* server→client */
        key.cli_ip = ip->ip_dst.s_addr;
        key.cli_port = dst_port;
        key.srv_ip = ip->ip_src.s_addr;
        key.srv_port = src_port;
        dir = 1;
    } else {
        /* client→server */
        key.cli_ip = ip->ip_src.s_addr;
        key.cli_port = src_port;
        key.srv_ip = ip->ip_dst.s_addr;
        key.srv_port = dst_port;
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
    /* Create the output directory if it does not exist. */
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
    /* Flush and close all open files. */
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        fflush(ctx->fp);
        fclose(ctx->fp);
    }
    return EXIT_SUCCESS;
}
