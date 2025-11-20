#include "common.h"

/* SMB2/3 명령어 코드 */
enum smb2_commands {
    SMB2_CREATE = 0x0005,
    SMB2_READ   = 0x0008,
    SMB2_WRITE  = 0x0009
};

static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

/*
 * ensure_capacity
 * 역할: 수신 버퍼가 꽉 차면 크기를 2배로 늘림.
 */
static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed) return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) exit(EXIT_FAILURE);
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

/*
 * smb_unicode_to_ascii
 * 역할: SMB의 UTF-16LE 파일명을 ASCII로 변환하고, 특수문자를 안전하게 치환.
 */
static void smb_unicode_to_ascii(const uint8_t *src, size_t src_len, char *dst, size_t dst_len) {
    size_t i, j;
    memset(dst, 0, dst_len);
    for (i = 0, j = 0; i < src_len && j < dst_len - 1; i += 2) {
        uint8_t low = src[i]; // 2바이트 중 하위 바이트만 사용 (ASCII 범위 가정)
        if (low == '\\' || low == '/') dst[j++] = '_'; // 경로 구분자 치환
        else if (low >= 32 && low <= 126) dst[j++] = (char)low;
        else dst[j++] = '_';
    }
}

/* [CREATE Request 파싱] 파일명 추출 */
static void parse_create_request(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 50) return;
    uint16_t name_offset = body[40] | (body[41] << 8);
    uint16_t name_len = body[42] | (body[43] << 8);
    
    if (name_offset < 64) return;
    size_t name_start = (size_t)name_offset - 64;
    if (name_start + name_len > len) return;

    /* 대기열에 요청 정보(파일명) 저장 */
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t));
    pc->msg_id = msg_id;
    smb_unicode_to_ascii(body + name_start, name_len, pc->filename, sizeof(pc->filename));
    
    pc->next = conn->pending_creates;
    conn->pending_creates = pc;
}

/* [CREATE Response 파싱] FileID와 파일명 매핑 등록 */
static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 64) return;

    /* 대기열에서 요청 찾기 */
    pending_create_t **prev = &conn->pending_creates;
    pending_create_t *curr = conn->pending_creates;
    pending_create_t *found = NULL;

    while (curr) {
        if (curr->msg_id == msg_id) {
            found = curr;
            *prev = curr->next; // 리스트에서 제거
            break;
        }
        prev = &curr->next;
        curr = curr->next;
    }
    if (!found) return;

    /* FileId 추출 (Offset 48) */
    uint8_t file_id[16];
    memcpy(file_id, body + 48, 16);

    /* file_writer 모듈에 매핑 등록 */
    register_file_mapping(file_id, found->filename);
    free(found);
}

/* [WRITE Request 파싱] 데이터 추출 및 쓰기 */
static void parse_write_request(const uint8_t *body, size_t len) {
    if (len < 32) return;
    uint16_t data_offset = body[2] | (body[3] << 8);
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t file_offset = 0;
    for (int i = 0; i < 8; i++) file_offset |= ((uint64_t)body[8 + i]) << (8 * i);
    const uint8_t *file_id = body + 24;

    if (data_offset < 64) return;
    size_t data_start = (size_t)data_offset - 64;
    if (len < data_start + data_length) return;

    write_file_chunk(file_id, file_offset, body + data_start, data_length);
}

/* [SMB2/3 메시지 파서 메인] */
static void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    size_t offset = 0;
    /* Compound Packet 처리 루프 */
    while (offset < len) {
        if (len - offset < 64) break;
        const uint8_t *hdr = msg + offset;

        /* 매직 코드 확인 (0xFE 'S' 'M' 'B') */
        if (!(hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B')) break;

        uint16_t command = hdr[12] | (hdr[13] << 8);
        uint32_t flags = hdr[16] | (hdr[17] << 8) | (hdr[18] << 16) | (hdr[19] << 24);
        uint32_t next_cmd = hdr[20] | (hdr[21] << 8) | (hdr[22] << 16) | (hdr[23] << 24);
        uint64_t msg_id = 0;
        for (int i = 0; i < 8; i++) msg_id |= ((uint64_t)hdr[24 + i]) << (8 * i);

        int is_response = (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0;
        
        /* Body 길이 계산 */
        size_t body_len;
        if (next_cmd == 0) body_len = (len > offset + 64) ? len - offset - 64 : 0;
        else body_len = next_cmd - 64;
        
        const uint8_t *body = hdr + 64;

        /* 명령어별 분기 처리 */
        if (!is_response) { // 요청 (Request)
            if (command == SMB2_CREATE && dir == 0) parse_create_request(conn, msg_id, body, body_len);
            else if (command == SMB2_WRITE && dir == 0) parse_write_request(body, body_len);
            // READ Request는 생략 (필요시 추가)
        } else { // 응답 (Response)
            if (command == SMB2_CREATE && dir == 1) handle_create_response(conn, msg_id, body, body_len);
            // READ Response는 생략
        }

        if (next_cmd == 0) break;
        offset += next_cmd;
    }
}

/*
 * smb_feed_bytes
 * 역할: TCP 스트림 데이터를 버퍼에 누적하고, NBSS 단위로 패킷을 잘라서 파서 호출.
 */
void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;

    /* NBSS(NetBIOS Session Service) 파싱 루프 */
    size_t pos = 0;
    while (s->buf_len - pos >= 4) {
        // NBSS 헤더: 첫 바이트는 타입, 나머지 3바이트가 길이(Big Endian)
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        
        // 아직 데이터가 다 안 들어왔으면 대기
        if (s->buf_len - pos < total_len) break; 

        const uint8_t *msg = s->buf + pos + 4;
        
        if (nbss_len >= 4) {
            if (msg[0] == 0xFE) parse_smb2_message(conn, dir, msg, nbss_len);
            // SMB1 (0xFF) 처리 로직은 생략하거나 필요시 추가
        }
        pos += total_len;
    }
    
    /* 처리된 데이터 제거 (메모리 이동) */
    if (pos > 0) {
        memmove(s->buf, s->buf + pos, s->buf_len - pos);
        s->buf_len -= pos;
    }
}
