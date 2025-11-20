#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* --------------------------------------------------------------------------
 * [구조체 정의] 데이터 모델링
 * -------------------------------------------------------------------------- */

/* * conn_key_t: TCP 연결을 식별하는 유니크 키 (4-tuple)
 * 용도: 수많은 패킷 중 같은 세션의 패킷을 묶기 위함.
 */
typedef struct conn_key {
    uint32_t cli_ip;   // 클라이언트 IP (Network Byte Order)
    uint16_t cli_port; // 클라이언트 Port
    uint32_t srv_ip;   // 서버 IP
    uint16_t srv_port; // 서버 Port (445 or 139)
} conn_key_t;

/* * tcp_stream_t: 단방향 TCP 스트림 상태
 * 용도: 패킷 유실이나 순서 뒤바뀜(Out-of-order)을 감지하기 위함.
 */
typedef struct tcp_stream {
    uint32_t next_seq; // 다음에 수신해야 할 기대 시퀀스 번호
    int has_next_seq;  // 첫 패킷 수신 여부 플래그 (0=초기화전, 1=추적중)
} tcp_stream_t;

/* * pending_create_t: CREATE 요청(파일명)을 응답(FileId)이 올 때까지 임시 저장
 * 용도: 요청에는 '이름'이 있고 응답에는 'ID'가 있으므로 둘을 매칭해야 함.
 */
typedef struct pending_create {
    uint64_t msg_id;       // 메시지 ID (요청/응답 매칭 키)
    char filename[256];    // 요청 패킷에서 추출한 파일명
    struct pending_create *next;
} pending_create_t;

/* * pending_read_t: READ 요청 정보를 응답이 올 때까지 저장
 */
typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;       // 파일 내 읽기 위치
    uint32_t length;       // 요청 길이
    struct pending_read *next;
} pending_read_t;

/* * smb_stream_t: SMB 데이터를 처리하기 위한 버퍼 및 상태
 */
typedef struct smb_stream {
    uint8_t *buf;           // 조각난 TCP 페이로드를 모으는 버퍼
    size_t buf_len;         // 현재 버퍼 데이터 길이
    size_t buf_cap;         // 버퍼 총 용량
    pending_read_t *pending; // 읽기 요청 대기열
} smb_stream_t;

/* * connection_t: 하나의 세션에 대한 통합 컨텍스트
 */
typedef struct connection {
    conn_key_t key;
    tcp_stream_t tcp[2];    // [0]: C->S, [1]: S->C
    smb_stream_t smb[2];
    pending_create_t *pending_creates; // CREATE 요청 대기열
    struct connection *next;
} connection_t;

/* --------------------------------------------------------------------------
 * [전역 변수 및 함수 프로토타입]
 * -------------------------------------------------------------------------- */
extern char *output_dir; // main.c에서 설정, 다른 곳에서 참조

/* file_writer.c */
void register_file_mapping(const uint8_t *file_id, const char *filename);
void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len);
void cleanup_files();

/* smb_parser.c */
void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len);

/* tcp_stream.c */
connection_t *get_connection(const conn_key_t *key);
void cleanup_connections();

#endif
