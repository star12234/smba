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

#include <pcap.h>           // libpcap 라이브러리를 포함합니다. (패킷 캡처 기능 제공)
#include <stdio.h>          // 표준 입출력 라이브러리를 포함합니다. (printf, fprintf, FILE 등)
#include <stdlib.h>         // 표준 유틸리티 라이브러리를 포함합니다. (malloc, free, exit, atoi 등)
#include <stdint.h>         // 고정 크기 정수형을 정의합니다. (uint8_t, uint32_t, uint64_t 등)
#include <string.h>         // 문자열 처리 함수들을 포함합니다. (memcpy, strlen, strcmp, strdup 등)
#include <arpa/inet.h>      // 인터넷 주소 변환 함수들을 포함합니다. (inet_ntoa, ntohs, htons 등)
#include <netinet/in.h>     // 인터넷 주소 구조체를 정의합니다. (sockaddr_in, in_addr 등)
#include <netinet/ip.h>     // IP 프로토콜 헤더 구조체를 정의합니다. (struct ip)
#include <netinet/tcp.h>    // TCP 프로토콜 헤더 구조체를 정의합니다. (struct tcphdr)
#include <unistd.h>         // POSIX 운영체제 API를 포함합니다. (close, access, mkdir 등)
#include <sys/stat.h>       // 파일 상태 및 속성 관련 함수와 매크로를 포함합니다. (mkdir의 모드 설정 등)
#include <sys/types.h>      // 시스템 데이터 타입들을 정의합니다. (size_t, off_t 등)

/* Connection key identifying one SMB TCP connection. */
typedef struct conn_key {   // TCP 연결을 식별하기 위한 키 구조체를 정의합니다.
    uint32_t cli_ip;        // 클라이언트의 IP 주소를 저장합니다. (4바이트)
    uint16_t cli_port;      // 클라이언트의 포트 번호를 저장합니다. (2바이트)
    uint32_t srv_ip;        // 서버의 IP 주소를 저장합니다. (4바이트)
    uint16_t srv_port;      // 서버의 포트 번호를 저장합니다. (2바이트)
} conn_key_t;               // 이 구조체의 타입을 conn_key_t로 정의합니다.

/* State for one direction of a TCP stream. */
typedef struct tcp_stream { // TCP 스트림의 한쪽 방향 상태를 관리하는 구조체를 정의합니다.
    uint32_t next_seq;      // 다음에 수신될 것으로 예상되는 TCP 시퀀스 번호를 저장합니다.
    int has_next_seq;       // next_seq 값이 유효하게 설정되었는지 여부를 나타내는 플래그입니다.
} tcp_stream_t;             // 이 구조체의 타입을 tcp_stream_t로 정의합니다.

/* Forward declaration */
typedef struct connection connection_t; // connection 구조체를 포인터로 미리 사용하기 위해 전방 선언합니다.

/* Pending SMB2 READ request */
typedef struct pending_read { // 응답을 기다리고 있는 SMB2 READ 요청 정보를 저장하는 구조체입니다.
    uint64_t msg_id;          // 요청과 응답을 매칭하기 위한 메시지 ID입니다.
    uint8_t file_id[16];      // 읽기를 요청한 파일의 고유 ID입니다. (16바이트)
    uint64_t offset;          // 파일 내에서 읽기 시작할 위치(오프셋)입니다.
    uint32_t length;          // 읽을 데이터의 길이입니다.
    struct pending_read *next; // 다음 대기 중인 READ 요청을 가리키는 포인터입니다. (연결 리스트)
} pending_read_t;             // 이 구조체의 타입을 pending_read_t로 정의합니다.

/* Pending SMB2 CREATE request */
typedef struct pending_create { // 응답을 기다리고 있는 SMB2 CREATE 요청 정보를 저장하는 구조체입니다.
    uint64_t msg_id;            // 요청과 응답을 매칭하기 위한 메시지 ID입니다.
    char *name;                 // 요청 패킷에서 파싱한 파일 이름을 저장하는 포인터입니다.
    struct pending_create *next; // 다음 대기 중인 CREATE 요청을 가리키는 포인터입니다. (연결 리스트)
} pending_create_t;             // 이 구조체의 타입을 pending_create_t로 정의합니다.

/* FileId to Filename Mapping */
typedef struct file_name_map {  // 파일 ID와 파일 이름을 매핑하여 저장하는 구조체입니다.
    uint8_t file_id[16];        // 파일의 고유 ID입니다. (Key 역할)
    char *name;                 // 해당 파일의 이름입니다. (Value 역할)
    struct file_name_map *next; // 다음 매핑 정보를 가리키는 포인터입니다. (연결 리스트)
} file_name_map_t;              // 이 구조체의 타입을 file_name_map_t로 정의합니다.

/* SMB stream state */
typedef struct smb_stream {     // SMB 데이터 스트림의 버퍼 및 상태를 관리하는 구조체입니다.
    uint8_t *buf;               // 조립 중인 SMB 데이터를 저장할 동적 할당 버퍼입니다.
    size_t buf_len;             // 현재 버퍼에 저장된 데이터의 실제 길이입니다.
    size_t buf_cap;             // 버퍼의 현재 할당된 총 용량(Capacity)입니다.
    pending_read_t *pending;    // 이 스트림 방향에서 대기 중인 READ 요청 리스트의 헤드입니다.
} smb_stream_t;                 // 이 구조체의 타입을 smb_stream_t로 정의합니다.

/* Connection Context */
struct connection {             // 하나의 TCP 연결 세션 전체를 관리하는 메인 구조체입니다.
    conn_key_t key;             // 이 연결을 식별하는 키(IP/Port 쌍)입니다.
    tcp_stream_t tcp[2];        // 양방향(클라이언트->서버, 서버->클라이언트) TCP 상태 배열입니다.
    smb_stream_t smb[2];        // 양방향 SMB 스트림 상태 배열입니다.
    pending_create_t *pending_creates; // 대기 중인 CREATE 요청 리스트의 헤드입니다.
    file_name_map_t *file_names;       // 파일 ID와 이름 매핑 정보 리스트의 헤드입니다.
    struct connection *next;    // 다음 연결 구조체를 가리키는 포인터입니다. (전역 리스트용)
};                              // 구조체 정의를 마칩니다. (typedef 된 이름은 connection_t)

static connection_t *connections = NULL; // 현재 활성화된 모든 연결을 관리하는 전역 연결 리스트의 헤드입니다.

/* Open File Context */
typedef struct file_ctx {       // 현재 열려 있는 파일의 핸들 정보를 저장하는 구조체입니다.
    uint8_t file_id[16];        // 파일 ID를 저장합니다.
    FILE *fp;                   // 실제 파일 입출력을 위한 파일 포인터입니다.
    struct file_ctx *next;      // 다음 열린 파일 컨텍스트를 가리키는 포인터입니다.
} file_ctx_t;                   // 이 구조체의 타입을 file_ctx_t로 정의합니다.

static file_ctx_t *open_files = NULL; // 현재 열려 있는 파일들의 리스트 헤드입니다.
static char *output_dir = NULL;       // 복구된 파일을 저장할 디렉토리 경로를 저장하는 전역 변수입니다.

/* [FIXED] Missing SMB1 definitions added here */
enum smb1_commands {            // SMB1 프로토콜 명령어 코드를 정의하는 열거형입니다.
    SMB1_COM_WRITE       = 0x0B, // SMB1 기본 쓰기 명령의 코드값(0x0B)입니다.
    SMB1_COM_WRITE_ANDX  = 0x2F  // SMB1 확장 쓰기 명령(AndX)의 코드값(0x2F)입니다.
};                              // 열거형 정의를 마칩니다.

/* SMB2 definitions */
enum smb2_commands {            // SMB2 프로토콜 명령어 코드를 정의하는 열거형입니다.
    SMB2_CREATE = 0x0005,       // SMB2 파일 생성/열기 명령의 코드값입니다.
    SMB2_READ   = 0x0008,       // SMB2 파일 읽기 명령의 코드값입니다.
    SMB2_WRITE  = 0x0009        // SMB2 파일 쓰기 명령의 코드값입니다.
};                              // 열거형 정의를 마칩니다.

static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001; // 서버에서 클라이언트로 가는 응답임을 나타내는 플래그 비트입니다.

/* Utility Functions */
/* Utility Functions */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) { // 두 연결 키가 동일한지 비교하는 함수입니다.
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&    // 클라이언트 IP와 포트가 같은지 확인합니다.
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;      // 서버 IP와 포트가 같은지 확인하고 결과를 반환합니다.
}                                                                     // 함수를 종료합니다.

static connection_t *get_connection(const conn_key_t *key) { // 키를 사용하여 연결 구조체를 찾거나 새로 생성하는 함수입니다.
    connection_t *c;                                         // 연결 구조체 포인터 변수를 선언합니다.
    for (c = connections; c; c = c->next) {                  // 전역 연결 리스트를 처음부터 끝까지 순회합니다.
        if (conn_key_equal(&c->key, key))                    // 현재 노드의 키와 찾는 키가 같은지 비교합니다.
            return c;                                        // 같다면 찾은 연결 구조체 포인터를 반환합니다.
    }                                                        // 루프 종료. 리스트에 해당 키가 없습니다.
    c = (connection_t *)calloc(1, sizeof(connection_t));     // 새로운 연결 구조체를 위해 메모리를 할당하고 0으로 초기화합니다.
    if (!c) {                                                // 메모리 할당에 실패했는지 확인합니다.
        fprintf(stderr, "Memory allocation failed\n");       // 에러 메시지를 표준 에러로 출력합니다.
        exit(EXIT_FAILURE);                                  // 프로그램을 에러 코드와 함께 종료합니다.
    }                                                        // 할당 성공 시 실행됩니다.
    c->key = *key;                                           // 인자로 받은 키 정보를 새 구조체에 복사합니다.
    c->next = connections;                                   // 새 구조체의 next 포인터가 현재 리스트의 헤드를 가리키게 합니다.
    connections = c;                                         // 전역 리스트 헤드를 새 구조체로 갱신합니다. (맨 앞에 추가)
    return c;                                                // 새로 생성된 연결 구조체 포인터를 반환합니다.
}                                                            // 함수를 종료합니다.

static void ensure_capacity(smb_stream_t *s, size_t needed) { // 버퍼 용량이 부족하면 늘려주는 함수입니다.
    if (s->buf_cap >= needed) return;                         // 현재 용량이 필요량보다 크거나 같으면 그냥 리턴합니다.
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;      // 새 용량을 계산합니다. 기존 용량이 있으면 2배, 없으면 1024로 설정합니다.
    while (new_cap < needed) new_cap *= 2;                    // 새 용량이 필요량보다 커질 때까지 계속 2배씩 늘립니다.
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);   // 계산된 크기로 메모리를 재할당합니다. 기존 데이터는 유지됩니다.
    if (!new_buf) exit(EXIT_FAILURE);                         // 재할당 실패 시 프로그램을 종료합니다.
    s->buf = new_buf;                                         // 구조체의 버퍼 포인터를 새로 할당된 주소로 갱신합니다.
    s->buf_cap = new_cap;                                     // 구조체의 용량 정보를 갱신합니다.
}                                                             // 함수를 종료합니다.

static char *utf16le_to_utf8(const uint8_t *data, size_t byte_len) { // UTF-16LE 데이터를 UTF-8(ASCII) 문자열로 변환하는 함수입니다.
    size_t char_count = byte_len / 2;                                // 2바이트가 한 글자이므로 글자 수를 계산합니다.
    char *out = (char *)calloc(char_count + 1, 1);                   // 글자 수 + 널 문자(1)만큼 메모리를 할당합니다.
    if (!out) return NULL;                                           // 할당 실패 시 NULL을 반환합니다.
    for (size_t i = 0; i < char_count; i++) {                        // 글자 수만큼 반복합니다.
        out[i] = (char)data[i * 2];                                  // 2바이트 중 하위 바이트(ASCII 부분)만 가져와 저장합니다.
    }                                                                // 반복 종료.
    out[char_count] = '\0';                                          // 문자열 끝에 널 문자를 추가합니다.
    return out;                                                      // 변환된 문자열 포인터를 반환합니다.
}                                                                    // 함수를 종료합니다.

static void sanitize_path(const char *in, char *out, size_t out_size) { // 파일 경로에서 위험하거나 불필요한 문자를 제거하는 함수입니다.
    size_t j = 0;                                                       // 출력 버퍼의 인덱스 변수입니다.
    int skip_leading = 1;                                               // 경로 맨 앞의 구분자를 건너뛰기 위한 플래그입니다.
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {                // 입력 문자열을 끝까지 순회합니다. (출력 버퍼 크기 체크 포함)
        char c = in[i];                                                 // 현재 문자를 가져옵니다.
        if (c == '\\') c = '/';                                         // 백슬래시를 슬래시로 변경합니다. (윈도우 경로 호환)
        if (i == 1 && in[1] == ':' ) continue;                          // 'C:' 같은 드라이브 문자는 무시하고 건너뜁니다.
        if (skip_leading && (c == '/' || c == '\\')) continue;          // 맨 처음에 나오는 슬래시나 백슬래시는 건너뜁니다.
        skip_leading = 0;                                               // 첫 문자를 처리했으므로 플래그를 끕니다.
        if (c == '.' && in[i + 1] == '.' ) {                            // '..' (상위 디렉토리) 패턴을 감지합니다.
            i += 1;                                                     // 다음 점(.)으로 인덱스를 이동합니다.
            if (in[i + 1] == '/' || in[i + 1] == '\\') i++;             // 그 뒤에 슬래시가 있으면 그것도 건너뜁니다.
            continue;                                                   // 이 문자는 출력에 포함시키지 않고 다음으로 넘어갑니다.
        }                                                               // '..' 처리 끝.
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') // 파일명에 사용할 수 없는 특수문자인지 확인합니다.
            continue;                                                   // 특수문자면 출력하지 않고 건너뜁니다.
        out[j++] = c;                                                   // 안전한 문자이므로 출력 버퍼에 저장하고 인덱스를 증가시킵니다.
    }                                                                   // 루프 종료.
    out[j] = '\0';                                                      // 출력 문자열 끝에 널 문자를 추가합니다.
}                                                                       // 함수를 종료합니다.

static void ensure_parent_dirs(const char *full_path) { // 파일 경로 상의 모든 부모 디렉토리를 생성하는 함수입니다.
    char tmp[1024];                                     // 경로 처리를 위한 임시 버퍼를 선언합니다.
    size_t len = strlen(full_path);                     // 전체 경로의 길이를 잽니다.
    if (len >= sizeof(tmp)) return;                     // 경로가 너무 길면 버퍼 오버플로우 방지를 위해 리턴합니다.
    strcpy(tmp, full_path);                             // 경로를 임시 버퍼에 복사합니다.
    for (char *p = tmp + 1; *p; p++) {                  // 두 번째 글자부터 끝까지 문자열을 순회합니다.
        if (*p == '/') {                                // 슬래시(디렉토리 구분자)를 만나면 실행합니다.
            *p = '\0';                                  // 슬래시를 널 문자로 바꿔 문자열을 잠시 끊습니다.
            mkdir(tmp, 0755);                           // 현재까지의 경로로 디렉토리를 생성합니다. (권한 755)
            *p = '/';                                   // 널 문자를 다시 슬래시로 복구합니다.
        }                                               // if 문 종료.
    }                                                   // for 문 종료.
}                                                       // 함수를 종료합니다. 

static void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) { // 특정 파일(FileId)에 대해, 주어진 오프셋 위치에 데이터 조각(data, len)을 실제 파일에 써주는 함수

    file_ctx_t *ctx; // 현재 열려 있는 파일들의 연결 리스트를 순회하기 위한 포인터(파일 컨텍스트)

    for (ctx = open_files; ctx; ctx = ctx->next) { // open_files(열려 있는 파일들의 리스트)를 처음부터 끝까지 순회
        if (memcmp(ctx->file_id, file_id, 16) == 0) break; // 현재 ctx가 가리키는 파일의 file_id와 인자로 받은 file_id가 같으면 해당 ctx를 사용하기 위해 반복문 탈출
    }

    if (!ctx) { // 위 반복문에서 같은 file_id를 가진 ctx를 찾지 못한 경우(아직 이 FileId에 해당하는 파일을 안 열었을 때)
        char path[1024]; // 생성할 파일의 전체 경로를 저장할 버퍼
        const file_name_map_t *m; // file_id -> 실제 파일 이름 매핑 리스트를 순회하기 위한 포인터
        const char *name = NULL; // file_id에 해당하는 파일 이름을 찾았을 때 저장할 포인터, 기본은 NULL

        for (m = connections ? connections->file_names : NULL; m; m = m->next) { // 전역/현재 connections 구조체가 존재하면 거기서 file_names 리스트를 순회
            if (memcmp(m->file_id, file_id, 16) == 0) { // 매핑 리스트 안에서 같은 file_id를 찾으면
                name = m->name; // 그에 대응되는 실제 파일 이름을 name에 저장
                break; // 더 이상 찾을 필요 없으므로 반복문 탈출
            }
        }

        if (name) { // file_id에 매칭되는 실제 파일 이름을 찾은 경우
            snprintf(path, sizeof(path), "%s/%s", output_dir, name); // output_dir/원본파일이름 형태로 경로 문자열 생성
            ensure_parent_dirs(path); // 해당 경로의 상위 디렉터리가 없으면 생성해 주는 함수(디렉터리 트리 보장)
        } else { // file_id로부터 이름을 찾지 못한 경우(이름 모를 파일)
            char hexname[33]; // file_id(16바이트)를 16진수 문자열(32글자)로 변환할 버퍼, 마지막은 널 문자까지 총 33바이트

            for (int i = 0; i < 16; i++) sprintf(&hexname[i * 2], "%02x", file_id[i]); // file_id의 각 바이트를 2자리 16진수로 변환하여 hexname에 이어붙임

            snprintf(path, sizeof(path), "%s/%s.bin", output_dir, hexname); // output_dir/16진수이름.bin 형태의 임시 파일 이름으로 경로 생성
        }

        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t)); // 새로운 파일 컨텍스트 구조체를 0으로 초기화하여 동적 할당
        memcpy(ctx->file_id, file_id, 16); // 이 컨텍스트가 어떤 file_id에 해당하는지 구조체 내부에 복사해 저장
        ctx->fp = fopen(path, "wb"); // 위에서 만든 경로로 바이너리 쓰기 모드("wb")로 파일 오픈(없으면 생성)

        if (!ctx->fp) { // 파일을 여는 데 실패한 경우
            fprintf(stderr, "Failed to open %s\n", path); // 에러 메시지를 stderr로 출력
            free(ctx); // 할당해 둔 ctx 구조체를 해제하여 메모리 누수 방지
            return; // 함수 종료(더 이상 진행 불가)
        }

        printf("[INFO] Created new file: %s\n", path + strlen(output_dir) + 1); // 생성된 파일 이름을 로그로 출력(출력 경로에서 앞의 output_dir/ 부분을 건너뛰고 파일명만 출력)

        ctx->next = open_files; // 새로 만든 ctx를 open_files 연결 리스트의 맨 앞에 연결
        open_files = ctx; // 리스트의 헤드를 새 컨텍스트로 갱신
    }

    fseeko(ctx->fp, (off_t)offset, SEEK_SET); // 파일 포인터를 파일 내에서 offset 위치로 이동(랜덤 액세스; 중간 부분부터 쓰기 위해 사용)
    fwrite(data, 1, len, ctx->fp); // data 버퍼의 내용을 len 바이트만큼 파일에 기록(1바이트 단위로 len번 쓰기)
    fflush(ctx->fp); // 버퍼링된 파일 출력 내용을 디스크로 즉시 밀어 넣어(플러시) 데이터가 바로 기록되도록 함
} // write_file_chunk 함수 끝



static void record_pending_read(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) { // SMB READ 요청 패킷을 처리하여, 나중에 READ 응답이 왔을 때 매칭할 수 있도록 정보를 pending 리스트에 기록하는 함수

    if (len < 48) return; // SMB2 READ Request의 본문 길이가 최소한의 헤더 크기(여기서는 48바이트)보다 짧으면 잘못된 패킷이므로 그냥 무시하고 리턴

    uint32_t length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24); // body[4..7]에서 little-endian 방식으로 읽어온 읽기 길이(Length 필드)를 32비트 정수로 변환

    uint64_t offset = 0; // 파일 안에서 읽기 시작할 위치(Offset)를 저장할 64비트 변수, 일단 0으로 초기화

    for (int i = 0; i < 8; i++) offset |= ((uint64_t)body[8 + i]) << (8 * i); // body[8..15]에 있는 8바이트를 little-endian으로 조합하여 64비트 offset 값으로 만듦

    const uint8_t *file_id = body + 24; // body[24..39] 위치에 있는 16바이트가 SMB2 READ Request의 FileId 필드라 가정하고 그 시작 주소를 포인터로 저장

    pending_read_t *pr = (pending_read_t *)calloc(1, sizeof(pending_read_t)); // 새로운 pending_read_t 구조체를 0으로 초기화하여 동적 할당(READ 요청 하나에 대응되는 대기 노드)

    if (!pr) return; // 메모리 할당 실패 시 조용히 함수 종료(더 처리할 수 없으므로)

    pr->msg_id = msg_id; // 이 READ 요청을 식별하기 위해 SMB2 메시지 ID(msg_id)를 구조체에 저장(나중에 응답에서 같은 ID를 찾기 위함)
    memcpy(pr->file_id, file_id, 16); // 읽으려는 대상 파일의 FileId(16바이트)를 구조체에 복사하여 저장
    pr->offset = offset; // 이 READ 요청이 파일 내에서 어느 위치(offset)부터 읽는지 기록
    pr->length = length; // 이 READ 요청이 읽고자 하는 데이터 길이를 기록
    pr->next = conn->smb[0].pending; // 현재 연결(conn)의 smb[0].pending 리스트 맨 앞에 새 노드를 삽입하기 위해 next를 기존 헤드로 연결
    conn->smb[0].pending = pr; // pending 리스트의 헤드를 새로 만든 pr 노드로 갱신
} // record_pending_read 함수 끝



static void handle_read_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) { // SMB READ 응답 패킷을 처리하여, 미리 기록해 둔 pending READ 요청과 매칭 후 실제 파일에 데이터를 써주는 함수

    if (len < 16) return; // 최소한 data_offset과 data_length를 읽을 수 있을 만큼의 길이가 안 되면 잘못된 패킷이므로 그냥 무시

    uint16_t data_offset = body[2] | (body[3] << 8); // body[2..3]에서 little-endian 방식으로 DataOffset 필드를 읽어옴(헤더 시작으로부터 응답 데이터까지의 오프셋)
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24); // body[4..7]에서 little-endian 방식으로 DataLength(응답 데이터 길이)를 읽어 32비트로 조합

    if (data_offset < 64) return; // SMB2 본문(body)이 실제 페이로드 시작 기준으로 64바이트 헤더 뒤에 데이터가 온다고 가정하고, 그보다 작은 오프셋이면 이상한 패킷이므로 무시

    size_t data_start = (size_t)data_offset - 64; // body 포인터 기준에서 실제 데이터가 시작되는 위치를 계산(본문에서 64바이트 이후부터 실제 데이터라 가정)

    if (len < data_start + data_length) return; // body의 전체 길이가 계산된 데이터 시작 위치 + 데이터 길이보다 작으면 데이터가 잘린 것이므로 무시

    pending_read_t **prev_ptr = &conn->smb[0].pending; // 연결의 pending 리스트에서 요소를 제거하기 위해 이전 노드를 가리키는 포인터의 포인터(헤드 포인터 주소부터 시작)
    pending_read_t *pr = conn->smb[0].pending; // 실제로 리스트를 순회할 포인터, 처음에는 헤드 노드를 가리킴

    while (pr) { // pending 리스트의 끝(NULL)까지 순회
        if (pr->msg_id == msg_id) break; // 현재 노드의 msg_id가 응답의 msg_id와 같으면 해당 요청을 찾았으므로 반복문 탈출
        prev_ptr = &pr->next; // 다음 노드를 가리키는 포인터 주소를 prev_ptr에 저장(한 노드씩 뒤로 이동하기 위해)
        pr = pr->next; // 실제 노드 포인터를 다음 노드로 이동
    }

    if (!pr) return; // 동일한 msg_id를 가진 pending READ 요청을 찾지 못했으면(예: 이미 처리됐거나 기록 안 됨) 그냥 함수 종료

    *prev_ptr = pr->next; // 연결 리스트에서 pr 노드를 제거: 이전 노드가 가리키던 next를 pr 다음 노드로 바꿔서 pr을 건너뛰게 함

    write_file_chunk(pr->file_id, pr->offset, body + data_start, data_length); // 찾은 pending 정보(pr)에 따라, 응답 데이터(body + data_start, data_length)를 해당 파일의 pr->offset 위치에 써 넣음

    free(pr); // 사용이 끝난 pending_read_t 노드를 해제하여 메모리 누수 방지
} // handle_read_response 함수 끝


static void record_pending_create(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) { // SMB2 CREATE 요청을 임시로 기록해두는 함수. 나중에 응답에서 FileId와 파일명을 매칭하기 위해 사용
    /* Note: Standard SMB2 NameOffset is usually at 44, but some versions use 48.
     * If filename is not detected, try changing 44 to 48. */ // SMB2 CREATE에서 파일 이름 위치(NameOffset)는 보통 44이지만, 구현에 따라 48일 수도 있다는 주석(필요하면 수정하라는 안내)
    if (len < 52) return; // body 길이가 최소 52바이트보다 작으면 CREATE 요청 구조를 해석할 수 없으므로 그냥 무시하고 함수 종료
    
    /* Using 44 as standard offset (Header included). */ // SMB2 헤더(64바이트)를 포함한 전체 기준에서 44를 NameOffset 기준으로 사용 중이라는 설명
    /* If this fails, change body[44/45] to body[48/49] */ // 만약 파일명을 제대로 못 찾으면 인덱스를 44/45에서 48/49로 바꿔보라는 안내
    uint16_t name_offset = body[44] | (body[45] << 8); // body[44], body[45]를 little-endian 방식으로 합쳐서 NameOffset(파일 이름 시작 위치, 헤더 기준 오프셋)을 계산
    uint16_t name_length = body[46] | (body[47] << 8); // body[46], body[47]를 little-endian으로 합쳐서 NameLength(파일 이름 길이, 바이트 단위)를 계산
    
    if (name_length == 0) return; // 파일 이름 길이가 0이면(이름 없는 열기, 예: 루트 등) 저장할 필요가 없으므로 종료
    if (name_offset < 64) return; // NameOffset이 SMB2 헤더(64바이트)보다 작으면 비정상 값이므로 종료
    size_t rel = (size_t)name_offset - 64; // body 기준에서의 상대 오프셋 계산: header(64바이트)를 뺀 위치를 실제 body 내부 인덱스로 사용
    if (rel + name_length > len) return; // 계산된 시작 위치 + 길이가 전체 body 길이를 넘으면 범위를 벗어나는 것이므로 종료
    const uint8_t *name_utf16 = body + rel; // UTF-16LE로 인코딩된 파일명 문자열이 시작되는 위치 포인터
    char *utf8 = utf16le_to_utf8(name_utf16, name_length); // UTF-16LE 파일명을 UTF-8 문자열로 변환하여 동적 할당된 char*로 받음
    if (!utf8) return; // 변환에 실패했거나 메모리 할당 실패 시 그냥 종료
    
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t)); // CREATE 요청 정보를 저장할 pending_create_t 구조체를 0으로 초기화하여 동적 할당
    if (!pc) { free(utf8); return; } // 구조체 할당 실패 시 이미 만들어둔 utf8 문자열을 해제하고 종료(메모리 누수 방지)
    pc->msg_id = msg_id; // 이 CREATE 요청을 구분하기 위해 SMB2 메시지 ID를 구조체에 저장
    pc->name = utf8; // 변환된 UTF-8 파일명을 구조체에 연결(소유권을 pc가 가짐)
    pc->next = conn->pending_creates; // 새로운 노드를 연결 리스트 머리에 붙이기 위해 next를 현재 헤드로 지정
    conn->pending_creates = pc; // 연결 리스트 헤드를 새로 만든 pc로 갱신
} // record_pending_create 함수 끝

static void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name) { // CREATE 응답에서 받은 FileId와 파일명을 매핑 테이블에 저장하는 함수
    file_name_map_t *m; // file_name_map_t 연결 리스트를 순회하기 위한 포인터
    for (m = conn->file_names; m; m = m->next) { // 현재 커넥션에 이미 저장된 file_names 리스트를 처음부터 끝까지 순회
        if (memcmp(m->file_id, file_id, 16) == 0) return; // 동일한 FileId가 이미 등록되어 있으면 중복 저장할 필요 없으므로 그냥 반환
    }
    char safe[512]; // 파일명을 sanitize(경로 세탁)한 결과를 담을 버퍼(최대 511문자 + 널)
    sanitize_path(orig_name, safe, sizeof(safe)); // 원래 파일명(orig_name)을 안전한 형태(safe)로 변환(디렉터리 탈출, 특수 문자 제거 등)
    m = (file_name_map_t *)calloc(1, sizeof(file_name_map_t)); // 새로운 파일 이름 매핑 구조체를 동적 할당 및 0 초기화
    if (!m) return; // 메모리 할당 실패 시 아무 작업 없이 종료
    memcpy(m->file_id, file_id, 16); // 이 매핑 엔트리가 담당하는 FileId(16바이트)를 구조체에 복사
    m->name = strdup(safe); // sanitize된 파일명을 동적 할당하여 구조체의 name에 저장(문자열의 소유권을 m이 가지게 됨)
    if (!m->name) { free(m); return; } // 문자열 할당 실패 시 구조체 m을 해제하고 종료
    m->next = conn->file_names; // 새 엔트리를 file_names 연결 리스트의 머리에 삽입하기 위해 next를 기존 헤드로 설정
    conn->file_names = m; // file_names 리스트의 헤드를 새 엔트리 m으로 갱신
} // remember_file_name 함수 끝

static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) { // SMB2 CREATE 응답을 처리하여 FileId와 이전에 기록한 파일명을 매핑하는 함수
    pending_create_t **prev_ptr = &conn->pending_creates; // pending CREATE 요청 리스트에서 노드를 제거하기 위해 '이전 노드의 next 포인터'를 가리키는 포인터의 포인터
    pending_create_t *pc = conn->pending_creates; // 실제로 순회할 pending_create_t 포인터, 리스트의 첫 노드부터 시작
    while (pc) { // 리스트 끝(NULL)이 될 때까지 순회
        if (pc->msg_id == msg_id) break; // 이 CREATE 응답의 msg_id와 일치하는 pending 노드를 찾으면 반복문 탈출
        prev_ptr = &pc->next; // 현재 노드의 next 멤버의 주소를 prev_ptr에 넣어 다음 반복에서 사용할 준비
        pc = pc->next; // 실제 노드 포인터를 다음 노드로 이동
    }
    if (!pc) return; // 동일한 msg_id를 가진 pending CREATE 요청이 없으면(기록 안 됐거나 이미 처리됨) 아무 작업 없이 종료
    if (len < 80) return; // CREATE 응답 body에서 FileId를 읽기 위해서는 최소 80바이트가 필요하다고 가정, 부족하면 종료
    const uint8_t *file_id = body + 64; // SMB2 CREATE Response 구조에서 FileId가 body 시작 기준 64바이트 오프셋에 있다고 가정하고 포인터 설정
    remember_file_name(conn, file_id, pc->name); // 찾은 FileId와 pending CREATE에 기록된 파일명을 매핑 테이블에 저장
    *prev_ptr = pc->next; // 연결 리스트에서 pc 노드를 제거: 이전 노드의 next를 pc 다음 노드로 변경
    free(pc->name); // pc가 소유하고 있던 파일명 문자열 메모리 해제
    free(pc); // pending_create_t 구조체 자체도 해제하여 메모리 누수 방지
} // handle_create_response 함수 끝

static void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) { // 하나의 TCP 페이로드(msg) 안에 포함된 SMB2 메시지들을 파싱하고, 각 명령에 맞게 처리하는 메인 파서 함수
    size_t offset = 0; // 현재 msg 버퍼 내에서 어느 위치까지 처리했는지를 나타내는 오프셋(바이트 단위)
    while (offset < len) { // offset이 전체 길이보다 작을 동안 계속해서 다음 SMB2 메시지를 파싱
        if (len - offset < 64) break; // 남은 데이터가 SMB2 헤더 최소 크기(64바이트)보다 작으면 더 이상 SMB2 메시지가 없다고 보고 루프 종료
        const uint8_t *hdr = msg + offset; // 현재 SMB2 메시지의 헤더 시작 위치(64바이트짜리 SMB2 헤더의 첫 바이트)를 가리키는 포인터
        if (!(hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B')) break; // 헤더 앞 4바이트가 0xFE 'S' 'M' 'B'가 아니면 SMB2 시그니처가 아니므로 파싱 중단
        uint16_t command = hdr[12] | (hdr[13] << 8); // SMB2 Command 코드(예: READ, WRITE, CREATE 등)를 little-endian으로 읽어옴
        uint32_t flags = hdr[16] | (hdr[17] << 8) | (hdr[18] << 16) | (hdr[19] << 24); // SMB2 Flags 필드를 32비트 정수로 조합(응답 여부, 기타 플래그 포함)
        uint32_t next_cmd = hdr[20] | (hdr[21] << 8) | (hdr[22] << 16) | (hdr[23] << 24); // 이 메시지 안에서 다음 SMB2 헤더까지의 오프셋(멀티플렉스된 여러 명령 처리용)
        uint64_t msg_id = 0; // SMB2 MessageId를 저장할 64비트 변수, 0으로 초기화
        for (int i = 0; i < 8; i++) msg_id |= ((uint64_t)hdr[24 + i]) << (8 * i); // hdr[24..31]의 8바이트를 little-endian으로 합쳐서 msg_id 구성
        int is_response = (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0; // Flags에 서버→클라이언트 방향 비트가 설정되어 있으면 응답 패킷으로 판단(1이면 응답, 0이면 요청)
        size_t body_len; // 헤더 이후의 본문 길이를 저장할 변수
        if (next_cmd == 0) { // next_cmd가 0이면 이 SMB2 메시지가 패킷 안에서 마지막 메시지라는 의미
            body_len = (len > offset + 64) ? len - offset - 64 : 0; // 전체 남은 길이에서 헤더 64바이트를 뺀 값을 body 길이로 사용(남은 게 없으면 0)
        } else { // next_cmd가 0이 아니면 현재 헤더에서 next_cmd 바이트 떨어진 위치에 다음 SMB2 헤더가 있다는 의미
            if (next_cmd < 64 || offset + next_cmd > len) break; // next_cmd가 비정상(64보다 작거나 전체 길이를 넘어가면)일 경우 파싱 중단
            body_len = next_cmd - 64; // 현재 헤더부터 다음 헤더까지 거리에서 헤더 64바이트를 뺀 값이 현재 메시지의 body 길이
        }
        const uint8_t *body = hdr + 64; // SMB2 헤더 바로 뒤부터 시작하는 본문 영역의 포인터
        
        if (!is_response) { // 클라이언트 → 서버 방향 요청 패킷일 때 처리
            if (command == SMB2_READ && dir == 0) { // 명령이 SMB2_READ이고, dir이 0(예: 클라이언트→서버 방향으로 정의)일 때
                record_pending_read(conn, msg_id, body, body_len); // 이 READ 요청을 나중에 응답과 매칭하기 위해 pending 리스트에 기록
            } else if (command == SMB2_WRITE && dir == 0) { // 명령이 SMB2_WRITE이고, 클라이언트→서버 방향일 때(서버로 쓰기 요청)
                if (body_len >= 32) { // WRITE 요청의 기본 구조를 해석할 수 있을 만큼 body 길이가 충분한지 체크(최소 32바이트)
                    uint16_t data_offset = body[2] | (body[3] << 8); // body[2..3]에서 DataOffset(헤더+본문 기준 데이터 시작 위치)을 읽어옴
                    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24); // body[4..7]에서 DataLength(쓰려는 데이터 길이)를 읽어 32비트로 조합
                    uint64_t file_offset = 0; // 파일 내에서 쓰기 시작할 위치를 저장할 64비트 변수
                    for (int i = 0; i < 8; i++) file_offset |= ((uint64_t)body[8 + i]) << (8 * i); // body[8..15]의 8바이트를 little-endian으로 합쳐 file_offset 계산
                    const uint8_t *file_id = body + 24; // body[24..39] 위치에 있는 16바이트를 FileId라고 가정하고 그 시작 주소를 포인터로 저장
                    if (data_offset >= 64) { // DataOffset이 최소 64 이상(헤더 끝 이후)인지 확인, 아니면 비정상
                        size_t data_start = (size_t)data_offset - 64; // body 기준에서 실제 데이터가 시작되는 위치를 계산(헤더 64바이트 제외)
                        if (body_len >= data_start + data_length) { // body 전체 길이가 계산된 시작 위치 + 길이를 충분히 포함하는지 확인(잘리지 않았는지 체크)
                            write_file_chunk(file_id, file_offset, body + data_start, data_length); // 해당 FileId의 file_offset 위치에 data_length만큼의 데이터를 파일에 기록
                        }
                    }
                }
            } else if (command == SMB2_CREATE && dir == 0) { // 명령이 SMB2_CREATE이고, 클라이언트→서버 방향일 때(파일/핸들 생성 요청)
                record_pending_create(conn, msg_id, body, body_len); // 이 CREATE 요청에서 파일명을 추출해 pending_create 리스트에 저장(나중에 응답과 매칭)
            }
        } else { // 서버 → 클라이언트 방향 응답 패킷일 때 처리
            if (command == SMB2_READ && dir == 1) { // 명령이 SMB2_READ 응답이고, dir==1(예: 서버→클라이언트 방향으로 정의)일 때
                handle_read_response(conn, msg_id, body, body_len); // 이전에 기록한 READ 요청과 매칭하여 응답 데이터를 파일에 써 넣음
            } else if (command == SMB2_CREATE && dir == 1) { // 명령이 SMB2_CREATE 응답이고, 서버→클라이언트 방향일 때
                handle_create_response(conn, msg_id, body, body_len); // CREATE 응답의 FileId와 pending CREATE의 파일명을 매칭하여 이름 매핑 테이블에 저장
            }
        }
        if (next_cmd == 0) break; // next_cmd가 0이면 현재 SMB2 헤더가 이 TCP 페이로드에서 마지막 메시지이므로 루프 종료
        offset += next_cmd; // 다음 SMB2 헤더가 있는 위치로 offset을 이동하여 다음 메시지를 파싱
    } // while 루프 끝
} // parse_smb2_message 함수 끝


static void create_file_id_smb1(const connection_t *conn, uint16_t fid, uint8_t file_id[16]) { // SMB1의 FID + 연결 정보(IP/PORT)를 조합해서 16바이트짜리 내부용 file_id를 만들어 주는 함수
    memset(file_id, 0, 16); // file_id 배열 전체를 0으로 초기화해서 깔끔한 상태에서 시작
    file_id[0] = (uint8_t)(fid & 0xFF); // FID의 하위 8비트(LSB)를 file_id[0]에 저장
    file_id[1] = (uint8_t)((fid >> 8) & 0xFF); // FID의 상위 8비트(MSB)를 file_id[1]에 저장 → FID 16비트를 little-endian 형태로 2바이트에 담는 셈
    memcpy(&file_id[2], &conn->key.cli_ip, 4); // file_id[2..5]에 클라이언트 IP 주소 4바이트를 복사 (conn->key.cli_ip 값 그대로)
    uint16_t cli_port = htons(conn->key.cli_port); // 클라이언트 포트를 네트워크 바이트 순서(big-endian)로 변환해서 cli_port에 저장
    memcpy(&file_id[6], &cli_port, 2); // file_id[6..7]에 클라이언트 포트 2바이트를 복사
    memcpy(&file_id[8], &conn->key.srv_ip, 4); // file_id[8..11]에 서버 IP 주소 4바이트를 복사
    uint16_t srv_port = htons(conn->key.srv_port); // 서버 포트를 네트워크 바이트 순서로 변환해서 srv_port에 저장
    memcpy(&file_id[12], &srv_port, 2); // file_id[12..13]에 서버 포트 2바이트를 복사 (file_id[14..15]은 초기화 시점에 0)
} // create_file_id_smb1 함수 끝

static void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) { // 하나의 SMB1 메시지(msg, len)를 파싱해서 WRITE 계열 요청을 처리하는 함수
    if (len < 32) return; // SMB1 헤더(최소 32바이트)를 읽을 수 없으면 잘못된 패킷으로 보고 즉시 종료
    if (!(msg[0] == 0xFF && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'M')) return; // 첫 4바이트가 0xFF 'S' 'M' 'B'가 아니면 SMB1 시그니처가 아니므로 종료
    uint8_t command = msg[4]; // SMB1 헤더의 5번째 바이트는 Command 코드(예: WRITE, WRITE_ANDX 등) → 이 값을 command 변수에 저장
    if (len < 33) return; // 최소한 WordCount(1바이트)를 읽을 수 있는지 확인, 부족하면 종료
    uint8_t word_count = msg[32]; // SMB1 헤더의 33번째 바이트가 WordCount(2바이트 단위 파라미터 개수) → 몇 개의 2바이트 워드를 params에 담았는지 의미
    const uint8_t *params = msg + 33; // 파라미터 영역 시작 주소: 헤더(32바이트) + word_count(1바이트) 뒤에서부터 시작
    size_t params_len = (size_t)word_count * 2; // 파라미터 총 길이는 word_count * 2바이트
    if (len < 33 + params_len + 2) return; // 전체 길이가 파라미터 + ByteCount(2바이트)를 포함할 만큼 충분하지 않으면 잘못된 패킷이므로 종료
    uint16_t byte_count = params[params_len] | (params[params_len + 1] << 8); // 파라미터 뒤에 이어지는 2바이트를 little-endian으로 읽어 ByteCount(데이터 영역 길이)를 구함
    const uint8_t *data_base = params + params_len + 2; // 데이터 영역 시작 주소: 파라미터 끝 + ByteCount(2바이트) 뒤부터
    if (data_base + byte_count > msg + len) return; // 데이터 영역 끝이 전체 메시지 범위를 넘어가면 잘못된 패킷이므로 종료
    if (dir != 0) return; // 이 코드는 dir == 0(예: 클라이언트 → 서버 방향)일 때만 SMB1 쓰기를 처리하도록 제한, 서버 → 클라이언트는 무시
    if (command == SMB1_COM_WRITE_ANDX) { // SMB1 WRITE ANDX(확장 WRITE) 명령일 때 처리
        if (word_count < 12) return; // WRITE_ANDX 구조에서 최소 12 워드(=24바이트)가 필요하므로 부족하면 종료
        uint16_t fid = params[6] | (params[7] << 8); // params[6..7]에 있는 FID(파일 핸들)를 little-endian으로 읽어옴
        uint16_t data_length = params[16] | (params[17] << 8); // params[16..17]에 있는 DataLength(실제 쓰려는 데이터 길이)를 읽어옴
        uint16_t data_offset = params[18] | (params[19] << 8); // params[18..19]에 있는 DataOffset(헤더 기준 데이터 시작 위치)를 읽어옴
        if (data_length == 0 || data_offset >= len) return; // 쓰기 길이가 0이거나 오프셋이 전체 길이를 넘어가면 이상한 패킷이므로 종료
        uint8_t file_id[16]; // SMB1용 file_id(내부 재조합에 사용될 16바이트 식별자) 버퍼
        create_file_id_smb1(conn, fid, file_id); // 현재 연결 정보와 FID를 기반으로 고유한 file_id를 생성
        write_file_chunk(file_id, 0, msg + data_offset, data_length); // file_id에 해당하는 파일의 offset=0 위치에 data_length만큼의 데이터를 써 줌 (여기서는 오프셋을 고려 안 하고 0으로 고정)
    } else if (command == SMB1_COM_WRITE) { // SMB1 기본 WRITE 명령일 때 처리
        if (word_count < 5) return; // 기본 WRITE 구조를 해석하기 위해 최소 5 워드(=10바이트)가 필요하므로 부족하면 종료
        uint16_t fid = params[0] | (params[1] << 8); // params[0..1]에 있는 FID(파일 핸들)를 little-endian으로 읽어옴
        uint16_t count = params[2] | (params[3] << 8); // params[2..3]에 있는 Count(쓰려는 데이터 길이)를 읽어옴
        if (count == 0) return; // 쓰기 길이가 0이면 실제로 쓸 데이터가 없으므로 종료
        size_t data_len = (count > byte_count) ? byte_count : count; // 실제 쓸 길이는 Count와 ByteCount 중 더 작은 값으로 제한(트렁크된 경우 방어 코드)
        uint8_t file_id[16]; // SMB1용 file_id 버퍼
        create_file_id_smb1(conn, fid, file_id); // FID와 연결 정보를 이용해 고유한 file_id를 생성
        write_file_chunk(file_id, 0, data_base, data_len); // file_id에 해당하는 파일의 offset=0 위치에 data_len만큼의 데이터를 써 줌(역시 오프셋은 고려하지 않고 0부터)
    }
} // parse_smb1_message 함수 끝

static void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) { // TCP 스트림에서 추출한 순서 보장 바이트(data)를 SMB 스트림 버퍼에 넣고, NBSS 단위로 잘라 SMB1/2 메시지를 파싱하는 함수
    smb_stream_t *s = &conn->smb[dir]; // 해당 방향(dir)에 대한 SMB 스트림 상태 구조체 포인터를 얻음 (버퍼, 길이 등 관리)
    ensure_capacity(s, s->buf_len + len); // 현재 버퍼에 기존 길이 + 새로 들어올 len 바이트를 담을 수 있도록 필요한 경우 메모리를 확장
    memcpy(s->buf + s->buf_len, data, len); // 스트림 버퍼의 끝(s->buf_len 위치)부터 새 데이터 len 바이트를 복사
    s->buf_len += len; // 버퍼에 쌓인 총 바이트 수를 len만큼 증가시킴
    size_t pos = 0; // 현재 버퍼에서 처리 중인 위치 인덱스(앞에서부터 차례대로 NBSS 블록을 떼어감)
    while (s->buf_len - pos >= 4) { // 남아 있는 데이터가 최소 4바이트 이상(=NBSS 헤더 크기)일 동안 반복
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3]; // NBSS 헤더[1..3]에서 3바이트 길이를 big-endian으로 읽어 NBSS payload 길이를 구함
        size_t total_len = 4 + nbss_len; // NBSS 전체 블록 길이 = 헤더 4바이트 + payload nbss_len 바이트
        if (s->buf_len - pos < total_len) break; // 현재 버퍼에 NBSS 한 블록을 다 담을 만큼 데이터가 없으면 다음 TCP 조각을 기다리기 위해 루프 종료
        const uint8_t *msg = s->buf + pos + 4; // 실제 SMB 메시지는 NBSS 헤더 뒤 4바이트 이후부터 시작 → 그 시작 주소를 msg로 설정
        size_t msg_len = nbss_len; // SMB 메시지 길이는 NBSS payload 길이와 동일
        if (msg_len >= 4) { // 최소 4바이트는 있어야 SMB2/SMB1 시그니처(0xFE 'S' 'M' 'B' 또는 0xFF 'S' 'M' 'B')를 확인 가능
            if (msg[0] == 0xFE) { // 첫 바이트가 0xFE이면 SMB2 프로토콜로 간주
                parse_smb2_message(conn, dir, msg, msg_len); // SMB2 메시지 파서로 전달해서 READ/WRITE/CREATE 등을 처리
            } else if (msg[0] == 0xFF) { // 첫 바이트가 0xFF이면 SMB1 프로토콜로 간주
                parse_smb1_message(conn, dir, msg, msg_len); // SMB1 메시지 파서로 전달해서 WRITE 등을 처리
            }
        }
        pos += total_len; // 이번에 처리한 NBSS 블록 길이만큼 pos를 앞으로 이동해서 다음 블록을 가리키게 함
    }
    if (pos > 0) { // 버퍼 앞쪽에서 일부 NBSS 블록을 소비했다면 남은 데이터들만 앞으로 당겨서 버퍼 정리
        memmove(s->buf, s->buf + pos, s->buf_len - pos); // s->buf[pos..buf_len-1] 영역을 s->buf[0..]로 앞당겨 복사 (중첩 영역이라 memmove 사용)
        s->buf_len -= pos; // 전체 길이에서 소비한 부분(pos)을 빼서 새 버퍼 길이를 갱신
    }
} // smb_feed_bytes 함수 끝

static void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) { // TCP 세그먼트 하나(방향, SEQ, payload)를 받아 순서 재조합 후 SMB 레벨로 넘기는 함수
    tcp_stream_t *ts = &conn->tcp[dir]; // 해당 방향(dir)에 대한 TCP 스트림 상태 구조체 포인터(다음 SEQ, 초기화 여부 등 관리)
    if (len == 0) return; // 페이로드 길이가 0이면 처리할 내용이 없으므로 바로 종료
    if (!ts->has_next_seq) { // 아직 이 방향의 TCP 스트림에 대해 기대하는 다음 SEQ 값이 설정되지 않은 초기 상태라면
        ts->next_seq = seq + len; // 이번 세그먼트의 SEQ + len을 다음에 기대할 SEQ 값으로 설정
        ts->has_next_seq = 1; // 이제부터는 next_seq 유효하다고 표시
        smb_feed_bytes(conn, dir, payload, len); // 순서가 맞다고 보고 바로 SMB 스트림으로 payload를 넘겨 파싱 시도
        return; // 초기 세그먼트 처리 후 함수 종료
    }
    if (seq == ts->next_seq) { // 이번 세그먼트의 시작 SEQ가 기대하던 next_seq와 정확히 일치할 때(=정상 순서로 도착)
        ts->next_seq += len; // 다음에 기대할 SEQ를 len만큼 증가(=현재 세그먼트 끝 이후 위치)
        smb_feed_bytes(conn, dir, payload, len); // 순서가 맞는 데이터이므로 SMB 스트림으로 넘겨 파싱
    } // 그 외 (seq != next_seq)인 경우는 재전송/역순/손실 등 복잡한 상황인데, 여기 코드에서는 단순하게 무시
} // feed_tcp_payload 함수 끝


static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) { // pcap이 캡처한 각 패킷마다 호출되는 콜백 함수, Ethernet/IP/TCP/SMB 여부를 검사하고 SMB 트래픽만 처리
    if (h->caplen < 14) return; // 캡처된 길이가 이더넷 헤더(14바이트)보다 짧으면 잘못된 패킷이므로 바로 반환
    size_t offset = 14; // 이더넷 헤더 이후부터 IP 헤더가 시작된다고 가정하고 오프셋을 14로 설정
    uint16_t eth_type = (bytes[12] << 8) | bytes[13]; // 이더넷 헤더의 Type 필드(12~13바이트)를 big-endian으로 읽어 EtherType (IPv4/VLAN 등) 추출
    if (eth_type == 0x8100 && h->caplen >= 18) { // EtherType이 0x8100(VLAN 태깅)이고, 최소 VLAN 헤더까지 캡처되어 있을 때
        offset += 4; // VLAN 태그 헤더 길이(4바이트)를 건너뛰기 위해 오프셋을 4 증가시킴
        eth_type = (bytes[offset - 2] << 8) | bytes[offset - 1]; // VLAN 태그 뒤에 오는 실제 EtherType(마지막 2바이트)을 다시 읽어 IPv4 여부 확인
    }
    if (eth_type != 0x0800) return; // 최종 EtherType이 IPv4(0x0800)가 아니면 IP 패킷이 아니므로 처리하지 않고 반환
    const struct ip *ip = (const struct ip *)(bytes + offset); // 이더넷(+VLAN) 헤더 뒤에서 IP 헤더가 시작하는 위치를 struct ip 포인터로 캐스팅
    if (ip->ip_p != IPPROTO_TCP) return; // IP 헤더의 프로토콜 필드가 TCP가 아니면 SMB 트래픽이 아니므로 반환
    uint32_t ip_hdr_len = ip->ip_hl * 4; // ip_hl(4비트 단위 헤더 길이)를 실제 바이트 단위로 변환(4를 곱해서 IP 헤더 길이 계산)
    const struct tcphdr *tcp = (const struct tcphdr *)((const uint8_t *)ip + ip_hdr_len); // IP 헤더 뒤에서 TCP 헤더가 시작하는 위치를 struct tcphdr 포인터로 캐스팅
    size_t ip_len = ntohs(ip->ip_len); // IP 전체 길이(ip_len)를 네트워크 바이트 순서에서 호스트 바이트 순서로 변환하여 저장
    size_t tcp_hdr_len = tcp->th_off * 4; // TCP 헤더 길이 필드(th_off, 4바이트 단위)를 실제 바이트 단위로 변환(4를 곱함)
    if (ip_len < ip_hdr_len + tcp_hdr_len) return; // IP 전체 길이가 IP 헤더 + TCP 헤더보다 작다면 이상한 패킷이므로 무시
    size_t payload_len = ip_len - ip_hdr_len - tcp_hdr_len; // IP 전체 길이에서 IP 헤더와 TCP 헤더를 뺀 값이 TCP payload(데이터) 길이
    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len; // TCP 헤더 바로 뒤 위치가 실제 TCP payload 시작 주소
    uint16_t src_port = ntohs(tcp->th_sport); // TCP 소스 포트를 네트워크 바이트 순서에서 호스트 바이트 순서로 변환
    uint16_t dst_port = ntohs(tcp->th_dport); // TCP 목적지 포트를 네트워크 바이트 순서에서 호스트 바이트 순서로 변환
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139) return; // 양쪽 포트 모두 445/139(SMB 관련 포트)가 아니면 SMB 트래픽이 아니므로 반환
    conn_key_t key; // 연결(클라이언트/서버 IP+포트)을 식별하기 위한 키 구조체
    int dir; // 현재 패킷이 클라이언트→서버(0)인지 서버→클라이언트(1)인지를 나타내는 방향 플래그
    if ((src_port == 445 || src_port == 139) && (dst_port != 445 && dst_port != 139)) { // 소스 포트가 445/139이고, 목적지 포트가 SMB가 아니라면: 이 방향을 서버→클라이언트로 판단
        key.cli_ip = ip->ip_dst.s_addr; key.cli_port = dst_port; // 클라이언트 IP/포트는 목적지(클라이언트가 서비스 받는 쪽)로 설정
        key.srv_ip = ip->ip_src.s_addr; key.srv_port = src_port; // 서버 IP/포트는 소스(445/139에서 나오는 쪽)로 설정
        dir = 1; // 이 패킷은 서버→클라이언트 방향이라고 표시
    } else { // 그 외의 경우: 일반적으로 클라이언트→서버 방향(클라이언트가 445/139로 접속하는 쪽)
        key.cli_ip = ip->ip_src.s_addr; key.cli_port = src_port; // 클라이언트 IP/포트는 소스로 설정
        key.srv_ip = ip->ip_dst.s_addr; key.srv_port = dst_port; // 서버 IP/포트는 목적지로 설정(보통 445/139)
        dir = 0; // 이 패킷은 클라이언트→서버 방향이라고 표시
    }
    connection_t *conn = get_connection(&key); // 위에서 만든 key(클라이언트/서버 조합)에 해당하는 connection_t 구조체를 가져오거나 새로 생성
    uint32_t seq = ntohl(tcp->th_seq); // TCP SEQ 번호를 네트워크 바이트 순서에서 호스트 순서로 변환하여 seq 변수에 저장
    feed_tcp_payload(conn, dir, seq, payload, payload_len); // 이 연결/방향에 대한 TCP 페이로드를 SEQ 기반으로 재조합 스트림에 넣고 SMB 파서로 전달
} // packet_handler 함수 끝

int main(int argc, char *argv[]) { // 프로그램 진입점: 인터페이스명과 출력 디렉토리를 인자로 받아 실시간 SMB 트래픽을 캡처하고 파일을 복원
    if (argc != 3) { // 인자 개수가 3개(프로그램 이름 + 인터페이스 + 출력 디렉토리)가 아니면 사용법 안내
        fprintf(stderr, "Usage: sudo %s <interface> <output_dir>\n", argv[0]); // 올바른 사용법을 stderr로 출력 (예: sudo ./smb_live eth0 out_dir)
        return EXIT_FAILURE; // 잘못된 사용법이므로 실패 상태 코드로 종료
    }
    const char *dev = argv[1]; // 첫 번째 인자를 캡처 대상 네트워크 인터페이스 이름(dev)로 사용
    output_dir = argv[2]; // 두 번째 인자를 전역 변수 output_dir에 저장(복원된 파일들이 저장될 디렉토리 경로)
    if (access(output_dir, F_OK) != 0) { // 지정한 output_dir가 존재하는지 검사(F_OK: 존재 여부), 존재하지 않으면 0이 아님
        if (mkdir(output_dir, 0755) != 0) { // 디렉토리가 없으면 0755 권한으로 새 디렉토리 생성 시도, 실패 시 0이 아님
            perror("mkdir"); // mkdir 실패 원인을 표준 에러로 출력(시스템 에러 메시지 포함)
            return EXIT_FAILURE; // 디렉토리를 만들 수 없으므로 프로그램 실패 코드로 종료
        }
    }
    char errbuf[PCAP_ERRBUF_SIZE]; // pcap_open_live에서 에러 메시지를 담기 위한 버퍼(정해진 매크로 크기)
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf); // 지정한 인터페이스(dev)에서 실시간 캡처 핸들을 열기: 최대 65535바이트, promiscuous 모드(1), 타임아웃 1000ms
    if (!handle) { // pcap_open_live가 실패하면 handle이 NULL
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf); // 어떤 인터페이스에서 어떤 에러가 났는지 에러 버퍼와 함께 출력
        return EXIT_FAILURE; // 캡처 장치를 열 수 없으니 실패 코드로 종료
    }
    if (pcap_datalink(handle) != DLT_EN10MB) { // 캡처되는 링크 계층 타입이 이더넷(DLT_EN10MB)이 아닌 경우
        fprintf(stderr, "Unsupported link type. Only Ethernet is supported.\n"); // 현재 프로그램이 이더넷 헤더(14바이트)만 가정하므로 지원 안 한다는 메시지 출력
        pcap_close(handle); // 열어 둔 pcap 핸들을 닫아 자원 해제
        return EXIT_FAILURE; // 실패 코드로 종료
    }
    printf("Monitoring on %s... Press Ctrl+C to stop.\n", dev); // 어느 인터페이스에서 모니터링 중인지 사용자에게 안내 메시지 출력
    pcap_loop(handle, 0, packet_handler, NULL); // pcap 루프를 시작: 0이면 무한 루프, 각 패킷마다 packet_handler 콜백 호출, user 인자는 NULL
    pcap_close(handle); // pcap 루프가 끝나면(예: Ctrl+C) 캡처 핸들을 닫아 자원 해제
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) { // 파일 재조합 과정에서 열려 있던 모든 파일 컨텍스트 연결 리스트를 순회
        fflush(ctx->fp); // 각 파일 스트림에 버퍼링된 내용을 디스크로 강제 플러시
        fclose(ctx->fp); // 파일 스트림을 닫아 파일 핸들을 해제
    }
    return EXIT_SUCCESS; // 프로그램이 정상적으로 종료되었음을 나타내는 성공 코드 반환
} // main 함수 끝
