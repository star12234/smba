#include "common.h"

/* * file_ctx_t: 현재 열려있는 파일의 핸들 정보를 저장
 * 용도: 매번 fopen/fclose를 하면 느리므로, 한 번 열어둔 파일 포인터(fp)를 재사용하기 위함.
 */
typedef struct file_ctx {
    uint8_t file_id[16];    // 파일 ID (검색 키)
    FILE *fp;               // 열려있는 파일의 포인터 (fwrite에 사용)
    struct file_ctx *next;  // 리스트 관리를 위한 포인터
} file_ctx_t;

static file_ctx_t *open_files = NULL; // 열려있는 모든 파일 리스트의 헤드

/*
 * utf16le_to_utf8
 * 역할: SMB 패킷에 있는 2바이트 문자열(UTF-16)을 C언어 문자열(ASCII/UTF-8)로 변환
 * 변수 설명:
 * - data: 변환할 원본 바이트 배열 포인터
 * - byte_len: 원본 데이터의 길이 (바이트 단위)
 * - char_count: 글자 수 (바이트 길이 / 2)
 * - out: 변환된 문자열을 저장할 메모리 공간 (리턴값)
 */
char *utf16le_to_utf8(const uint8_t *data, size_t byte_len) {
    size_t char_count = byte_len / 2;
    char *out = (char *)calloc(char_count + 1, 1); // NULL 문자 포함 메모리 할당
    if (!out) return NULL;
    
    // i: 루프 카운터, 글자 단위로 반복
    for (size_t i = 0; i < char_count; i++) {
        // 간단하게 2바이트 중 앞바이트(ASCII 부분)만 취해서 저장
        // 한글 등의 경우 깨질 수 있으나 기본 동작엔 문제 없음
        out[i] = (char)data[i * 2];
    }
    return out;
}

/*
 * sanitize_path
 * 역할: 파일명에 포함된 위험하거나 불필요한 문자 제거 (보안 목적)
 * 변수 설명:
 * - in: 원본 파일명
 * - out: 정제된 파일명이 저장될 버퍼
 * - skip_leading: 경로 맨 앞의 슬래시(/)를 제거하기 위한 플래그
 * - c: 현재 검사 중인 문자 하나
 */
void sanitize_path(const char *in, char *out, size_t out_size) {
    size_t j = 0; // 출력 버퍼(out)의 현재 인덱스
    int skip_leading = 1;
    
    // i: 입력 문자열(in)을 순회하는 인덱스
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        char c = in[i];
        if (c == '\\') c = '/'; // 윈도우 경로 구분자를 리눅스용으로 변경
        if (i == 1 && in[1] == ':') continue; // C: 같은 드라이브 문자 건너뜀
        if (skip_leading && (c == '/' || c == '\\')) continue; // 맨 앞 슬래시 제거
        
        skip_leading = 0; // 첫 글자 이후로는 leading 체크 안 함
        
        // 상위 폴더(..)로 이동하는 해킹 시도 방지
        if (c == '.' && in[i + 1] == '.') {
            i++; 
            if (in[i + 1] == '/' || in[i + 1] == '\\') i++;
            continue;
        }
        // 파일명에 쓸 수 없는 특수문자 제거
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') continue;
        out[j++] = c; // 안전한 문자만 버퍼에 추가
    }
    out[j] = '\0'; // 문자열 끝 알림
}

/*
 * remember_file_name
 * 역할: 복구된 파일명을 메모리에 영구 저장 (나중에 WRITE 패킷이 오면 쓰려고)
 * 변수 설명:
 * - conn: 현재 연결 정보
 * - file_id: 매핑할 키값
 * - orig_name: 원본 파일명
 * - m: 새로 생성하거나 탐색할 매핑 구조체 포인터
 */
void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name) {
    file_name_map_t *m;
    // 이미 등록된 ID인지 확인
    for (m = conn->file_names; m; m = m->next) {
        if (memcmp(m->file_id, file_id, 16) == 0) return;
    }
    
    char safe[512]; // 정제된 파일명을 담을 임시 버퍼
    sanitize_path(orig_name, safe, sizeof(safe));
    
    // 새 매핑 정보 생성
    m = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    memcpy(m->file_id, file_id, 16);
    m->name = strdup(safe); // 문자열 복제하여 저장
    m->next = conn->file_names; // 리스트 맨 앞에 추가
    conn->file_names = m;
    
    printf("[INFO] Mapped ID to Name: %s\n", safe);
}

/* 디렉토리 자동 생성 함수 (mkdir -p 와 비슷) */
static void ensure_parent_dirs(const char *full_path) {
    char tmp[1024];
    if (strlen(full_path) >= sizeof(tmp)) return;
    strcpy(tmp, full_path);
    
    // p: 경로 문자열을 탐색하는 포인터
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { // 슬래시를 만나면
            *p = '\0';   // 잠시 문자열을 끊고
            mkdir(tmp, 0755); // 여기까지의 경로로 폴더 생성
            *p = '/';    // 다시 슬래시 복구
        }
    }
}

/*
 * write_file_chunk
 * 역할: 실제 데이터를 파일에 쓰는 핵심 함수
 * 변수 설명:
 * - ctx: 파일 핸들 정보를 담은 구조체 포인터 (캐싱용)
 * - path: 파일의 전체 경로를 저장할 문자열 버퍼
 * - m: 파일명 매핑 정보를 찾기 위한 순회용 포인터
 */
void write_file_chunk(connection_t *conn, const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    file_ctx_t *ctx;
    // 1. 이미 열려있는 파일 중에서 찾기
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0) break;
    }
    
    // 2. 없으면 새로 열기
    if (!ctx) {
        char path[1024];
        const file_name_map_t *m;
        const char *name = NULL;
        
        // 저장해둔 파일명 매핑 테이블 검색
        for (m = conn ? conn->file_names : NULL; m; m = m->next) {
            if (memcmp(m->file_id, file_id, 16) == 0) {
                name = m->name; // 찾았다!
                break;
            }
        }

        if (name) {
            // 이름을 찾았으면 그 이름으로 경로 생성
            snprintf(path, sizeof(path), "%s/%s", output_dir, name);
            ensure_parent_dirs(path);
        } else {
            // 못 찾았으면 Hex ID로 이름 생성
            char hexname[33];
            for (int i = 0; i < 16; i++) sprintf(&hexname[i * 2], "%02x", file_id[i]);
            snprintf(path, sizeof(path), "%s/%s.bin", output_dir, hexname);
        }

        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        memcpy(ctx->file_id, file_id, 16);
        ctx->fp = fopen(path, "wb"); // 바이너리 쓰기 모드로 파일 오픈
        
        if (!ctx->fp) {
            fprintf(stderr, "Failed to open %s\n", path);
            free(ctx);
            return;
        }
        printf("[IO] Created/Opened: %s\n", path);
        
        ctx->next = open_files;
        open_files = ctx;
    }
    
    // 3. 데이터 쓰기
    fseeko(ctx->fp, (off_t)offset, SEEK_SET); // 정확한 위치로 이동
    fwrite(data, 1, len, ctx->fp); // 데이터 기록
    fflush(ctx->fp); // 버퍼를 비워 즉시 디스크에 저장 (강제 종료 시 데이터 보호)
}

/* 프로그램 종료 시 호출되어 모든 파일을 닫음 */
void close_all_files() {
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        if (ctx->fp) fclose(ctx->fp);
    }
}