#include "common.h"
#include <unistd.h>

/* * file_ctx_t: 열려있는 파일의 핸들 관리
 * 용도: 매번 파일을 열고 닫으면 성능이 저하되므로 fp를 유지함.
 */
typedef struct file_ctx {
    uint8_t file_id[16];    // SMB 프로토콜의 File GUID
    char filename[256];     // 실제 파일명 (CREATE 패킷에서 복원됨)
    FILE *fp;               // 파일 포인터
    struct file_ctx *next;
} file_ctx_t;

static file_ctx_t *open_files = NULL; // 열린 파일 리스트 헤드

/*
 * register_file_mapping
 * 역할: CREATE 응답을 받았을 때, FileId와 파일명을 매핑하여 미리 컨텍스트 생성.
 * 인자: 
 * - file_id: 서버가 할당한 16바이트 ID
 * - filename: 클라이언트가 요청했던 파일명
 */
void register_file_mapping(const uint8_t *file_id, const char *filename) {
    file_ctx_t *ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
    memcpy(ctx->file_id, file_id, 16);
    strncpy(ctx->filename, filename, sizeof(ctx->filename) - 1);
    ctx->fp = NULL; /* 아직 데이터가 없으므로 파일은 열지 않음 */

    ctx->next = open_files;
    open_files = ctx;
    printf("[INFO] File Mapping Created: ID -> %s\n", filename);
}

/*
 * write_file_chunk
 * 역할: 실제 데이터를 디스크에 씀.
 * 로직: 
 * 1. 이미 매핑된 파일인지 확인.
 * 2. 매핑 없으면 Hex 이름으로 생성 (Fallback).
 * 3. 파일이 안 열려있으면 fopen.
 * 4. fseek로 오프셋 이동 후 fwrite.
 */
void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    file_ctx_t *ctx;
    /* 리스트 검색 */
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0)
            break;
    }

    /* 컨텍스트가 없으면(중간부터 캡처됨) Hex 이름으로 생성 */
    if (!ctx) {
        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        memcpy(ctx->file_id, file_id, 16);
        
        char hexname[33];
        for (int i = 0; i < 16; i++) sprintf(&hexname[i * 2], "%02x", file_id[i]);
        snprintf(ctx->filename, sizeof(ctx->filename), "%s.bin", hexname);
        
        ctx->next = open_files;
        open_files = ctx;
    }

    /* 파일 Open (최초 1회) */
    if (!ctx->fp) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", output_dir, ctx->filename);
        ctx->fp = fopen(path, "wb"); // wb: 바이너리 쓰기 (기존 내용 삭제됨)
        if (!ctx->fp) {
            fprintf(stderr, "[ERR] Failed to open file: %s\n", path);
            return;
        }
        printf("[IO] Writing to: %s (Offset: %lu, Len: %zu)\n", ctx->filename, offset, len);
    }

    /* 데이터 기록 */
    fseeko(ctx->fp, (off_t)offset, SEEK_SET);
    fwrite(data, 1, len, ctx->fp);
}

/* 프로그램 종료 시 파일 닫기 */
void cleanup_files() {
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        if (ctx->fp) {
            fflush(ctx->fp);
            fclose(ctx->fp);
        }
    }
}
