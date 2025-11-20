#include "common.h"

static connection_t *connections = NULL; // 전역 연결 리스트

/*
 * conn_key_equal
 * 역할: 두 키(IP/Port 쌍)가 동일한지 비교.
 * 리턴: 같으면 1, 다르면 0
 */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

/*
 * get_connection
 * 역할: 키에 해당하는 연결 구조체를 찾거나, 없으면 새로 생성하여 반환.
 */
connection_t *get_connection(const conn_key_t *key) {
    connection_t *c;
    /* 기존 연결 검색 */
    for (c = connections; c; c = c->next) {
        if (conn_key_equal(&c->key, key))
            return c;
    }
    /* 신규 연결 생성 및 초기화 */
    c = (connection_t *)calloc(1, sizeof(connection_t));
    if (!c) { fprintf(stderr, "OOM\n"); exit(1); }
    
    c->key = *key;
    c->next = connections; // Head에 삽입
    connections = c;
    return c;
}

/* 메모리 정리 (프로그램 종료 시) */
void cleanup_connections() {
    connection_t *c = connections;
    while (c) {
        connection_t *next = c->next;
        // 버퍼 및 대기열 메모리 해제 로직 필요
        free(c->smb[0].buf);
        free(c->smb[1].buf);
        free(c);
        c = next;
    }
}
