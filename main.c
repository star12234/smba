#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include "common.h"

char *output_dir = NULL; // 전역 변수 정의

/*
 * feed_tcp_payload
 * 역할: TCP 시퀀스를 확인하여 패킷 순서가 맞는지 검증 후 SMB 파서로 전달.
 * 인자: seq (현재 패킷의 시퀀스 번호), len (페이로드 길이)
 */
static void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) {
    tcp_stream_t *ts = &conn->tcp[dir];
    if (len == 0) return;

    /* 단순화된 재조합 로직: 순서가 맞거나 첫 패킷이면 처리 */
    if (!ts->has_next_seq) {
        ts->next_seq = seq + len;
        ts->has_next_seq = 1;
        smb_feed_bytes(conn, dir, payload, len);
    } else if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb_feed_bytes(conn, dir, payload, len);
    } else {
        // Out-of-order 패킷은 드롭 (복잡성 감소를 위해)
    }
}

/*
 * packet_handler
 * 역할: pcap 루프에서 호출되는 콜백 함수. 패킷 필터링 및 디스패치.
 */
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen < 14) return;
    
    /* 이더넷 헤더 건너뛰기 (IPv4 가정) */
    const struct ip *ip_hdr = (const struct ip *)(bytes + 14);
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    uint32_t ip_hlen = ip_hdr->ip_hl * 4;
    const struct tcphdr *tcp = (const struct tcphdr *)((uint8_t *)ip_hdr + ip_hlen);
    size_t tcp_hlen = tcp->th_off * 4;
    
    /* 페이로드 계산 */
    size_t total_len = ntohs(ip_hdr->ip_len);
    size_t payload_len = total_len - ip_hlen - tcp_hlen;
    const uint8_t *payload = (uint8_t *)tcp + tcp_hlen;

    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);

    /* 포트 필터링 (445 SMB) */
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139) return;

    /* 연결 키 생성 및 방향 결정 */
    conn_key_t key;
    int dir; // 0: 요청(C->S), 1: 응답(S->C)

    if (dst_port == 445 || dst_port == 139) {
        dir = 0; // Client -> Server
        key.cli_ip = ip_hdr->ip_src.s_addr; key.cli_port = src_port;
        key.srv_ip = ip_hdr->ip_dst.s_addr; key.srv_port = dst_port;
    } else {
        dir = 1; // Server -> Client
        key.cli_ip = ip_hdr->ip_dst.s_addr; key.cli_port = dst_port;
        key.srv_ip = ip_hdr->ip_src.s_addr; key.srv_port = src_port;
    }

    /* 처리 위임 */
    connection_t *conn = get_connection(&key);
    feed_tcp_payload(conn, dir, ntohl(tcp->th_seq), payload, payload_len);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <output_dir>\n", argv[0]);
        return 1;
    }
    char *dev = argv[1];
    output_dir = argv[2];
    mkdir(output_dir, 0755);

    char errbuf[PCAP_ERRBUF_SIZE];
    /* 실시간 캡처 오픈 (Promiscuous mode on) */
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "PCAP Open Failed: %s\n", errbuf);
        return 1;
    }

    printf("Sniffing on %s...\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    cleanup_files();
    cleanup_connections();
    return 0;
}
