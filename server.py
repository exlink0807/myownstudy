"""
server.py

client.c 가 접속할 로컬 테스트 서버.
자체 프로토콜: [4B length][2B type][2B reserved] + [BSON payload]

실행: python server.py
(client.c 를 빌드해서 실행하기 전에 먼저 켜 두세요)
"""

import socket
import struct
import bson  # pip install bson

HEADER_FMT = "<IHH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_client(conn, addr):
    print(f"[server] 연결됨: {addr}")
    try:
        while True:
            header_raw = recv_exact(conn, HEADER_SIZE)
            if header_raw is None:
                break
            total_len, packet_type, reserved = struct.unpack(HEADER_FMT, header_raw)

            payload_raw = recv_exact(conn, total_len)
            if payload_raw is None:
                break

            doc = bson.loads(payload_raw)
            print(f"[server] type={packet_type} payload={doc}")

            # 간단한 ack 응답
            ack_doc = {"type": "ack", "for": doc.get("type", "unknown"), "status": "ok"}
            ack_payload = bson.dumps(ack_doc)
            ack_header = struct.pack(HEADER_FMT, len(ack_payload), 100, 0)
            conn.sendall(ack_header + ack_payload)
    finally:
        conn.close()
        print(f"[server] 연결 종료: {addr}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 9000))
    srv.listen(1)
    print("[server] 127.0.0.1:9000 에서 대기 중...")

    while True:
        conn, addr = srv.accept()
        handle_client(conn, addr)


if __name__ == "__main__":
    main()
