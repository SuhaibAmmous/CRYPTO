import argparse
import socket
import sys
import threading

import config
from protocol.transport import send_frame, recv_frame, TransportError
from protocol.handshake import perform_handshake, HandshakeError
from protocol.session import Session, SessionError, MSG_CHAT, MSG_CLOSE


def _open_socket(role: str, host: str, port: int) -> socket.socket:
    """Create the connected TCP socket for the given role."""
    if role == "server":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        print(f"[server] listening on {host}:{port} — waiting for a client...")
        conn, addr = listener.accept()
        listener.close()
        print(f"[server] client connected from {addr[0]}:{addr[1]}")
        return conn

    # client
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[client] connecting to {host}:{port} ...")
    sock.connect((host, port))
    print("[client] connected.")
    return sock


def _receiver_loop(sock: socket.socket, session: Session, stop: threading.Event) -> None:
    """Background thread: receive, authenticate, decrypt, and print messages."""
    while not stop.is_set():
        try:
            record = recv_frame(sock)
        except TransportError:
            print("\n[*] peer closed the connection.")
            stop.set()
            break
        try:
            msg_type, plaintext = session.decrypt(record)
        except SessionError as exc:
            # Replay, reorder, or tamper attempt — reject but stay alive.
            print(f"\n[!] rejected a record: {exc}")
            continue
        if msg_type == MSG_CLOSE:
            print("\n[*] peer ended the session.")
            stop.set()
            break
        peer = session._peer_id.decode("utf-8", "replace")
        print(f"\n{peer}: {plaintext.decode('utf-8', 'replace')}")
        print("you> ", end="", flush=True)


def run_chat(sock: socket.socket, session: Session) -> None:
    """Interactive send/receive loop. Type '/quit' or send EOF to exit."""
    stop = threading.Event()
    receiver = threading.Thread(
        target=_receiver_loop, args=(sock, session, stop), daemon=True
    )
    receiver.start()

    print("\n[*] secure channel established. Type messages and press Enter.")
    print("[*] commands: '/quit' to leave.\n")

    try:
        while not stop.is_set():
            try:
                line = input("you> ")
            except EOFError:
                break
            if stop.is_set():
                break
            if line.strip() == "/quit":
                break
            try:
                send_frame(sock, session.encrypt(line.encode("utf-8"), MSG_CHAT))
            except TransportError:
                print("[*] connection lost while sending.")
                break
    except KeyboardInterrupt:
        pass
    finally:
        if not stop.is_set():
            try:
                send_frame(sock, session.encrypt(b"", MSG_CLOSE))
            except (TransportError, OSError):
                pass
        stop.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        print("[*] disconnected.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecureChannel — authenticated, encrypted TCP chat."
    )
    parser.add_argument("--role", required=True, choices=["server", "client"],
                        help="run as server (waits) or client (connects)")
    parser.add_argument("--host", default=config.DEFAULT_HOST,
                        help=f"host to bind/connect (default {config.DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT,
                        help=f"TCP port (default {config.DEFAULT_PORT})")
    args = parser.parse_args()

    try:
        sock = _open_socket(args.role, args.host, args.port)
    except OSError as exc:
        print(f"[!] socket error: {exc}", file=sys.stderr)
        return 1

    try:
        keys = perform_handshake(
            sock, args.role, config.PSK,
            config.CLIENT_ID, config.SERVER_ID, config.PROTOCOL_VERSION,
        )
    except (HandshakeError, TransportError) as exc:
        print(f"[!] handshake failed: {exc}", file=sys.stderr)
        sock.close()
        return 1

    print("[*] handshake complete — keys derived, peer authenticated.")
    session = Session(args.role, keys, config.PROTOCOL_VERSION_BYTE)
    run_chat(sock, session)
    return 0


if __name__ == "__main__":
    sys.exit(main())
