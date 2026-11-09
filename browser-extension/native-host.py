#!/usr/bin/env python3

import json
import os
import socket
import struct
import sys
import time

MAX_MESSAGE_BYTES = 64 * 1024
EXTENSION_ORIGIN = "chrome-extension://mmehefpkhobgphfjkjlnebgbgfbmmmca/"
SOCKET_PATH = os.environ.get("PSST_BROWSER_SOCKET", "/run/psst/bridge.sock")
HANDOFF_TIMEOUT = 60
POLL_INTERVAL = 0.1


def read_message():
    header = sys.stdin.buffer.read(4)
    if len(header) != 4:
        raise ValueError("missing native-messaging header")

    length = struct.unpack("=I", header)[0]
    if length > MAX_MESSAGE_BYTES:
        raise ValueError("native-messaging request is too large")

    payload = sys.stdin.buffer.read(length)
    if len(payload) != length:
        raise ValueError("incomplete native-messaging request")

    return json.loads(payload)


def request_assertion_once(request):
    payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bridge:
        bridge.settimeout(20)
        bridge.connect(SOCKET_PATH)
        bridge.sendall(payload)
        bridge.shutdown(socket.SHUT_WR)

        response = bytearray()
        while len(response) <= MAX_MESSAGE_BYTES:
            chunk = bridge.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if response.endswith(b"\n"):
                break

    if len(response) > MAX_MESSAGE_BYTES:
        raise ValueError("psst browser response is too large")

    return json.loads(response)


def request_assertion(request):
    deadline = time.monotonic() + HANDOFF_TIMEOUT
    while True:
        response = request_assertion_once(request)
        if response.get("code") != "passkey_handoff_required":
            return response
        remaining = deadline - time.monotonic()
        if remaining <= POLL_INTERVAL:
            if remaining > 0:
                time.sleep(remaining)
            return response

        time.sleep(POLL_INTERVAL)


def write_message(response):
    payload = json.dumps(response, separators=(",", ":")).encode()
    sys.stdout.buffer.write(struct.pack("=I", len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {
        EXTENSION_ORIGIN,
        EXTENSION_ORIGIN.removesuffix("/"),
    }:
        raise ValueError("unexpected extension origin")

    write_message(request_assertion(read_message()))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        write_message(
            {
                "success": False,
                "code": "browser_bridge_unavailable",
                "error": str(error),
            }
        )
