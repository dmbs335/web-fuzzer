"""Minimal SCGI server that returns Location header for internal redirect."""
import socket
import sys
import os

def netstring(data):
    """SCGI netstring encoding."""
    return f"{len(data)}:{data},".encode()

def handle_request(conn):
    # Read SCGI request
    data = b""
    while True:
        chunk = conn.recv(8192)
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data or len(data) > 65536:
            break
    
    # Parse enough to get REQUEST_URI
    request_uri = "/"
    try:
        # SCGI: netstring of null-separated key=value pairs
        colon = data.index(b":")
        length = int(data[:colon])
        headers_data = data[colon+1:colon+1+length]
        headers = headers_data.split(b"\x00")
        for i in range(0, len(headers)-1, 2):
            if headers[i] == b"REQUEST_URI":
                request_uri = headers[i+1].decode()
    except:
        pass
    
    # Determine response based on path
    redirect_target = os.environ.get("REDIRECT_TARGET", "/server-status")
    
    if "/trigger-redirect" in request_uri:
        # Return Location header to trigger internal redirect
        body = ""
        response = (
            f"Status: 200 OK\r\n"
            f"Location: {redirect_target}\r\n"
            f"Content-Type: text/html\r\n"
            f"\r\n"
            f"{body}"
        )
    else:
        body = f"<html>SCGI Backend - URI: {request_uri}</html>"
        response = (
            f"Status: 200 OK\r\n"
            f"Content-Type: text/html\r\n"
            f"\r\n"
            f"{body}"
        )
    
    conn.sendall(response.encode())
    conn.close()

def main():
    port = int(os.environ.get("SCGI_PORT", "4000"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(5)
    print(f"SCGI server on port {port}", flush=True)
    while True:
        conn, addr = sock.accept()
        try:
            handle_request(conn)
        except Exception as e:
            print(f"Error: {e}", flush=True)
            try: conn.close()
            except: pass

if __name__ == "__main__":
    main()
