#!/usr/bin/env python3
"""
Simple HTTP/3 client for testing.
Uses aioquic to make HTTP/3 requests.

Usage:
    python http3_client.py [options] URL [URL ...]

Options:
    --insecure          Skip certificate verification
    --output-dir DIR    Directory to save responses
    --data FILE         File to POST
    -v                  Verbose output
"""

import argparse
import asyncio
import os
import ssl
import sys
from urllib.parse import urlparse

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DataReceived,
    HeadersReceived,
    H3Event,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._request_events = {}
        self._request_waiter = {}

    def http_event_received(self, event: H3Event):
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                self._request_events[stream_id].append(event)
                if event.stream_ended:
                    waiter = self._request_waiter.pop(stream_id, None)
                    if waiter is not None:
                        waiter.set_result(None)

    def quic_event_received(self, event):
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def get(self, url: str, headers: dict = None) -> tuple:
        """Perform HTTP GET request."""
        return await self._request("GET", url, headers or {}, None)

    async def post(self, url: str, data: bytes, headers: dict = None) -> tuple:
        """Perform HTTP POST request."""
        return await self._request("POST", url, headers or {}, data)

    async def head(self, url: str, headers: dict = None) -> tuple:
        """Perform HTTP HEAD request."""
        return await self._request("HEAD", url, headers or {}, None)

    async def _request(self, method: str, url: str, headers: dict, data: bytes) -> tuple:
        parsed = urlparse(url)
        authority = parsed.netloc
        path = parsed.path or "/"

        if self._http is None:
            self._http = H3Connection(self._quic)

        stream_id = self._quic.get_next_available_stream_id()
        self._request_events[stream_id] = []

        # Build headers
        request_headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ]
        for name, value in headers.items():
            request_headers.append((name.encode(), value.encode()))

        if data is not None:
            request_headers.append((b"content-length", str(len(data)).encode()))

        # Send headers
        self._http.send_headers(
            stream_id=stream_id,
            headers=request_headers,
            end_stream=(data is None),
        )

        # Send body if present
        if data is not None:
            self._http.send_data(
                stream_id=stream_id,
                data=data,
                end_stream=True,
            )

        # Transmit
        self.transmit()

        # Wait for response
        waiter = self._loop.create_future()
        self._request_waiter[stream_id] = waiter
        await asyncio.wait_for(waiter, timeout=30.0)

        # Process events
        status = None
        response_headers = []
        body = b""

        for event in self._request_events[stream_id]:
            if isinstance(event, HeadersReceived):
                for name, value in event.headers:
                    if name == b":status":
                        status = int(value.decode())
                    else:
                        response_headers.append((name.decode(), value.decode()))
            elif isinstance(event, DataReceived):
                body += event.data

        return status, response_headers, body


async def main():
    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument("urls", nargs="+", help="URLs to request")
    parser.add_argument("--insecure", action="store_true", help="Skip certificate verification")
    parser.add_argument("--output-dir", help="Directory to save responses")
    parser.add_argument("--data", help="File to POST")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Configure QUIC
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
    )
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE

    # Read POST data if provided
    post_data = None
    if args.data:
        with open(args.data, "rb") as f:
            post_data = f.read()

    # Process each URL
    exit_code = 0
    for url in args.urls:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        if args.verbose:
            print(f"Connecting to {host}:{port}...")

        try:
            async with connect(
                host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
            ) as client:
                client = client  # type: HttpClient

                if post_data is not None:
                    status, headers, body = await client.post(url, post_data)
                else:
                    status, headers, body = await client.get(url)

                if args.verbose:
                    print(f"Status: {status}")
                    for name, value in headers:
                        print(f"  {name}: {value}")
                    print(f"Body: {len(body)} bytes")

                # Save to output directory
                if args.output_dir:
                    os.makedirs(args.output_dir, exist_ok=True)
                    filename = os.path.basename(parsed.path) or "index.html"
                    output_path = os.path.join(args.output_dir, filename)
                    with open(output_path, "wb") as f:
                        f.write(body)
                    if args.verbose:
                        print(f"Saved to: {output_path}")

                if status != 200:
                    exit_code = 1

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
