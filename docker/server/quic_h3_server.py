#!/usr/bin/env python3
"""
HTTP/3 Server for E2E Testing

A full HTTP/3 server using aioquic that:
- Handles GET, POST, HEAD requests
- Serves files from document root
- Echoes POST body for /echo endpoint
- Supports trailers
- Logs all events for debugging
"""

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Tuple, List

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    HeadersReceived,
    DataReceived,
    H3Event,
)
# TrailersReceived may not exist in newer aioquic versions
try:
    from aioquic.h3.events import TrailersReceived
except ImportError:
    TrailersReceived = None
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ProtocolNegotiated,
    StreamDataReceived,
    QuicEvent,
)
from aioquic.quic.logger import QuicFileLogger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class RequestState:
    """Holds state for an HTTP/3 request."""

    def __init__(self) -> None:
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.headers: List[Tuple[bytes, bytes]] = []
        self.body: bytes = b""
        self.trailers: List[Tuple[bytes, bytes]] = []
        self.headers_received: bool = False
        self.body_complete: bool = False


class HttpServerProtocol(QuicConnectionProtocol):
    """HTTP/3 server protocol handler."""

    def __init__(self, *args, document_root: str = "/www", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._requests: Dict[int, RequestState] = {}
        self._document_root = Path(document_root)

    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC events."""
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic, enable_webtransport=False)
                logger.info(f"H3 connection established, ALPN: {event.alpn_protocol}")

        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        """Handle HTTP/3 events."""
        if isinstance(event, HeadersReceived):
            self._handle_headers(event.stream_id, event.headers, event.stream_ended)
        elif isinstance(event, DataReceived):
            self._handle_data(event.stream_id, event.data, event.stream_ended)
        elif TrailersReceived is not None and isinstance(event, TrailersReceived):
            self._handle_trailers(event.stream_id, event.headers)

    def _handle_headers(
        self, stream_id: int, headers: List[Tuple[bytes, bytes]], end_stream: bool
    ) -> None:
        """Handle incoming headers."""
        request = RequestState()
        request.headers = headers
        request.headers_received = True

        # Parse pseudo-headers
        for name, value in headers:
            if name == b":method":
                request.method = value.decode()
            elif name == b":path":
                request.path = value.decode()

        self._requests[stream_id] = request

        logger.info(
            f"Stream {stream_id}: {request.method} {request.path} "
            f"(end_stream={end_stream})"
        )

        # For GET/HEAD without body, respond immediately
        if end_stream and request.method in ("GET", "HEAD"):
            request.body_complete = True
            self._send_response(stream_id)

    def _handle_data(
        self, stream_id: int, data: bytes, end_stream: bool
    ) -> None:
        """Handle incoming body data."""
        request = self._requests.get(stream_id)
        if request is None:
            logger.warning(f"Stream {stream_id}: data received without headers")
            return

        request.body += data
        logger.info(
            f"Stream {stream_id}: received {len(data)} bytes body "
            f"(total: {len(request.body)}, end_stream={end_stream})"
        )

        if end_stream:
            request.body_complete = True
            self._send_response(stream_id)

    def _handle_trailers(
        self, stream_id: int, headers: List[Tuple[bytes, bytes]]
    ) -> None:
        """Handle incoming trailers."""
        request = self._requests.get(stream_id)
        if request is None:
            logger.warning(f"Stream {stream_id}: trailers received without headers")
            return

        request.trailers = headers
        logger.info(f"Stream {stream_id}: received trailers: {headers}")

    def _send_response(self, stream_id: int) -> None:
        """Send response for a request."""
        request = self._requests.get(stream_id)
        if request is None:
            return

        method = request.method or "GET"
        path = request.path or "/"

        # Route request
        if path == "/echo" and method == "POST":
            # Echo POST body
            body = request.body
            status = 200
            content_type = b"application/octet-stream"
        elif path == "/trailers" and method == "POST":
            # Echo with trailers
            self._send_with_trailers(stream_id, request)
            return
        elif path == "/goaway":
            # Test GOAWAY
            self._http.send_goaway(0)
            self.transmit()
            body = b"GOAWAY sent"
            status = 200
            content_type = b"text/plain"
        elif method == "HEAD":
            # HEAD request - read file for content-length but don't send body
            body, status, content_type = self._read_file(path)
            body = b""  # Don't send body for HEAD
        elif method == "GET":
            # Serve from document root
            body, status, content_type = self._read_file(path)
        elif method == "POST":
            # Default POST handler - echo body
            body = request.body
            status = 200
            content_type = b"application/octet-stream"
        else:
            body = b"Method Not Allowed"
            status = 405
            content_type = b"text/plain"

        self._send_simple_response(stream_id, status, content_type, body)

    def _read_file(self, path: str) -> Tuple[bytes, int, bytes]:
        """Read file from document root."""
        # Normalize path
        if path == "/":
            path = "/index.html"

        # Security: prevent directory traversal
        try:
            file_path = (self._document_root / path.lstrip("/")).resolve()
            if not str(file_path).startswith(str(self._document_root.resolve())):
                return b"Forbidden", 403, b"text/plain"
        except Exception:
            return b"Bad Request", 400, b"text/plain"

        # Read file
        if file_path.is_file():
            try:
                body = file_path.read_bytes()
                # Determine content type
                suffix = file_path.suffix.lower()
                content_types = {
                    ".html": b"text/html",
                    ".txt": b"text/plain",
                    ".json": b"application/json",
                    ".bin": b"application/octet-stream",
                }
                content_type = content_types.get(suffix, b"application/octet-stream")
                return body, 200, content_type
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
                return b"Internal Server Error", 500, b"text/plain"
        else:
            return b"Not Found", 404, b"text/plain"

    def _send_simple_response(
        self,
        stream_id: int,
        status: int,
        content_type: bytes,
        body: bytes,
    ) -> None:
        """Send a simple response with headers and body."""
        headers = [
            (b":status", str(status).encode()),
            (b"content-type", content_type),
            (b"content-length", str(len(body)).encode()),
        ]

        self._http.send_headers(stream_id, headers)

        if body:
            self._http.send_data(stream_id, body, end_stream=True)
        else:
            self._http.send_data(stream_id, b"", end_stream=True)

        self.transmit()
        logger.info(f"Stream {stream_id}: sent {status} ({len(body)} bytes)")

        # Clean up
        self._requests.pop(stream_id, None)

    def _send_with_trailers(self, stream_id: int, request: RequestState) -> None:
        """Send response with trailers."""
        headers = [
            (b":status", b"200"),
            (b"content-type", b"application/octet-stream"),
        ]

        self._http.send_headers(stream_id, headers)
        self._http.send_data(stream_id, request.body, end_stream=False)

        # Send trailers
        trailers = [
            (b"x-checksum", b"abc123"),
            (b"x-trailer-test", b"success"),
        ]
        self._http.send_headers(stream_id, trailers, end_stream=True)

        self.transmit()
        logger.info(f"Stream {stream_id}: sent response with trailers")

        # Clean up
        self._requests.pop(stream_id, None)


async def main(
    host: str,
    port: int,
    certificate: str,
    private_key: str,
    document_root: str,
    secrets_log: Optional[str] = None,
    quic_log: Optional[str] = None,
) -> None:
    """Run the HTTP/3 server."""

    # Configure QUIC
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )

    # Load certificate and key
    configuration.load_cert_chain(certificate, private_key)

    # Optional: secrets log for Wireshark
    if secrets_log:
        configuration.secrets_log_file = open(secrets_log, "a")

    # Optional: QUIC event logger
    quic_logger = None
    if quic_log:
        quic_logger = QuicFileLogger(quic_log)

    # Create document root if it doesn't exist
    doc_root = Path(document_root)
    if not doc_root.exists():
        logger.warning(f"Document root {document_root} does not exist")

    logger.info(f"Starting HTTP/3 server on {host}:{port}")
    logger.info(f"ALPN protocols: {H3_ALPN}")
    logger.info(f"Certificate: {certificate}")
    logger.info(f"Document root: {document_root}")

    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: HttpServerProtocol(
            *args, document_root=document_root, **kwargs
        ),
        retry=False,
    )

    logger.info("Server is running. Press Ctrl+C to stop.")
    await asyncio.Future()  # Run forever


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP/3 Server for E2E Testing")
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4435,
        help="Port to bind to (default: 4435)",
    )
    parser.add_argument(
        "--cert",
        type=str,
        required=True,
        help="Path to TLS certificate",
    )
    parser.add_argument(
        "--key",
        type=str,
        required=True,
        help="Path to TLS private key",
    )
    parser.add_argument(
        "--document-root",
        type=str,
        default="/www",
        help="Document root for serving files (default: /www)",
    )
    parser.add_argument(
        "--secrets-log",
        type=str,
        help="Path to secrets log file (for Wireshark)",
    )
    parser.add_argument(
        "--quic-log",
        type=str,
        help="Path to QUIC event log directory",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        asyncio.run(
            main(
                host=args.host,
                port=args.port,
                certificate=args.cert,
                private_key=args.key,
                document_root=args.document_root,
                secrets_log=args.secrets_log,
                quic_log=args.quic_log,
            )
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
