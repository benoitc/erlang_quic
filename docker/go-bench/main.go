// quic-go benchmark server for QUIC throughput comparison
//
// Supports two modes:
// - Upload: Client sends data, server sinks it
// - Download: Client sends 8-byte size, server sends that many bytes
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"io"
	"log"

	"github.com/quic-go/quic-go"
)

const alpnBench = "bench"

func main() {
	listen := flag.String("listen", "0.0.0.0:4434", "Address to listen on")
	certFile := flag.String("cert", "/certs/cert.pem", "Certificate file")
	keyFile := flag.String("key", "/certs/priv.key", "Private key file")
	flag.Parse()

	log.Printf("Starting quic-go benchmark server on %s", *listen)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnBench},
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:             30_000_000_000, // 30s in nanoseconds
		MaxIncomingStreams:         100,
		MaxIncomingUniStreams:      100,
		InitialStreamReceiveWindow: 16 * 1024 * 1024,
		MaxStreamReceiveWindow:     16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
	}

	listener, err := quic.ListenAddr(*listen, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", *listen)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "done")
	log.Printf("New connection from %s", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Accept stream error: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream quic.Stream) {
	defer stream.Close()
	streamID := stream.StreamID()

	// Read first chunk to determine mode
	header := make([]byte, 8)
	n, err := io.ReadFull(stream, header)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		log.Printf("Stream %d: read error: %v", streamID, err)
		return
	}

	// If we got exactly 8 bytes and then EOF, this is a download request
	if n == 8 {
		// Try to read one more byte to see if there's more data
		extra := make([]byte, 1)
		extraN, extraErr := stream.Read(extra)
		if extraN == 0 && (extraErr == io.EOF || extraErr == nil) {
			// Download mode: 8 bytes = size request
			size := binary.BigEndian.Uint64(header)
			log.Printf("Stream %d: download request for %d bytes", streamID, size)
			sendData(stream, int(size))
			return
		}
		// There's more data, this is upload mode
		// Process the header + extra byte, then continue reading
		bytesRecv := int64(n + extraN)
		bytesRecv += sinkData(stream)
		log.Printf("Stream %d: upload received %d bytes", streamID, bytesRecv)
	} else if n > 0 {
		// Upload mode: sink the data
		bytesRecv := int64(n)
		bytesRecv += sinkData(stream)
		log.Printf("Stream %d: upload received %d bytes", streamID, bytesRecv)
	}
}

func sinkData(stream quic.Stream) int64 {
	buf := make([]byte, 64*1024)
	var total int64
	for {
		n, err := stream.Read(buf)
		total += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	return total
}

func sendData(stream quic.Stream, size int) {
	buf := make([]byte, 32*1024)
	for i := range buf {
		buf[i] = 0x42
	}

	remaining := size
	for remaining > 0 {
		toWrite := remaining
		if toWrite > len(buf) {
			toWrite = len(buf)
		}
		n, err := stream.Write(buf[:toWrite])
		if err != nil {
			log.Printf("Stream %d: write error: %v", stream.StreamID(), err)
			return
		}
		remaining -= n
	}
	log.Printf("Stream %d: download complete, sent %d bytes", stream.StreamID(), size)
}
