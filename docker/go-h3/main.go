// quic-go HTTP/3 peer for GOAWAY interop testing.
//
//	goaway-h3 server --listen 0.0.0.0:4440 --cert cert.pem --key priv.key
//	goaway-h3 client URL [URL ...]
//
// The server answers /goaway by starting a graceful shutdown of that one
// connection (quic-go sends GOAWAY) while the response is still in flight.
// The client fetches each URL on one connection and prints one line per URL.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: goaway-h3 server|client ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		os.Exit(runClient(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "usage: goaway-h3 server|client ...")
		os.Exit(2)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:4440", "address to listen on")
	cert := fs.String("cert", "/certs/cert.pem", "certificate file")
	key := fs.String("key", "/certs/priv.key", "private key file")
	_ = fs.Parse(args)

	tlsCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{tlsCert}})
	ln, err := quic.ListenAddr(*listen, tlsConf, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on %s", *listen)
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go serveConn(conn)
	}
}

// One http3.Server per connection, so Shutdown drains that connection
// alone and the process keeps serving the next one.
func serveConn(conn *quic.Conn) {
	srv := &http3.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/goaway", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
		// Let the GOAWAY reach the client before the response ends.
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, " and done")
		log.Printf("%s: GOAWAY sent, response finished", conn.RemoteAddr())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	srv.Handler = mux
	if err := srv.ServeQUICConn(conn); err != nil {
		log.Printf("%s: %v", conn.RemoteAddr(), err)
	}
}

func runClient(urls []string) int {
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "usage: goaway-h3 client URL [URL ...]")
		return 2
	}
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	exit := 0
	for i, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			fmt.Printf("url=%d error=%v\n", i+1, err)
			if i == 0 {
				exit = 1
			}
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("url=%d error=%v\n", i+1, err)
			exit = 1
			continue
		}
		fmt.Printf("url=%d status=%d body=%s\n", i+1, resp.StatusCode, body)
		if resp.StatusCode != http.StatusOK && i == 0 {
			exit = 1
		}
	}
	return exit
}
