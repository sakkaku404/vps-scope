//go:build ignore

// VPS Scope disposable-lab network helper. It is not part of release binaries.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	mode := flag.String("mode", "serve", "serve or probe")
	network := flag.String("network", "tcp4", "tcp4, tcp6, udp4, or udp6")
	address := flag.String("address", "127.0.0.1:39081", "listen or remote address")
	timeout := flag.Duration("timeout", 4*time.Second, "probe timeout")
	flag.Parse()
	var err error
	if *mode == "serve" {
		err = serve(*network, *address)
	} else if *mode == "probe" {
		err = probe(*network, *address, *timeout)
	} else {
		err = fmt.Errorf("unsupported mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(network, address string) error {
	if network == "tcp4" || network == "tcp6" {
		ln, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		defer ln.Close()
		fmt.Println("READY", ln.Addr())
		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(conn, io.LimitReader(conn, 64<<10))
			}()
		}
	}
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("READY", conn.LocalAddr())
	buf := make([]byte, 64<<10)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, _ = conn.WriteTo(buf[:n], peer)
	}
}

func probe(network, address string, timeout time.Duration) error {
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	payload := []byte("vps-scope-lab-probe")
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != string(payload) {
		return fmt.Errorf("unexpected echo response")
	}
	fmt.Println("PASS", network, address)
	return nil
}
