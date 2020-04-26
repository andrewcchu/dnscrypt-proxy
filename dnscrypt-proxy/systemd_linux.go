// +build !android

package main

import (
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) addSystemDListeners() error {
	files := activation.Files(true)

	if len(files) > 0 {
		if len(proxy.userName) > 0 || proxy.child {
			dlog.Fatal("Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.")
		}
		dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
	}
	for i, file := range files {
		defer file.Close()
		if listener, err := net.FileListener(file); err == nil {
			dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listener.Addr())
			proxy.tcpListener = append(proxy.tcpListener, listener.(*net.TCPListener))
		} else if pc, err := net.FilePacketConn(file); err == nil {
			dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), pc.LocalAddr())
			proxy.udpListener = append(proxy.udpListener, listener.(*net.UDPConn))
		}
	}
	return nil
}
