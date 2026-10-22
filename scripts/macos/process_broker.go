//go:build darwin

package process

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Only the root-owned foxVPN helper supplies this anonymous inherited socket.
// The core keeps its dedicated unprivileged UID. The helper returns paths only
// inside user-selected bundles, and accepts no PID, filename, command or URL.
type foxProcessSearcher struct {
	conn  net.Conn
	mutex sync.Mutex
}

func newFoxProcessSearcher() (Searcher, error, bool) {
	raw := os.Getenv("FOXVPN_PROCESS_FD")
	if raw == "" {
		return nil, nil, false
	}
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("invalid foxVPN process channel"), true
	}
	file := os.NewFile(uintptr(fd), "foxvpn-process-channel")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err, true
	}
	return &foxProcessSearcher{conn: conn}, nil, true
}
func (s *foxProcessSearcher) ResetCache()  {}
func (s *foxProcessSearcher) Close() error { return s.conn.Close() }
func (s *foxProcessSearcher) FindProcessInfo(ctx context.Context, network string, source, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !source.IsValid() || !destination.IsValid() {
		return nil, ErrNotFound
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	frame := make([]byte, 44)
	copy(frame, "FXP1")
	switch network {
	case "tcp":
		frame[4] = 1
	case "udp":
		frame[4] = 2
	default:
		return nil, ErrNotFound
	}
	if source.Addr().Is4() != destination.Addr().Is4() {
		return nil, ErrNotFound
	}
	if source.Addr().Is4() {
		frame[5] = 4
		a := source.Addr().As4()
		b := destination.Addr().As4()
		copy(frame[18:22], a[:])
		copy(frame[34:38], b[:])
	} else {
		frame[5] = 6
		a := source.Addr().As16()
		b := destination.Addr().As16()
		copy(frame[6:22], a[:])
		copy(frame[22:38], b[:])
	}
	binary.BigEndian.PutUint16(frame[38:40], source.Port())
	binary.BigEndian.PutUint16(frame[40:42], destination.Port())
	deadline := time.Now().Add(time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := s.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := io.Copy(s.conn, bytes.NewReader(frame)); err != nil {
		s.conn.Close()
		return nil, err
	}
	header := make([]byte, 7)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		s.conn.Close()
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[5:7]))
	if header[0] == 0 && length == 0 {
		return nil, ErrNotFound
	}
	if header[0] != 1 || length == 0 || length >= 4096 {
		s.conn.Close()
		return nil, ErrNotFound
	}
	path := make([]byte, length)
	if _, err := io.ReadFull(s.conn, path); err != nil {
		s.conn.Close()
		return nil, err
	}
	return &adapter.ConnectionOwner{UserId: int32(binary.BigEndian.Uint32(header[1:5])), ProcessPath: string(path)}, nil
}
