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
	conn     net.Conn
	once     sync.Once
	requests chan foxProcessQuery
	done     chan struct{}
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
	return makeFoxProcessSearcher(conn), nil, true
}

// One worker owns stream framing. A caller timeout never closes the channel or
// leaves a late reply available for the next connection.
type foxProcessQuery struct {
	ctx   context.Context
	frame []byte
	reply chan foxProcessReply
}
type foxProcessReply struct {
	owner *adapter.ConnectionOwner
	err   error
}

func makeFoxProcessSearcher(conn net.Conn) *foxProcessSearcher {
	s := &foxProcessSearcher{conn: conn, requests: make(chan foxProcessQuery), done: make(chan struct{})}
	go s.serve()
	return s
}
func (s *foxProcessSearcher) ResetCache() {}
func (s *foxProcessSearcher) Close() error {
	var err error
	s.once.Do(func() { close(s.done); err = s.conn.Close() })
	return err
}
func (s *foxProcessSearcher) serve() {
	defer s.Close()
	for {
		select {
		case <-s.done:
			return
		case q := <-s.requests:
			if q.ctx.Err() != nil {
				q.reply <- foxProcessReply{err: q.ctx.Err()}
				continue
			}
			// Bound a genuinely broken peer separately from a short caller deadline.
			owner, err := s.exchange(q.frame)
			q.reply <- foxProcessReply{owner, err}
			if err != nil && err != ErrNotFound {
				return
			}
		}
	}
}
func (s *foxProcessSearcher) FindProcessInfo(ctx context.Context, network string, source, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
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
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	q := foxProcessQuery{ctx: lookup, frame: frame, reply: make(chan foxProcessReply, 1)}
	select {
	case <-lookup.Done():
		return nil, lookup.Err()
	case <-s.done:
		return nil, net.ErrClosed
	case s.requests <- q:
	}
	select {
	case <-lookup.Done():
		return nil, lookup.Err()
	case <-s.done:
		return nil, net.ErrClosed
	case reply := <-q.reply:
		if err := lookup.Err(); err != nil {
			return nil, err
		}
		return reply.owner, reply.err
	}
}
func (s *foxProcessSearcher) exchange(frame []byte) (*adapter.ConnectionOwner, error) {
	deadline := time.Now().Add(5 * time.Second)
	if err := s.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := io.Copy(s.conn, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	header := make([]byte, 7)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[5:7]))
	if header[0] == 0 && length == 0 && bytes.Equal(header[1:5], []byte{0, 0, 0, 0}) {
		return nil, ErrNotFound
	}
	if header[0] != 1 || length == 0 || length >= 4096 {
		return nil, fmt.Errorf("invalid foxVPN process response")
	}
	path := make([]byte, length)
	if _, err := io.ReadFull(s.conn, path); err != nil {
		return nil, err
	}
	return &adapter.ConnectionOwner{UserId: int32(binary.BigEndian.Uint32(header[1:5])), ProcessPath: string(path)}, nil
}
