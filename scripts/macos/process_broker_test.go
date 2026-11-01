//go:build darwin

package process

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func foxQuery(s *foxProcessSearcher, ctx context.Context, port uint16) (string, error) {
	owner, err := s.FindProcessInfo(ctx, "tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), netip.MustParseAddrPort("203.0.113.1:443"))
	if err != nil {
		return "", err
	}
	return owner.ProcessPath, nil
}
func foxReply(conn net.Conn, path string) error {
	header := make([]byte, 7)
	header[0] = 1
	binary.BigEndian.PutUint32(header[1:5], 501)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(path)))
	_, err := conn.Write(append(header, []byte(path)...))
	return err
}
func TestFoxProcessLateReplyIsDrainedAndNextConnectionRecovers(t *testing.T) {
	a, b := net.Pipe()
	s := makeFoxProcessSearcher(a)
	defer s.Close()
	defer b.Close()
	done := make(chan struct{})

	go func() {
		defer close(done)
		frame := make([]byte, 44)
		if _, err := io.ReadFull(b, frame); err != nil {
			return
		}
		time.Sleep(1200 * time.Millisecond)
		if foxReply(b, "/late-first") != nil {
			return
		}
		if _, err := io.ReadFull(b, frame); err != nil {
			return
		}
		_ = foxReply(b, "/correct-second")
	}()
	if _, err := foxQuery(s, context.Background(), 50000); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected caller timeout, got %v", err)
	}
	if path, err := foxQuery(s, context.Background(), 50001); err != nil || path != "/correct-second" {
		t.Fatalf("late reply crossed connections or channel poisoned: %q %v", path, err)
	}
	<-done
}
func TestFoxProcessCancellationAndQueueDoNotSendCancelledRequests(t *testing.T) {
	a, b := net.Pipe()
	s := makeFoxProcessSearcher(a)
	defer s.Close()
	defer b.Close()
	seen := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		f := make([]byte, 44)
		if _, err := io.ReadFull(b, f); err != nil {
			return
		}
		close(seen)
		<-release
		_ = foxReply(b, "/cancelled")
		if _, err := io.ReadFull(b, f); err != nil {
			return
		}
		if binary.BigEndian.Uint16(f[38:40]) != 50002 {
			return
		}
		_ = foxReply(b, "/last")
	}()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := foxQuery(s, ctx, 50000); first <- err }()
	<-seen
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	queued, cancelQueue := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelQueue()
	if _, err := foxQuery(s, queued, 50001); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	if path, err := foxQuery(s, context.Background(), 50002); err != nil || path != "/last" {
		t.Fatalf("%q %v", path, err)
	}
	<-done
}
func TestFoxProcessConcurrentRepliesStayAssociated(t *testing.T) {
	a, b := net.Pipe()
	s := makeFoxProcessSearcher(a)
	defer s.Close()
	defer b.Close()
	go func() {
		f := make([]byte, 44)
		for i := 0; i < 16; i++ {
			if _, err := io.ReadFull(b, f); err != nil {
				return
			}
			_ = foxReply(b, string(f[38:40]))
		}
	}()
	var wg sync.WaitGroup
	for i := uint16(50000); i < 50016; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			path, err := foxQuery(s, context.Background(), port)
			want := []byte{byte(port >> 8), byte(port)}
			if err != nil || path != string(want) {
				t.Errorf("reply mismatch for %d: %q %v", port, path, err)
			}
		}(i)
	}
	wg.Wait()
}
func TestFoxProcessCloseUnblocksPendingLookup(t *testing.T) {
	a, b := net.Pipe()
	s := makeFoxProcessSearcher(a)
	defer b.Close()
	read := make(chan struct{})
	go func() { _, _ = io.ReadFull(b, make([]byte, 44)); close(read) }()
	done := make(chan error, 1)
	go func() { _, err := foxQuery(s, context.Background(), 50000); done <- err }()
	<-read
	_ = s.Close()
	_ = s.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed channel accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("close leaked pending lookup")
	}
}
func TestFoxProcessUnknownOwnerDoesNotPoisonNextQuery(t *testing.T) {
	a, b := net.Pipe()
	s := makeFoxProcessSearcher(a)
	defer s.Close()
	defer b.Close()
	go func() {
		f := make([]byte, 44)
		_, _ = io.ReadFull(b, f)
		_, _ = b.Write(make([]byte, 7))
		_, _ = io.ReadFull(b, f)
		_ = foxReply(b, "/known")
	}()
	if _, err := foxQuery(s, context.Background(), 50000); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if path, err := foxQuery(s, context.Background(), 50001); err != nil || path != "/known" {
		t.Fatalf("%q %v", path, err)
	}
}
func TestFoxProcessMalformedReplyFailsClosed(t *testing.T) {
	a, b := net.Pipe()
	s := makeFoxProcessSearcher(a)
	defer s.Close()
	defer b.Close()
	go func() { _, _ = io.ReadFull(b, make([]byte, 44)); _, _ = b.Write([]byte{1, 0, 0, 1, 245, 255, 255}) }()
	if _, err := foxQuery(s, context.Background(), 50000); err == nil {
		t.Fatal("malformed reply accepted")
	}
	if _, err := foxQuery(s, context.Background(), 50001); err == nil {
		t.Fatal("invalid transport reused")
	}
}
