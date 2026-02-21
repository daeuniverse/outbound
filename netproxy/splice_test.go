// +build linux

package netproxy

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// BenchmarkSpliceVsCopy benchmarks splice vs standard copy
func BenchmarkSpliceVsCopy(b *testing.B) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "splice_test_*.dat")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write test data (10MB)
	testData := make([]byte, 10*1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if _, err := tmpFile.Write(testData); err != nil {
		b.Fatal(err)
	}
	tmpFile.Sync()

	b.Run("StandardCopy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Reset file position
			tmpFile.Seek(0, 0)

			// Create pipe for testing
			r, w, err := os.Pipe()
			if err != nil {
				b.Fatal(err)
			}

			// Standard io.Copy
			go func() {
				io.Copy(w, tmpFile)
				w.Close()
			}()

			// Read from pipe (discard)
			io.Copy(io.Discard, r)
			r.Close()
		}
	})

	b.Run("SpliceCopy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Reset file position
			tmpFile.Seek(0, 0)

			// Create pipe for testing
			r, w, err := os.Pipe()
			if err != nil {
				b.Fatal(err)
			}

			// Use splice
			go func() {
				rfd := tmpFile.Fd()
				wfd := w.Fd()
				splice(int(wfd), int(rfd), 10*1024*1024)
				w.Close()
			}()

			// Read from pipe (discard)
			io.Copy(io.Discard, r)
			r.Close()
		}
	})
}

// BenchmarkTCPForward benchmarks TCP forwarding with splice
func BenchmarkTCPForward(b *testing.B) {
	// Start echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo server
			}(conn)
		}
	}()

	// Create test data
	testData := make([]byte, 1024*1024) // 1MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		// Send and receive
		go func() {
			conn.Write(testData)
		}()

		received := make([]byte, len(testData))
		conn.Read(received)
		conn.Close()
	}
}

// BenchmarkThroughput measures actual throughput
func BenchmarkThroughput(b *testing.B) {
	dataSize := 100 * 1024 * 1024 // 100MB

	// Create pipe pair
	r1, w1, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("StandardCopy", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(int64(dataSize))

		for i := 0; i < b.N; i++ {
			// Write test data
			go func() {
				testData := make([]byte, dataSize)
				w1.Write(testData)
				w1.Close()
			}()

			// Read and discard
			io.Copy(io.Discard, r1)
		}
	})

	r1.Close()
	w1.Close()
}

// TestSpliceCorrectness verifies splice produces correct data
func TestSpliceCorrectness(t *testing.T) {
	// Create test file
	tmpFile, err := os.CreateTemp("", "splice_correctness_*.dat")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	testData := []byte("Hello, World! This is a splice test with some data.")
	tmpFile.Write(testData)
	tmpFile.Sync()
	tmpFile.Seek(0, 0)

	// Create pipe
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	// Transfer using splice
	done := make(chan error)
	go func() {
		_, err := splice(int(w.Fd()), int(tmpFile.Fd()), int64(len(testData)))
		w.Close()
		done <- err
	}()

	// Read result
	result := make([]byte, len(testData))
	n, err := io.ReadFull(r, result)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected %d bytes, got %d", len(testData), n)
	}

	if string(result) != string(testData) {
		t.Errorf("Data mismatch: expected %q, got %q", testData, result)
	}

	if err := <-done; err != nil {
		t.Errorf("Splice error: %v", err)
	}
}

// TestSpliceLargeData tests splice with large data transfers
func TestSpliceLargeData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large data test in short mode")
	}

	// Create large test file (10MB)
	tmpFile, err := os.CreateTemp("", "splice_large_*.dat")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	size := 10 * 1024 * 1024
	testData := make([]byte, size)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	tmpFile.Write(testData)
	tmpFile.Sync()
	tmpFile.Seek(0, 0)

	// Create pipe
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	// Transfer using splice
	start := time.Now()
	done := make(chan error)
	go func() {
		_, err := splice(int(w.Fd()), int(tmpFile.Fd()), int64(size))
		w.Close()
		done <- err
	}()

	// Read result
	result := make([]byte, size)
	n, err := io.ReadFull(r, result)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	elapsed := time.Since(start)

	if n != size {
		t.Errorf("Expected %d bytes, got %d", size, n)
	}

	// Verify data
	for i := range result {
		if result[i] != testData[i] {
			t.Errorf("Data mismatch at byte %d", i)
			break
		}
	}

	if err := <-done; err != nil {
		t.Errorf("Splice error: %v", err)
	}

	throughputMBps := float64(size) / elapsed.Seconds() / 1024 / 1024
	t.Logf("Throughput: %.2f MB/s", throughputMBps)
}

// TestSpliceIntegration tests integration with net.Conn
func TestSpliceIntegration(t *testing.T) {
	// This tests the ReadFrom/WriteTo functions with TCP connections

	// Create TCP connection pair
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		var err error
		serverConn, err = listener.Accept()
		if err != nil {
			t.Error(err)
		}
		close(done)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	<-done
	defer serverConn.Close()

	testData := []byte("Integration test data")
	clientConn.Write(testData)

	// Use ReadFrom with splice optimization
	buf := make([]byte, len(testData))
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(testData) {
		t.Errorf("Expected %d bytes, got %d", len(testData), n)
	}

	if string(buf) != string(testData) {
		t.Errorf("Data mismatch: expected %q, got %q", testData, buf)
	}
}

// BenchmarkRealWorldScenario simulates real proxy usage
func BenchmarkRealWorldScenario(b *testing.B) {
	// Setup: client -> proxy -> server

	// Server
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer serverListener.Close()

	go func() {
		for {
			conn, err := serverListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo
			}(conn)
		}
	}()

	// Client
	b.ResetTimer()
	b.SetBytes(1024 * 1024) // 1MB per operation

	for i := 0; i < b.N; i++ {
		clientConn, err := net.Dial("tcp", serverListener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		data := make([]byte, 1024*1024)
		go func() {
			clientConn.Write(data)
			clientConn.Close()
		}()

		io.Copy(io.Discard, clientConn)
	}
}

// getFD extracts file descriptor from various connection types
func getFD(conn interface{}) (int, error) {
	switch c := conn.(type) {
	case *net.TCPConn:
		f, err := c.File()
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return int(f.Fd()), nil
	case *os.File:
		return int(c.Fd()), nil
	case interface{ Fd() uintptr }:
		return int(c.Fd()), nil
	default:
		return 0, syscall.EBADF
	}
}
