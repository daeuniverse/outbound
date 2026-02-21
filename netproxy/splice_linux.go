package netproxy

import (
	"io"
	"syscall"
)

const (
	maxSpliceSize = 1 << 30 // 1GB maximum per splice call
	
	// Splice flags
	SPLICE_F_MOVE     = 0x01 // Move pages instead of copying
	SPLICE_F_NONBLOCK = 0x02 // Non-blocking operation
	SPLICE_F_MORE     = 0x04 // More data will follow
	SPLICE_F_GIFT     = 0x08 // Gift pages to kernel
)

// canSplice checks if both connections support splice operation
func canSplice(dst, src interface{}) bool {
	_, dstOk := dst.(interface{ SyscallConn() (syscall.RawConn, error) })
	_, srcOk := src.(interface{ SyscallConn() (syscall.RawConn, error) })
	return dstOk && srcOk
}

// splice performs zero-copy transfer from src to dst using Linux splice syscall
// Returns the number of bytes transferred and any error
func splice(dstFD, srcFD int, limit int64) (int64, error) {
	var total int64
	
	for total < limit {
		remaining := limit - total
		if remaining > maxSpliceSize {
			remaining = maxSpliceSize
		}
		
		// Use splice to transfer data directly in kernel space
		// Use SPLICE_F_MORE to indicate more data will follow
		flags := 0
		if remaining < maxSpliceSize {
			flags = SPLICE_F_MORE
		}
		n, err := syscall.Splice(srcFD, nil, dstFD, nil, int(remaining), flags)
		if err != nil {
			return total, err
		}
		
		total += int64(n)
		
		// EOF reached
		if n == 0 {
			break
		}
	}
	
	return total, nil
}

// ReadFrom implements io.ReaderFrom with zero-copy optimization
// This is the optimized version for Linux systems
func ReadFrom(dst Conn, src io.Reader) (int64, error) {
	// Try zero-copy splice first
	if canSplice(dst, src) {
		// Get file descriptors
		dstConn, err := dst.(interface{ SyscallConn() (syscall.RawConn, error) }).SyscallConn()
		if err != nil {
			goto fallback
		}
		
		srcConn, err := src.(interface{ SyscallConn() (syscall.RawConn, error) }).SyscallConn()
		if err != nil {
			goto fallback
		}
		
		var dstFD, srcFD int
		var errDst, errSrc error
		
		// Extract file descriptors
		dstConn.Control(func(fd uintptr) {
			dstFD = int(fd)
		})
		srcConn.Control(func(fd uintptr) {
			srcFD = int(fd)
		})
		
		if errDst != nil || errSrc != nil {
			goto fallback
		}
		
		// Perform zero-copy transfer
		return splice(dstFD, srcFD, 1<<40) // 1TB limit (effectively unlimited)
	}
	
fallback:
	// Standard copy fallback
	return io.Copy(dst, src)
}

// WriteTo implements io.WriterTo with zero-copy optimization
// This is the optimized version for Linux systems
func WriteTo(src Conn, dst io.Writer) (int64, error) {
	// Try zero-copy splice first
	if canSplice(dst, src) {
		dstConn, err := dst.(interface{ SyscallConn() (syscall.RawConn, error) }).SyscallConn()
		if err != nil {
			goto fallback
		}
		
		srcConn, err := src.(interface{ SyscallConn() (syscall.RawConn, error) }).SyscallConn()
		if err != nil {
			goto fallback
		}
		
		var dstFD, srcFD int
		var errDst, errSrc error
		
		dstConn.Control(func(fd uintptr) {
			dstFD = int(fd)
		})
		srcConn.Control(func(fd uintptr) {
			srcFD = int(fd)
		})
		
		if errDst != nil || errSrc != nil {
			goto fallback
		}
		
		// Perform zero-copy transfer
		return splice(dstFD, srcFD, 1<<40)
	}
	
fallback:
	// Standard copy fallback
	return io.Copy(dst, src)
}
