package shadowsocks2022

import (
	"sync"
)

const (
	// DefaultWindowSize is the default size of the sliding window
	DefaultWindowSize = 1024
)

// SlidingWindowFilter implements a sliding window filter for replay protection
// It uses a bitmap to track received packet IDs within the window
type SlidingWindowFilter struct {
	mu         sync.Mutex
	lastID     uint64
	windowSize uint64
	bitmap     []uint64 // Each uint64 can track 64 packet IDs
}

// NewSlidingWindowFilter creates a new sliding window filter
func NewSlidingWindowFilter(windowSize int) *SlidingWindowFilter {
	if windowSize <= 0 {
		windowSize = DefaultWindowSize
	}
	// Round up to next multiple of 64
	bitmapSize := (windowSize + 63) / 64
	return &SlidingWindowFilter{
		windowSize: uint64(windowSize),
		bitmap:     make([]uint64, bitmapSize),
	}
}

// Check checks if the packet ID is valid (not replayed)
// Returns true if the ID is new and valid, false if it's a replay
func (f *SlidingWindowFilter) Check(id uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// If ID is too old (before the window), reject
	if f.lastID > f.windowSize && id <= f.lastID-f.windowSize {
		return false
	}

	// If ID is newer than lastID, update window
	if id > f.lastID {
		// Shift the window
		shift := id - f.lastID
		if shift >= f.windowSize {
			// Clear entire bitmap
			for i := range f.bitmap {
				f.bitmap[i] = 0
			}
		} else {
			// Shift bitmap
			f.shiftBitmap(shift)
		}
		f.lastID = id
		// Mark current ID as seen
		f.setBit(0)
		return true
	}

	// ID is within the window, check if already seen
	offset := f.lastID - id
	if f.getBit(offset) {
		return false // Already seen
	}

	// Mark as seen
	f.setBit(offset)
	return true
}

// shiftBitmap shifts the bitmap by the given amount
func (f *SlidingWindowFilter) shiftBitmap(shift uint64) {
	if shift >= f.windowSize {
		for i := range f.bitmap {
			f.bitmap[i] = 0
		}
		return
	}

	wordShift := shift / 64
	bitShift := shift % 64

	if wordShift > 0 {
		// Shift words
		for i := len(f.bitmap) - 1; i >= int(wordShift); i-- {
			f.bitmap[i] = f.bitmap[i-int(wordShift)]
		}
		for i := 0; i < int(wordShift); i++ {
			f.bitmap[i] = 0
		}
	}

	if bitShift > 0 {
		// Shift bits within words
		var carry uint64
		for i := 0; i < len(f.bitmap); i++ {
			newCarry := f.bitmap[i] >> (64 - bitShift)
			f.bitmap[i] = (f.bitmap[i] << bitShift) | carry
			carry = newCarry
		}
	}
}

// setBit sets the bit at the given offset (0 = current position)
func (f *SlidingWindowFilter) setBit(offset uint64) {
	wordIndex := offset / 64
	if wordIndex >= uint64(len(f.bitmap)) {
		return
	}
	bitIndex := offset % 64
	f.bitmap[wordIndex] |= 1 << bitIndex
}

// getBit gets the bit at the given offset
func (f *SlidingWindowFilter) getBit(offset uint64) bool {
	wordIndex := offset / 64
	if wordIndex >= uint64(len(f.bitmap)) {
		return false
	}
	bitIndex := offset % 64
	return (f.bitmap[wordIndex] & (1 << bitIndex)) != 0
}

// Reset resets the filter
func (f *SlidingWindowFilter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastID = 0
	for i := range f.bitmap {
		f.bitmap[i] = 0
	}
}

// SessionFilter manages replay filters for multiple sessions
type SessionFilter struct {
	mu       sync.RWMutex
	filters  map[string]*SlidingWindowFilter
	maxItems int
}

// NewSessionFilter creates a new session filter manager
func NewSessionFilter(maxItems int) *SessionFilter {
	if maxItems <= 0 {
		maxItems = 1024
	}
	return &SessionFilter{
		filters:  make(map[string]*SlidingWindowFilter),
		maxItems: maxItems,
	}
}

// GetOrCreate gets or creates a filter for the given session key
func (sf *SessionFilter) GetOrCreate(sessionKey string) *SlidingWindowFilter {
	sf.mu.RLock()
	filter, ok := sf.filters[sessionKey]
	sf.mu.RUnlock()

	if ok {
		return filter
	}

	sf.mu.Lock()
	defer sf.mu.Unlock()

	// Double check after acquiring write lock
	if filter, ok = sf.filters[sessionKey]; ok {
		return filter
	}

	// Evict old entries if at capacity
	if len(sf.filters) >= sf.maxItems {
		// Simple eviction: remove first item
		for k := range sf.filters {
			delete(sf.filters, k)
			break
		}
	}

	filter = NewSlidingWindowFilter(DefaultWindowSize)
	sf.filters[sessionKey] = filter
	return filter
}

// Remove removes a filter for the given session key
func (sf *SessionFilter) Remove(sessionKey string) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	delete(sf.filters, sessionKey)
}
