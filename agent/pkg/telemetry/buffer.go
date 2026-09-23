package telemetry

import (
	"sync"
	"time"
)

// Event represents an individual endpoint telemetry observation.
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"` // e.g., "PROCESS_START", "NETWORK_CONNECT", "FILE_WRITE"
	Payload   map[string]interface{} `json:"payload"`
}

// RingBuffer provides an in-memory, thread-safe circular buffer for telemetry
// events. If the control-plane network disconnects, events continue buffering
// locally up to Capacity without blocking agent execution or dropping critical data.
type RingBuffer struct {
	mu       sync.Mutex
	capacity int
	events   []Event
	head     int
	tail     int
	size     int
}

// NewRingBuffer allocates a ring buffer with the specified capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 10000
	}
	return &RingBuffer{
		capacity: capacity,
		events:   make([]Event, capacity),
	}
}

// Push adds an event to the buffer. If full, it overwrites the oldest event.
func (rb *RingBuffer) Push(evt Event) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.events[rb.head] = evt
	rb.head = (rb.head + 1) % rb.capacity

	if rb.size < rb.capacity {
		rb.size++
	} else {
		// Overwrite oldest: advance tail
		rb.tail = (rb.tail + 1) % rb.capacity
	}
}

// DrainAll extracts all pending events from the buffer in chronological order
// and clears the buffer. Typically invoked when the network reconnects.
func (rb *RingBuffer) DrainAll() []Event {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.size == 0 {
		return []Event{}
	}

	result := make([]Event, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.tail + i) % rb.capacity
		result[i] = rb.events[idx]
	}

	rb.size = 0
	rb.head = 0
	rb.tail = 0

	return result
}

// Size returns the count of un-drained events.
func (rb *RingBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}
