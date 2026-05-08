package server

import (
	"sync"

	"github.com/chainreactors/aiscan/pkg/acp"
)

type Hub struct {
	mu          sync.Mutex
	subscribers map[string]map[chan acp.Message]struct{}
}

func NewHub() *Hub {
	return &Hub{subscribers: make(map[string]map[chan acp.Message]struct{})}
}

func (h *Hub) Subscribe(spaceID string) (<-chan acp.Message, func()) {
	ch := make(chan acp.Message, 16)
	h.mu.Lock()
	if _, ok := h.subscribers[spaceID]; !ok {
		h.subscribers[spaceID] = make(map[chan acp.Message]struct{})
	}
	h.subscribers[spaceID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if bucket, ok := h.subscribers[spaceID]; ok {
			delete(bucket, ch)
			if len(bucket) == 0 {
				delete(h.subscribers, spaceID)
			}
		}
		close(ch)
		h.mu.Unlock()
	}
}

func (h *Hub) Broadcast(spaceID string, message acp.Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subscribers[spaceID] {
		select {
		case ch <- message:
		default:
		}
	}
}
