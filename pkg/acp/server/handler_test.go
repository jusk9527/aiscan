package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/aiscan/pkg/acp"
)

func TestHandlerHTTPAndSSE(t *testing.T) {
	server := httptest.NewServer(NewHandler(NewService(NewMemoryStore())))
	defer server.Close()

	node := postJSON[acp.Node](t, server.URL+"/nodes", "", map[string]any{"name": "agent", "meta": map[string]any{"role": "test"}}, http.StatusCreated)
	space := postJSON[acp.SpaceInfo](t, server.URL+"/spaces", node.ID, map[string]any{"name": "case", "description": "tester"}, http.StatusOK)

	sseReq, err := http.NewRequest(http.MethodGet, server.URL+"/spaces/"+space.ID+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(sseReq)
	if err != nil {
		t.Fatalf("open sse: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("content-type = %q", got)
	}

	done := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				done <- strings.TrimPrefix(line, "data: ")
				return
			}
		}
		done <- ""
	}()

	message := postJSON[acp.Message](t, server.URL+"/spaces/"+space.ID+"/messages", node.ID, map[string]any{"content": map[string]any{"text": "hello"}}, http.StatusCreated)

	select {
	case data := <-done:
		if data == "" {
			t.Fatal("sse closed without data")
		}
		var got acp.Message
		if err := json.Unmarshal([]byte(data), &got); err != nil {
			t.Fatalf("decode sse data: %v", err)
		}
		if got.ID != message.ID {
			t.Fatalf("sse message id = %s, want %s", got.ID, message.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for sse message")
	}
}

func TestHandlerDefaultsAndValidation(t *testing.T) {
	server := httptest.NewServer(NewHandler(NewService(NewMemoryStore())))
	defer server.Close()

	node := postJSON[acp.Node](t, server.URL+"/nodes", "", map[string]any{"name": "agent"}, http.StatusCreated)
	if node.Meta == nil || len(node.Meta) != 0 {
		t.Fatalf("node meta = %#v, want empty map", node.Meta)
	}
	space := postJSON[acp.SpaceInfo](t, server.URL+"/spaces", node.ID, map[string]any{"name": "case", "description": "tester"}, http.StatusOK)
	message := postJSON[acp.Message](t, server.URL+"/spaces/"+space.ID+"/messages", node.ID, map[string]any{"content": map[string]any{"text": "hello"}}, http.StatusCreated)
	if message.Refs.Messages == nil || message.Refs.Nodes == nil || len(message.Refs.Messages) != 0 || len(message.Refs.Nodes) != 0 {
		t.Fatalf("message refs = %#v, want empty slices", message.Refs)
	}

	postJSONStatus(t, server.URL+"/spaces/"+space.ID+"/messages", node.ID, map[string]any{"content": nil}, http.StatusUnprocessableEntity)
	postJSONStatus(t, server.URL+"/spaces/"+space.ID+"/messages", node.ID, map[string]any{}, http.StatusUnprocessableEntity)
}

func postJSON[T any](t *testing.T, url, nodeID string, body any, wantStatus int) T {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if nodeID != "" {
		req.Header.Set("X-Node-ID", nodeID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func postJSONStatus(t *testing.T, url, nodeID string, body any, wantStatus int) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if nodeID != "" {
		req.Header.Set("X-Node-ID", nodeID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, wantStatus, strings.TrimSpace(string(data)))
	}
}
