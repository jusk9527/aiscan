package tool

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainreactors/aiscan/skills"
)

func TestReadToolReadsVirtualSkill(t *testing.T) {
	store, diagnostics := skills.LoadEmbeddedStore()
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	read := NewReadTool(t.TempDir(), store)

	out, err := read.Execute(context.Background(), readArgs("aiscan://skills/aiscan/SKILL.md", 0, 0))
	if err != nil {
		t.Fatalf("read.Execute() error = %v", err)
	}
	if !strings.Contains(out, "name: aiscan") || !strings.Contains(out, "# Aiscan Mechanisms") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestReadToolVirtualSkillOffsetLimit(t *testing.T) {
	store, _ := skills.LoadEmbeddedStore()
	read := NewReadTool(t.TempDir(), store)

	out, err := read.Execute(context.Background(), readArgs("aiscan://skills/aiscan/SKILL.md", 0, 3))
	if err != nil {
		t.Fatalf("read.Execute() error = %v", err)
	}
	if got := len(strings.Split(out, "\n")); got != 3 {
		t.Fatalf("line count = %d, want 3:\n%s", got, out)
	}
}

func TestReadToolReadsFilesystemPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	read := NewReadTool(dir)

	out, err := read.Execute(context.Background(), readArgs("note.txt", 0, 0))
	if err != nil {
		t.Fatalf("read.Execute() error = %v", err)
	}
	if out != "hello" {
		t.Fatalf("output = %q, want hello", out)
	}
}

func TestReadToolMissingVirtualSkill(t *testing.T) {
	store, _ := skills.LoadEmbeddedStore()
	read := NewReadTool(t.TempDir(), store)

	_, err := read.Execute(context.Background(), readArgs("aiscan://skills/missing/SKILL.md", 0, 0))
	if err == nil || !strings.Contains(err.Error(), "virtual file not found") {
		t.Fatalf("error = %v, want virtual file not found", err)
	}
}

func readArgs(path string, offset, limit int) string {
	data, err := json.Marshal(map[string]any{
		"path":   path,
		"offset": offset,
		"limit":  limit,
	})
	if err != nil {
		panic(err)
	}
	return string(data)
}
