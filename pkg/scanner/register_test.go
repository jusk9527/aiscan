package scanner

import (
	"testing"

	"github.com/chainreactors/aiscan/pkg/scanner/engines"
	"github.com/chainreactors/sdk/gogo"
	"github.com/chainreactors/sdk/spray"
)

func TestRegisterAllTreatsNeutronAsOptional(t *testing.T) {
	reg := NewScannerRegistry()
	engineSet := &engines.Set{
		Gogo:  gogo.NewEngine(nil),
		Spray: spray.NewEngine(nil),
	}

	if err := RegisterAll(reg, engineSet); err != nil {
		t.Fatalf("RegisterAll() error = %v", err)
	}
	for _, name := range []string{"scan", "gogo", "spray"} {
		if !reg.Has(name) {
			t.Fatalf("expected %q to be registered", name)
		}
	}
	if reg.Has("neutron") {
		t.Fatal("neutron should not be registered without templates")
	}
}
