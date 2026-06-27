package claims

import (
	"testing"
)

func TestTAC_Has(t *testing.T) {
	tac := TAC("rwl")
	if !tac.Has(TACRead) {
		t.Error("expected Has('r') = true")
	}
	if tac.Has(TACAdmin) {
		t.Error("expected Has('a') = false")
	}
}

func TestTAC_HasAll(t *testing.T) {
	tac := TAC("rwlk")
	if !tac.HasAll("rw") {
		t.Error("expected HasAll(rw) = true")
	}
	if tac.HasAll("rwa") {
		t.Error("expected HasAll(rwa) = false")
	}
}

func TestTAC_IsSubsetOf(t *testing.T) {
	if !TAC("rl").IsSubsetOf(TAC("rwl")) {
		t.Error("rl should be subset of rwl")
	}
	if TAC("rw").IsSubsetOf(TAC("rl")) {
		t.Error("rw should not be subset of rl")
	}
}

func TestTAC_Validate(t *testing.T) {
	if err := TAC("rwlidka").Validate(); err != nil {
		t.Errorf("valid TAC rejected: %v", err)
	}
	if err := TAC("rx").Validate(); err == nil {
		t.Error("invalid TAC 'rx' should be rejected")
	}
	if err := TAC("").Validate(); err != nil {
		t.Errorf("empty TAC should be valid: %v", err)
	}
}
