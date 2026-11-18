// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestMixedWorkIsBalancedAcrossFlows(t *testing.T) {
	const flows = 8
	counts := [flows]int{}
	for i := 0; i < flows*100; i++ {
		if uniqueQuery("mixed", i, flows) {
			counts[i%flows]++
		}
		if uniqueQuery("warm", i, flows) || !uniqueQuery("miss", i, flows) {
			t.Fatal("pure workloads changed")
		}
	}
	for flow, n := range counts {
		if n != 10 {
			t.Fatalf("flow %d: %d unique names, want 10", flow, n)
		}
	}
}
