//go:build gdns_udp_addrport && gdns_dnssec_mixed

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

// Keep the signed-address experiment with the opt-in UDP performance build.
const signedAddressCacheFastPath = true
