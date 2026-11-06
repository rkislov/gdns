// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package access

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

const hashPrefix = "$argon2id$v=19$m=65536,t=3,p=4$"

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", fmt.Errorf("password must contain 12..1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return hashPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(sum), nil
}
func hashParts(encoded string) ([]byte, []byte, bool) {
	if !strings.HasPrefix(encoded, hashPrefix) || len(encoded) > 256 {
		return nil, nil, false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, hashPrefix), "$")
	if len(parts) != 2 {
		return nil, nil, false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[0])
	sum, e2 := base64.RawStdEncoding.DecodeString(parts[1])
	return salt, sum, e1 == nil && e2 == nil && len(salt) == 16 && len(sum) == 32
}
func validHash(encoded string) bool { _, _, ok := hashParts(encoded); return ok }
func VerifyPassword(password, encoded string) bool {
	if len(password) > 1024 {
		return false
	}
	salt, want, ok := hashParts(encoded)
	if !ok {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
