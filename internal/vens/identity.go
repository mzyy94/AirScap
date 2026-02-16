package vens

import (
	"fmt"
	"strconv"
	"strings"
)

// Identity derivation constants from PasswordManager.getEncryptionBytesFromString().
const (
	identityKey   = "pFusCANsNapFiPfu"
	identityShift = 11
)

// ComputeIdentity derives a pairing identity string from a password.
// identity[i] = ord(password[i]) + ord(KEY[i]) + SHIFT
func ComputeIdentity(password string) (string, error) {
	if len(password) > len(identityKey) {
		return "", fmt.Errorf("password too long (max %d chars, got %d)", len(identityKey), len(password))
	}
	var b strings.Builder
	for i, c := range password {
		v := int(c) + int(identityKey[i]) + identityShift
		b.WriteString(strconv.Itoa(v))
	}
	return b.String(), nil
}
