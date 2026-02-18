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

// PasswordFromSerial derives the default scanner password from a serial number.
// The password is the last 4 characters of the serial after stripping trailing
// spaces and NUL bytes. For example, serial "iX500-AK6ABB0700" yields "0700".
func PasswordFromSerial(serial string) string {
	s := strings.TrimRight(serial, " \x00")
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}

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
