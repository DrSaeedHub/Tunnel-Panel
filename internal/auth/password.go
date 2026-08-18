// Package auth implements password hashing, token issuance, session handling,
// login rate limiting, and account lockout (§18).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// MinPasswordLength is the hard floor. It used to be 8, then 12 before that —
// both are good passwords and a bad requirement. A rule that refuses what
// somebody has already chosen mostly teaches them to append "12" to it, and
// the panel is not the right place to argue about it. RecommendedPasswordLength
// says the recommendation once, where the password is chosen, and enforces
// nothing.
const MinPasswordLength = 1

// RecommendedPasswordLength is advice, not a rule. Nothing rejects a password
// for being shorter than this.
const RecommendedPasswordLength = 12

// MaxPasswordLength bounds the input so a very long password cannot be used to
// make the server do unbounded hashing work.
const MaxPasswordLength = 1024

// argon2id parameters. Memory dominates the cost and is what makes GPU cracking
// expensive; 64 MiB with three passes is a well-established interactive setting
// and costs a fraction of a second on the hardware this panel runs on.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// Errors returned by password handling.
var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	ErrPasswordWeak     = errors.New("password is too easy to guess")
	ErrInvalidHash      = errors.New("stored password hash is malformed")
)

// weakPasswords are rejected outright regardless of length. The list is short
// on purpose: it catches the passwords an operator types to "just get in for
// now", which is exactly when a panel running as root gets compromised.
var weakPasswords = map[string]struct{}{
	"password":         {},
	"password1":        {},
	"password123":      {},
	"passw0rd123":      {},
	"administrator":    {},
	"letmein12345":     {},
	"changeme1234":     {},
	"qwertyuiop12":     {},
	"123456789012":     {},
	"1234567890123":    {},
	"abcdefghijkl":     {},
	"gre-panel1234":    {},
	"grepanel1234":     {},
	"welcome12345":     {},
	"iloveyou1234":     {},
	"adminadmin12":     {},
	"rootroot1234":     {},
	"trustno1trust":    {},
	"qazwsxedc1234":    {},
	"passwordpassword": {},
}

// ValidatePassword applies the password policy. The username is compared
// against the password because reusing it is the most common weak choice.
func ValidatePassword(password, username string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	lower := strings.ToLower(password)
	if _, bad := weakPasswords[lower]; bad {
		return ErrPasswordWeak
	}
	if isSingleRepeatedRune(password) {
		return fmt.Errorf("%w: it is one character repeated", ErrPasswordWeak)
	}
	if isSequentialRun(lower) {
		return fmt.Errorf("%w: it is a straight run of consecutive characters", ErrPasswordWeak)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("%w: it is only whitespace", ErrPasswordWeak)
	}
	return nil
}

// isSingleRepeatedRune reports whether a password of two or more characters
// is the same character over and over ("aaaaaaaa"). A single character is
// short, not repeated, so it is not flagged here — MinPasswordLength is what
// decides whether it is long enough.
func isSingleRepeatedRune(s string) bool {
	runes := []rune(s)
	if len(runes) < 2 {
		return false
	}
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

// isSequentialRun reports whether every character steps by exactly one from the
// previous, in either direction: "123456789012" and "abcdefghijkl".
func isSequentialRun(s string) bool {
	runes := []rune(s)
	if len(runes) < 2 {
		return false
	}
	step := runes[1] - runes[0]
	if step != 1 && step != -1 {
		return false
	}
	for i := 2; i < len(runes); i++ {
		if runes[i]-runes[i-1] != step {
			return false
		}
	}
	// Only alphanumeric runs are worth rejecting; a deliberate punctuation
	// sequence is not the failure mode this rule is aimed at.
	for _, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// HashPassword returns an argon2id PHC-format hash with a fresh random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating password salt: %w", err)
	}
	return hashWithSalt(password, salt), nil
}

func hashWithSalt(password string, salt []byte) string {
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword reports whether password matches the encoded hash. The
// comparison is constant time, and the parameters come from the stored hash so
// that hashes written with older parameters keep verifying.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when the requested username does not exist, so
// that an unknown user and a wrong password cost the same amount of work and
// cannot be told apart by timing (§18).
var dummyHash = hashWithSalt("gre-panel unknown user placeholder", make([]byte, argonSaltLen))

// burnPasswordTime performs the same hashing work as a real verification and
// discards the result.
func burnPasswordTime(password string) {
	_, _ = VerifyPassword(dummyHash, password)
}
