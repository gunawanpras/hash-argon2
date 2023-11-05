package hash

import (
	"math/rand"
	"strings"
)

const (
	alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVQXYZ1234567890"
)

// RandomString generates a random string of length n
func RandomString(n int) string {
	var sb strings.Builder
	k := len(alphanum)

	for i := 0; i < n; i++ {
		c := alphanum[rand.Intn(k)]
		sb.WriteByte(c)
	}

	return sb.String()
}
