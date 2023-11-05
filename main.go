package main

import (
	"argon2/hash"
	"fmt"
	"runtime"
)

func main() {
	argon2id := hash.NewArgon2ID(hash.Params{
		Time:        2,
		Memory:      64 * 1024,
		Parallelism: uint8(runtime.NumCPU()),
		KeyLength:   32,
	})

	plainText := "MyP@55w0rd"
	salt := hash.RandomString(10)

	hash, err := argon2id.Hash(plainText, salt)
	if err != nil {
		fmt.Println(err)
	}

	verified, err := argon2id.Verify(plainText, hash)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("HASH \t=", hash)

	if verified {
		fmt.Println("VERIFY \t= hash matched!")

	} else {
		fmt.Println("VERIFY \t= hash does not matched!")
	}
}
