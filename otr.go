package main

import (
	"math/big"
	"strings"
	"strconv"
	"time"
	"crypto/aes"
	"crypto/cipher"
	//"crypto/dsa"
	//"crypto/rsa"
	//"crypto/md5"
	// alias mrand for "math/rand" and crand for "crypto/rand" to avoid confusion
	mrand "math/rand"
	crand "crypto/rand"
	//"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"log"

)


/***************** Define Objects *****************/

// User Object
type User struct {
	id int
	message string
	publicKey int
	privateKey int
	dhExponent int
}

// Maybe Eve Object


/***************** Basic Functions *****************/


// Function to generate prime number p
func getPrime() *big.Int {
	
	var r io.Reader
	var randomPrime *big.Int
	var err error
	
	// Generate as long as the result is a prime and not <nil>
	// 32 bit primes seem to be the best compromise between randomness and reliability
	for {
		// Writing random number into io.Reader object r in order to pass it to rand.Prime
		r = strings.NewReader(strconv.Itoa(mrand.Int()))
		randomPrime, err = crand.Prime(r, 32)
		// Do until there is no error anymore, then break and return prime number
		if err == nil {
			break
		}
	}
	return randomPrime
}

// Function to get generator g (primitive root modulo p)
func getPrimitiveRoot(prime *big.Int) (int) {
	return 1
}


// Function to create user
func createUser() () {
	return
}



// See alternate IV creation from ciphertext below
//var iv = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}


func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
	    return nil, err
	}
	//b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
	    return nil, err
	}
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
	    return nil, err
	}
	if len(text) < aes.BlockSize {
	    return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(text, text)
	//data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
	    return nil, err
	}
	return text, nil
}


/***************** Main *****************/
func main() {

	
	key := []byte("a very very very very secret key") // 32 bytes
	plaintext := []byte("some really really really long plaintext")
	fmt.Printf("%s\n", plaintext)
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
	    log.Fatal(err)
	}
	fmt.Printf("%0x\n", ciphertext)
	result, err := decrypt(key, ciphertext)
	if err != nil {
	    log.Fatal(err)
	}
	fmt.Printf("%s\n", result)
	
	
	// Get initial seed to ensure randomness
	mrand.Seed(time.Now().UTC().UnixNano())
	
	
	// Debug getPrime
	fmt.Println("Prime Number:" + getPrime().String())



}

