package main

import (
	"math/big"
	"strings"
	"strconv"
	"time"
	"crypto/aes"
	"crypto/cipher"
	//"crypto/dsa"
	"crypto/rsa"
	//"crypto/md5"
	"crypto/x509"
	// alias mrand for "math/rand" and crand for "crypto/rand" to avoid confusion
	mrand "math/rand"
	crand "crypto/rand"
	//"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"log"
	"encoding/pem"
	"encoding/asn1"
	"os"
	//"reflect"

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

// Takes in a key and text and uses AES-256 CTR Mode to create ciphertext from plaintext
func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
	    return nil, err
	}
	//b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(text))
	//IV created from split end of ciphertext array
	iv := ciphertext[:aes.BlockSize]
	
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
	    return nil, err
	}
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext, nil
}

// Takes in a key and ciphertext and uses AES-256 CTR Mode to decrypt ciphertext into plaintext
func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
	    return nil, err
	}
	if len(text) < aes.BlockSize {
	    return nil, errors.New("ciphertext too short")
	}
	//IV created from split end of ciphertext array
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


//Saves private key as pem file and returns private key as pem byte array.
func savePEMKey(fileName string, key *rsa.PrivateKey) ([]byte, error){
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
	return pem.EncodeToMemory(privateKey), err
}

//Saves public key as pem file and returns public key as pem byte array.
func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) ([]byte, error){
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
	return pem.EncodeToMemory(pemkey), err
}

// Check if error != nil, if it is true then exit and print fatal error
func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err)
		os.Exit(1)
	}
}

//Generates rsa private and public key of size "bit"
func generateKeys(bit int) (rsa.PublicKey, *rsa.PrivateKey, error){
	test, err:= rsa.GenerateKey(crand.Reader, bit)
	testPub := test.PublicKey
	checkError(err)
	return testPub, test, nil
}

func generatePEMKeys(privFileName string, pubFileName string, pubkey rsa.PublicKey, privkey *rsa.PrivateKey) ([]byte, []byte, error) {
	privateKeyPEM, err := savePEMKey(privFileName,privkey)
	checkError(err)
	publicKeyPEM, err := savePublicPEMKey(pubFileName, pubkey)
	checkError(err)
	return privateKeyPEM, publicKeyPEM, nil
}


/***************** Main *****************/
func main() {

	// AES Encryption 
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
	// End of AES Encryption
	
	
	// Get initial seed to ensure randomness
	mrand.Seed(time.Now().UTC().UnixNano())
	
	
	// Debug getPrime
	fmt.Println("Prime Number:" + getPrime().String())
	bitSize := 2048
	
	// RSA Key Generation
	// Generates keys for Alice and Bob
	alicePublicKey, alicePrivateKey, err:= generateKeys(bitSize)
	bobPublicKey, bobPrivateKey, err:= generateKeys(bitSize)


	//fmt.Printf("Alice Public Key: \n%s\n", alicePublicKey)
	//fmt.Printf("Alice Private Key: \n%s\n", alicePrivateKey)
	//fmt.Printf("Bob Public Key: \n%s\n", bobPublicKey)
	//fmt.Printf("Bob Private Key: \n%s\n", bobPrivateKey)

	// Saves Private Key and Public Key as PEM file and puts it into variable
	alicePrivateKeyPEM, alicePublicKeyPEM, err := generatePEMKeys("alicePrivateKeyPEM", "alicePublicKeyPEM", alicePublicKey, alicePrivateKey)
	bobPrivateKeyPEM, bobPublicKeyPEM, err := generatePEMKeys("bobPrivateKeyPEM", "bobPublicKeyPEM", bobPublicKey, bobPrivateKey)
	fmt.Printf("Bob Public Key: \n%s\n", bobPublicKeyPEM)
	fmt.Printf("Bob Private Key: \n%s\n", bobPrivateKeyPEM)
	fmt.Printf("Alice Public Key: \n%s\n", alicePublicKeyPEM)
	fmt.Printf("Alice Private Key: \n%s\n", alicePrivateKeyPEM)


	// End of RSA Key Generation
	
}

