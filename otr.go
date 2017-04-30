package main

import (
	"math/big"
	"strings"
	"strconv"
	"time"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	//"crypto/dsa"
	"crypto/rsa"
	"crypto/md5"
	"crypto/x509"
	"crypto/sha256"
	// alias mrand for "math/rand" and crand for "crypto/rand" to avoid confusion
	mrand "math/rand"
	crand "crypto/rand"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"log"
	"encoding/pem"
	"encoding/asn1"
	"os"
	//"reflect"
	"encoding/hex"
	//"unicode/utf-8"

)


/********************************************* Define Objects *********************************************/

// User Object
type User struct {
	id int
	message string
	rsaPublicKey int
	rsaPrivateKey int
	dhPublic int
	dhSecret int
}

// Maybe Eve Object


/********************************************* Diffie-Hellman *********************************************/


// Function to generate prime number p
func getPrime() int {
	
	var r io.Reader
	var randomPrime *big.Int
	var randomPrimeInt int
	var err error
	
	// Generate as long as the result is a prime and not <nil>
	for {
		// Writing random number into io.Reader object r in order to pass it to rand.Prime
		mrand.Seed(time.Now().UTC().UnixNano())
		r = strings.NewReader(strconv.Itoa(mrand.Int()))
		// 32 bit primes seem to be the best compromise between randomness and reliability
		randomPrime, err = crand.Prime(r, 32)
		// Do until there is no error anymore, then break and return prime number
		if err == nil {
			break
		}
	}
	randomPrimeInt, _ = strconv.Atoi(randomPrime.String())
	fmt.Printf("Randomly Generated Prime: %d\n", randomPrimeInt)
	return randomPrimeInt
	//return randomPrime
}


// Function to factorize given non-prime into prime factors --> too hard to implement, took it from https://rosettacode.org/wiki/Prime_decomposition#Go
var ZERO = big.NewInt(0)
var ONE  = big.NewInt(1)

func primeFactorization(n *big.Int) []*big.Int {
	res := []*big.Int{}
	mod, div := new(big.Int), new(big.Int)
	for i := big.NewInt(2); i.Cmp(n) != 1; {
		div.DivMod(n, i, mod)
		for mod.Cmp(ZERO) == 0 {
			res = append(res, new(big.Int).Set(i))
			n.Set(div)
			div.DivMod(n, i, mod)
		}
		i.Add(i, ONE)
	}
	return res
}


// Function to get generator g (primitive root modulo p) --> Implemented test routine described in https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Finding_primitive_roots
func getPrimitiveRoot(prime int) (int) {
	var phiOfPrime int
	var generator int
	var equals1 bool
	var testExp big.Int
	
	// Phi of a prime is always prime - 1
	phiOfPrime = prime - 1
	fmt.Println(`ϕ(prime) =`, phiOfPrime)
	
	// Find all of phiOfPrime's prime factors
	primeFactors := primeFactorization(big.NewInt(int64(phiOfPrime)))
	fmt.Println("Prime Factors of", phiOfPrime, "are:", primeFactors)
	
	// sequentially increase counter i and test if i is generator until smallest onne is found
	for i := 2; i < phiOfPrime; i++ {
		equals1 = false		
		for _, factor := range primeFactors{
			// cast *big.Int return value from primeFactorization to int
			factorInt, _:= strconv.Atoi(factor.String())
			
			// Compute modular exponentiation: i^(phiOfPrime/factorInt) mod prime
			testExp.Exp(big.NewInt(int64(i)), big.NewInt(int64(phiOfPrime/factorInt)), big.NewInt(int64(prime)))
			
			// Compare result of modular exponentiation with 1, if equal, compare function returns 0. In this case, set equals1 to true. This means, current i is not a generator and loop while go on.
			if (testExp.Cmp(big.NewInt(int64(1))) == 0) {
				equals1 = true
			}
		}
		
		// If testing for every factor was successful (which means, the testing term never equaled 1), break loop and return found generator. Otherwise test another potential generator.
		if (equals1 == false) {
			generator = i
			fmt.Println("Smallest Primitive Root / Generator of", prime, "is", generator)
			break
		}
		
	}
	return generator
}


// Function to create secret and public key
func getDHSecretAndPublicKey(prime int, generator int) (int, int) {
	var ownDHsecret int
	var publicKey big.Int
	
	ownDHsecret = mrand.Intn(prime)
	
	publicKey.Exp(big.NewInt(int64(generator)), big.NewInt(int64(ownDHsecret)), big.NewInt(int64(prime)))
	
	publicKeyInt, _:= strconv.Atoi(publicKey.String())
	return ownDHsecret, publicKeyInt
}

// Function to compute shared secret
func getSharedSecret(ownDHSecret, partnerDHpublicKey int, prime int) (int) {
	var sharedSecret big.Int
	
	sharedSecret.Exp(big.NewInt(int64(partnerDHpublicKey)), big.NewInt(int64(ownDHSecret)), big.NewInt(int64(prime)))
	sharedSecretInt, _:= strconv.Atoi(sharedSecret.String())
	return sharedSecretInt
}


/********************************************* AES *********************************************/

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

/********************************************* RSA *********************************************/

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

// Generates PEM KEY files from RSA Keys
func generatePEMKeys(privFileName string, pubFileName string, pubkey rsa.PublicKey, privkey *rsa.PrivateKey) ([]byte, []byte, error) {
	privateKeyPEM, err := savePEMKey(privFileName,privkey)
	checkError(err)
	publicKeyPEM, err := savePublicPEMKey(pubFileName, pubkey)
	checkError(err)
	return privateKeyPEM, publicKeyPEM, nil
}

/********************************************* MD5 *********************************************/

// Generates 32 character MD5 Hash from DH shared secret
func generateMD5Hash(sharedSecret int) (string) {
	byteSecret := []byte(strconv.Itoa(sharedSecret))
	h := md5.New()
	h.Write([]byte(byteSecret))
	base32str := hex.EncodeToString(h.Sum(nil))
	return base32str
}

/********************************************* HMAC *********************************************/

// Checks if HMAC created from ciphertext and key is valid
func checkMAC(message, messageMac, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMac, expectedMAC)
}


// Generates HMAC from ciphertext and key
func generateMAC(message, key []byte) ([]byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	hashMAC := mac.Sum(nil)
	return hashMAC
}

/********************************************* Signatures *********************************************/

// Generates Signature from RSA private key and hash
func generateSignature(rsaPrivateKey *rsa.PrivateKey, hash []byte) ([]byte) {
	signature, err := rsa.SignPKCS1v15(crand.Reader, rsaPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		return nil
	}
	return signature
}

// Checks if Signature created from hash and RSA private key is valid
func verifySignature(rsaPublicKey *rsa.PublicKey, hash []byte, signature []byte) bool {
	err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		fmt.Printf("Error verification of signature: %s\n", err)
		return false
	}
	return true
}

/********************************************* Main *********************************************/
func main() {

	// Get initial seed to ensure randomness
	mrand.Seed(time.Now().UTC().UnixNano())
	
	
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
	
	//MD5 Hash
	testKey := generateMD5Hash(86)	//Given an integer (shared secret key from DHKE), create MD5 hash 32 characters long.
	fmt.Println("Hash: ", testKey)

	// AES Encryption 
	key := []byte(testKey) // 32 bytes
	plaintext := []byte("some really really really long plaintext")
	fmt.Printf("Plaintext: ")
	fmt.Printf("%s\n", plaintext)
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
	    log.Fatal(err)
	}
	fmt.Printf("Ciphertext: ")
	fmt.Printf("%0x\n", ciphertext)
	result, err := decrypt(key, ciphertext)
	if err != nil {
	    log.Fatal(err)
	}
	fmt.Printf("Decrypted Plaintext: %s\n", result)
	// End of AES Encryption
	

	// HMAC
	MACHash := generateMAC(ciphertext, key)
	success := checkMAC(ciphertext, MACHash, key)
	fmt.Println(MACHash)
	fmt.Println(success)

	// Signature
	signature := generateSignature(alicePrivateKey, MACHash)
	verified := verifySignature(&alicePublicKey, MACHash, signature)
	fmt.Println(hex.EncodeToString(signature))
	fmt.Println(verified)

	// Debug DH
	
	// Generate random prime
	prime := getPrime()
	//debugPrime := 2857
	
	// Generate /primitive root generator
	generator := getPrimitiveRoot(prime)
	
	// Generate DH secret and public key for Alice
	AliceDHsecret, AliceDHpublicKey := getDHSecretAndPublicKey(prime, generator)
	fmt.Println("Alice's DH Secret and Public Key:", AliceDHsecret, AliceDHpublicKey)
	
	// Generate DH secret and public key for Bob
	BobDHsecret, BobDHpublicKey := getDHSecretAndPublicKey(prime, generator)
	fmt.Println("Bob's DH Secret and Public Key:", BobDHsecret, BobDHpublicKey)
	
	// Let Alice compute Shared Secret
	AliceSharedSecret := getSharedSecret(AliceDHsecret,BobDHpublicKey, prime)
	
	// Let Alice compute Shared Secret
	BobSharedSecret := getSharedSecret(BobDHsecret,AliceDHpublicKey, prime)
	
	// Are they the same?
	fmt.Println("Alice's Shared Secret:", AliceSharedSecret)
	fmt.Println("Bob's Shared Secret:", BobSharedSecret)
	if (AliceSharedSecret == BobSharedSecret){
		fmt.Println("SUCCESS!!!!! :-)")
	}
	

}

