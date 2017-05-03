package main

import (
	"math/big"
	"strings"
	"strconv"
	"time"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
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
	"encoding/pem"
	"encoding/asn1"
	"os"
	"encoding/hex"
	"sync"

)


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
	fmt.Println("********** Generate initial Diffie Hellman Parameters **********")
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
			fmt.Println("************* Verifying exchanged DH Public Keys ***************")
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



/********************************************* Define actual OTR Requirements and Objects *********************************************/

// Create shared channels that will be used by Alice and Bob for communication
// Channels to send information from Sender to Receiver
var SenderToReceiver = make(chan string)
var SenderToReceiverInt = make(chan int)
var SenderToReceiverVar = make(chan []byte)

// Channels to send information from Receiver to Sender
var ReceiverToSender = make(chan string)
var ReceiverToSenderInt = make(chan int)
var ReceiverToSenderVar = make(chan []byte)

// Create waitGroup for Synchronization
var wg sync.WaitGroup

// User Object
type user struct {
	id int
	name string
	messages []string
	messageCounter int
	rsaPublicKey *rsa.PublicKey
	rsaPrivateKey *rsa.PrivateKey
	rsaPartnerPublicKey *rsa.PublicKey
	dhPrime int
	dhGenerator int
	dhPublicOwn int
	dhPublicPartner int
	dhSecret int
	dhSharedSecret int
	SharedSecretHash string
}

// Function to run initial Diffie-Hellman Parameter setup
func initiateDHParameters(initiator *user) {

	// INITIAL DIFFIE HELLMAN BLOCK
	// Create Parameters
	initiator.dhPrime = getPrime()
	initiator.dhGenerator = getPrimitiveRoot(initiator.dhPrime)
	initiator.dhSecret, initiator.dhPublicOwn = getDHSecretAndPublicKey(initiator.dhPrime, initiator.dhGenerator)
	//MD5 Hash on own DH Public --> Generates a String Hash
	dhPublicOwnHash := generateMD5Hash(initiator.dhPublicOwn)
	// Generate Signature for DH Public Hash using RSA Private Key and DH Public Hash
	dhPublicOwnSignature := generateSignature(initiator.rsaPrivateKey, []byte(dhPublicOwnHash))
	// Send Parameters
	SenderToReceiverInt <- initiator.dhPrime
	SenderToReceiverInt <- initiator.dhGenerator
	SenderToReceiverInt <- initiator.dhPublicOwn
	// Send PublicOwn Signature
	SenderToReceiverVar <- dhPublicOwnSignature
	// Receive DH Public Key
	initiator.dhPublicPartner = <-ReceiverToSenderInt
	// Receive DH Public Key Signature
	dhPublicPartnerSignature := <-ReceiverToSenderVar
	//MD5 Hash on DH Public --> Generates a String Hash
	dhPublicPartnerHash := generateMD5Hash(initiator.dhPublicPartner)
	// Verify received DH Public Key Signature
	verified := verifySignature(initiator.rsaPartnerPublicKey, []byte(dhPublicPartnerHash), dhPublicPartnerSignature)
	fmt.Println("Verified",initiator.name,"'s RSA Signature of DH Public Key:", verified)
	// Compute Shared Secret
	initiator.dhSharedSecret = getSharedSecret(initiator.dhSecret,initiator.dhPublicPartner, initiator.dhPrime) 
	// Generate MD5 Hash for AES from shared secret
	initiator.SharedSecretHash = generateMD5Hash(initiator.dhSharedSecret)
	
	wg.Done()
}

// Function to receive and respond to initial Diffie-Hellman Parameter setup
func receiveDHParameters(receiver *user) {
	
	
	// INITIAL DIFFIE HELLMAN BLOCK
	// Receive Parameters
	receiver.dhPrime = <-SenderToReceiverInt
	receiver.dhGenerator = <-SenderToReceiverInt
	receiver.dhPublicPartner = <-SenderToReceiverInt
	dhPublicPartnerSignature := <-SenderToReceiverVar
	//MD5 Hash on DH Public Partner --> Generates a String Hash
	dhPublicPartnerHash := generateMD5Hash(receiver.dhPublicPartner)
	//Verify DH Partner Public Signature
	verified := verifySignature(receiver.rsaPartnerPublicKey, []byte(dhPublicPartnerHash), dhPublicPartnerSignature)
	fmt.Println("Verified",receiver.name,"'s RSA Signature of DH Public Key:", verified)
	// Create own DH Secret and Public Key
	receiver.dhSecret, receiver.dhPublicOwn = getDHSecretAndPublicKey(receiver.dhPrime, receiver.dhGenerator)
	//MD5 Hash on DH Public --> Generates a String Hash
	dhPublicOwnHash := generateMD5Hash(receiver.dhPublicOwn)
	// Generate Signature for DH Public Hash using RSA Private Key and DH Public Hash
	dhPublicOwnSignature := generateSignature(receiver.rsaPrivateKey, []byte(dhPublicOwnHash))
	// Send DH Public Key
	ReceiverToSenderInt <- receiver.dhPublicOwn
	// Send DH Public Key Signature
	ReceiverToSenderVar <- dhPublicOwnSignature
	// Compute Shared Secret
	receiver.dhSharedSecret = getSharedSecret(receiver.dhSecret, receiver.dhPublicPartner, receiver.dhPrime)
	// Generate MD5 Hash for AES from shared secret
	receiver.SharedSecretHash = generateMD5Hash(receiver.dhSharedSecret)
	
	wg.Done()
	
}
	
	
// Function to send message
func sendMessage(sender *user, counter int) {
	
	// ENCRYPT AND SEND MESSAGE
	fmt.Println("************************** Message", counter, "***************************")
	fmt.Println(sender.name, "sends:", sender.messages[sender.messageCounter])
	c, err := encrypt([]byte(sender.SharedSecretHash), []byte(sender.messages[sender.messageCounter]))
	if err != nil {
		fmt.Println("Encryption Failed!")
	}
	// Generate the MAC
	MK_temp := sha256.Sum256([]byte(sender.SharedSecretHash))
	var MK []byte = MK_temp[:]
	mac := generateMAC(c, MK)
	// Send the encrypted message and MAC
	SenderToReceiver <- string(c)
	SenderToReceiverVar <- mac
	
	sender.messageCounter++
	wg.Done()

}

// Function to receive message
func receiveMessage(receiver *user) {
		
	// RECEIVE MESSAGE
	message, r := <- SenderToReceiver
	messageMAC := <- SenderToReceiverVar
	if messageMAC == nil {
		fmt.Println(receiver.name, "did not receive MAC: ", messageMAC)
	} else {
		// Check received messageMAC
		MK_temp := sha256.Sum256([]byte(receiver.SharedSecretHash))
		var MK []byte = MK_temp[:]
		macVerified := checkMAC([]byte(message), messageMAC, MK)
		if macVerified == false {
			fmt.Println("Message MAC INVALID: ", macVerified)
		}				
	
	}
	
	// Decrypt the received message
	if r {
		d, err := decrypt([]byte(receiver.SharedSecretHash), []byte(message))
		if err != nil {
			fmt.Println("Decryption Failed!")
		}
		fmt.Println(receiver.name, "received:", string(d))
	} else {
			fmt.Printf("Error")
	}
	
	wg.Done()
}


func initiateRekeying (sender *user) {
	
	// INITIATE RE-KEYING
	sender.dhSecret, sender.dhPublicOwn = getDHSecretAndPublicKey(sender.dhPrime, sender.dhGenerator)
	// Create MAC of own DH Public Key
	MK_temp := sha256.Sum256([]byte(sender.SharedSecretHash))
	var MK []byte = MK_temp[:]
	DHKeyMAC := generateMAC([]byte(string(sender.dhPublicOwn)), MK)	

	// Send own DH Public Key and its MAC
	fmt.Println("************************** Re-Keying ***************************")
	fmt.Println(sender.name, "initiates re-keying and sends new DH Public Key")
	SenderToReceiverInt <- sender.dhPublicOwn
	SenderToReceiverVar <- DHKeyMAC
	// Receive Receiver's DH Public Key and its MAC
	sender.dhPublicPartner = <-ReceiverToSenderInt
	DHPublicPartnerMAC := <- ReceiverToSenderVar

	// Verify received MAC
	DHPartnerMACVerified := checkMAC([]byte(string(sender.dhPublicPartner)), DHPublicPartnerMAC, MK)
	if DHPartnerMACVerified == false {
		fmt.Println(sender.name," DH Public MAC Verification: ", DHPartnerMACVerified)
	}

	// Compute Shared Secret and its MD5 Hash for AES from shared secret
	sender.dhSharedSecret = getSharedSecret(sender.dhSecret,sender.dhPublicPartner, sender.dhPrime) 
	sender.SharedSecretHash = generateMD5Hash(sender.dhSharedSecret)
	
	wg.Done()
}

func respondToRekeying (receiver *user) {

	// RECEIVE RE-KEYING
	// Create own DH Secret and Public Key
	receiver.dhSecret, receiver.dhPublicOwn = getDHSecretAndPublicKey(receiver.dhPrime, receiver.dhGenerator)
	
	// Receive DH Public Key and its MAC
	receiver.dhPublicPartner = <-SenderToReceiverInt
	DHPublicPartnerMAC := <- SenderToReceiverVar
	
	// Create MAC of DH Public Key and send it
	MK_temp := sha256.Sum256([]byte(receiver.SharedSecretHash))
	var MK []byte = MK_temp[:]
	DHKeyMAC := generateMAC([]byte(string(receiver.dhPublicOwn)), MK)

	// Send DH Public Key and its MAC
	fmt.Println(receiver.name, "answers with new DH Public Key")
	ReceiverToSenderInt <- receiver.dhPublicOwn
	ReceiverToSenderVar <- DHKeyMAC
	
	// Verify received MAC
	DHPartnerMACVerified := checkMAC([]byte(string(receiver.dhPublicPartner)), DHPublicPartnerMAC, MK)
	if DHPartnerMACVerified == false {
		fmt.Println(receiver.name, " DH Public MAC Verification: ", DHPartnerMACVerified)
	}
	// Compute Shared Secret and its MD5 Hash for AES from shared secret
	receiver.dhSharedSecret = getSharedSecret(receiver.dhSecret, receiver.dhPublicPartner, receiver.dhPrime) 
	receiver.SharedSecretHash = generateMD5Hash(receiver.dhSharedSecret)
	
	wg.Done()
}


/********************************************* Main *********************************************/
func main() {

	// Get initial seed to ensure randomness
	mrand.Seed(time.Now().UTC().UnixNano())
	

	// Generate Alice and Bob's RSA Keys
	// Define bitSize of RSA Keys
	bitSize := 2048
	aliceRSAPublicKey, aliceRSAPrivateKey, err:= generateKeys(bitSize)
	if err != nil {
		fmt.Println(" RSA Key Generation Failed!")
	}
	
	bobRSAPublicKey, bobRSAPrivateKey, err:= generateKeys(bitSize)
	if err != nil {
		fmt.Println(" RSA Key Generation Failed!")
	}
	
    // Create Messages
	aliceMessages := []string{
		"Lights on", 
		"Forward drift?", 
		"413 is in", 
		"The Eagle has landed"} 
	
	bobMessages := []string{
		"30 seconds", 
		"yes", 
		"Houston, Tranquility base here", 
		"A small step for a student, a giant leap for the group"}
	
	// Create User Objects with partly initial dummy values
	alice := user{0, "Alice", aliceMessages, 0, &aliceRSAPublicKey, aliceRSAPrivateKey, &bobRSAPublicKey, 0, 0, 0, 0, 0, 0, ""}
	bob := user{1, "Bob", bobMessages, 0, &bobRSAPublicKey, bobRSAPrivateKey, &aliceRSAPublicKey, 0, 0, 0, 0, 0, 0, ""}
	
	// Set up initial Diffie-Hellman Parameters
	wg.Add(1)
	go initiateDHParameters(&alice)
	wg.Add(1)
	go receiveDHParameters(&bob)
	wg.Wait()
	
	
	// Send and Receive Messages (Alice sends messages with even, Bob with odd numbers) and Re-Keying
	for i := 1; i < 9; i++ {
		var sender, receiver *user
		
		if (i%2==1){
			sender = &alice
			receiver = &bob
		} else{
			sender = &bob
			receiver = &alice
		}
		
		// Send Message
		wg.Add(1)
		go sendMessage(sender, i)
		// Receive Message
		wg.Add(1)
		go receiveMessage (receiver)
		wg.Wait()
		//Re-Keying
		wg.Add(1)
		go initiateRekeying(sender)
		wg.Add(1)
		go respondToRekeying(receiver)
		wg.Wait()
	}
	
}

