package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ssh"
)

func set32BytePassword(passw string) ([]byte, error) {
	if len(passw) > 32 {
		return []byte(""), fmt.Errorf("password is to large")
	} else if len(passw) == 32 {
		return []byte(passw), nil
	}
	key := make([]byte, 32)
	i := 0
	for i < len(passw) {
		key[i] = passw[i]
		i++
	}
	for i < 32 {
		key[i] = 0
		i++
	}
	return key, nil
}
func tSShConnection(pKey interface{}) {
	privateKey, err := ssh.NewSignerFromKey(pKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get signer from private key: %v\n", err)
		os.Exit(1)
	}
	config := &ssh.ClientConfig{
		User: "d",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Note: Do not use this for production
	}

	// Connect to SSH server
	host := "127.0.0.99:3333"
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to dial: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Now you can use the client to execute commands, create sessions, etc.
	// For example, creating a session:
	session, err := client.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create session: %v\n", err)
		os.Exit(1)
	}
	defer session.Close()

	// Execute a command
	output, err := session.CombinedOutput("ls -l")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to execute command: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func main() {
	mnemonic := "orchard slow airport right beauty impact file disorder scrap tide moral heavy remove blade sketch garbage ugly depart culture accuse hello treat kid wrong"
	// Generate a 256-bit key for encryption
	// key := make([]byte, 32)
	// if _, err := rand.Read(key); err != nil {
	// 	log.Fatal(err)
	// }
	// key = []byte("password")
	// Generate a nonce for ChaCha20
	// nonce := make([]byte, chacha20.NonceSizeX)
	// if _, err := rand.Read(nonce); err != nil {
	// 	log.Fatal(err)
	// }
	key, err := set32BytePassword("password")
	if err != nil {
		log.Fatal(err)
	}
	nonce := []byte("24CharacterNonce!!!!!!!!")
	if len(nonce) != 24 {
		log.Fatal("Nonce must be exactly 24 bytes long")
	}
	encryptedMnemonic := encryptMnemonic(mnemonic, key, nonce)

	// differentKey, _ := set32BytePassword("pepelaug1h1231sdfsdfsdf")
	// decryptedMnemonic := decryptMnemonic(hex.EncodeToString(encryptedMnemonic), hex.EncodeToString(differentKey), hex.EncodeToString(nonce))
	decryptedMnemonic := decryptMnemonic(hex.EncodeToString(encryptedMnemonic), hex.EncodeToString(key), hex.EncodeToString(nonce))
	// fmt.Printf("Encryption Key: %s\n", hex.EncodeToString(key))

	priv, err := generatePublicAndPrivateSSHKeys(string(decryptedMnemonic))
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("Debug:::::::::")
	// fmt.Printf("Encrypted Mnemonic: %v, len: %v\n", encryptedMnemonic, len(encryptedMnemonic))
	// fmt.Printf("Encrypted Mnemonic Hex: <%x>, len: %v\n\nnonceHex: %x\nnonce: %v\n\n", encryptedMnemonic, len(fmt.Sprintf("%x", encryptedMnemonic)), hex.EncodeToString(nonce), nonce)
	// fmt.Printf("keyHex: %v\nkey: %v len:%v\nkeyString: %s\nbase64: %s\n\n", hex.EncodeToString(key), key, len(key), string(key), base64.StdEncoding.EncodeToString(key))
	// fmt.Printf("Original Mnemonic:\n%s\nDecrypted mnemonic:\n%v\n", mnemonic, string(decryptedMnemonic))
	tSShConnection(priv)
	writePrivAndPubKeysToFiles(priv)
}

func writePrivAndPubKeysToFiles(privKey *ecdsa.PrivateKey) error {
	// Convert the ECDSA private key to an SSH public key
	publicKeySSH, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		fmt.Println("Error converting to SSH public key:", err)
		return err
	}

	// Save the SSH public key
	err = os.WriteFile("public_key.pub", ssh.MarshalAuthorizedKey(publicKeySSH), 0655)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return err
	}

	// Convert the private key to PEM format
	x509Encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		fmt.Println("Error encoding private key:", err)
		return err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})

	// Save the private key
	err = os.WriteFile("private_key.pem", pemEncoded, 0600)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return err
	}
	return nil
}

func generatePublicAndPrivateSSHKeys(mnemonic string) (*ecdsa.PrivateKey, error) {
	// Your 24-word BIP39 mnemonic
	// mnemonic := "your 24-word mnemonic here"

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Use the seed to generate an ECDSA private key
	// Note: This is a simplistic approach; in real applications, more sophisticated methods are used.
	privateKey, err := seedToPrivateKey(seed)
	if err != nil {
		fmt.Println("Error creating private key from seed:", err)
		return nil, err
	}
	privateKey, err = seedToPrivateKey(seed)
	if err != nil {
		fmt.Println("Error creating private key from seed:", err)
		return nil, err
	}

	fmt.Println("SSH key pair generated successfully.")
	fmt.Println("trace")

	fmt.Printf("Seed:\n%s\nPrivateKey:\n%v\n", seed, privateKey)
	fmt.Println("trace")
	// signer, _ := ssh.NewSignerFromKey(privateKey)
	return privateKey, nil

}

func seedToPrivateKey(seed []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(seed[:32]) // Using the first 32 bytes of the seed
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(seed[:32])
	return privKey, nil
}

func encryptMnemonic(mnemonic string, key, nonce []byte) (enctyptedMnemonic []byte) {

	// Create a new ChaCha20 cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the mnemonic
	data := []byte(mnemonic)
	enctyptedMnemonic = make([]byte, len(data))
	cipher.XORKeyStream(enctyptedMnemonic, data)
	// fmt.Printf("len of encrypted %v\n", )

	return enctyptedMnemonic
}

func decryptMnemonic(encryptedMnemonicHex, keyHex, nonceHex string) []byte {
	// The encryption key and nonce used during encryption
	// In a real-world application, these should be securely stored and retrieved
	// keyHex := "your 256-bit key in hex"
	// nonceHex := "your nonce in hex"

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatalf("error when decoding keyHex: %s", err)
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		log.Fatalf("error when decoding nonceHex %s", err)
	}

	// Encrypted data (hexadecimal format)
	// encryptedHex := "your encrypted data in hex"
	encrypted, err := hex.DecodeString(encryptedMnemonicHex)
	if err != nil {
		log.Fatalf("error when decoding encryptedHex %s", err)
	}

	// Create a new ChaCha20 cipher for decryption
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt the data
	decrypted := make([]byte, len(encrypted))
	cipher.XORKeyStream(decrypted, encrypted)

	return decrypted
}
