package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	// Load private key from file
	key, err := os.ReadFile(`D:\Coding\Go\sshKeyFromMnemonicTest\private_key.pem`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read private key: %v\n", err)
		os.Exit(1)
	}

	// Parse the private key
	privateKey, err := ssh.ParsePrivateKey(key)
	
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse private key: %v\n", err)
		os.Exit(1)
	}

	// Create SSH client configuration
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
