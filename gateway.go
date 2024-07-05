package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"gopkg.in/yaml.v2"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// Config holds the authentication details
type Config struct {
	ValidSSHKeys map[string]gossh.PublicKey // map[username]publicKey
	PrivateKeys  map[string]string          // map[username]privateKeyPath
	Allowlist    []*net.IPNet               // list of allowlisted IPs or IP ranges
	HoneypotAddr string                     `yaml:"honeypot_addr"`
	RealSSHAddr  string                     `yaml:"real_ssh_addr"`
	SSHPort      int                        `yaml:"ssh_port"`
}

type User struct {
	Username   string `yaml:"username"`
	SSHKey     string `yaml:"ssh_key,omitempty"`
	PrivateKey string `yaml:"private_key,omitempty"`
}

var config Config

func loadConfig(filePath string) error {
	config.ValidSSHKeys = make(map[string]gossh.PublicKey)
	config.PrivateKeys = make(map[string]string)

	// Load the config file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var rawConfig struct {
		HoneypotAddr string   `yaml:"honeypot_addr"`
		RealSSHAddr  string   `yaml:"real_ssh_addr"`
		SSHPort      int      `yaml:"ssh_port"`
		Allowlist    []string `yaml:"allowlist"`
		Users        []User   `yaml:"users"`
	}

	err = yaml.Unmarshal(data, &rawConfig)
	if err != nil {
		return err
	}

	config.HoneypotAddr = rawConfig.HoneypotAddr
	config.RealSSHAddr = rawConfig.RealSSHAddr
	config.SSHPort = rawConfig.SSHPort

	// Parse allowlist
	for _, cidr := range rawConfig.Allowlist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				log.Printf("Invalid IP range: %s", cidr)
			} else {
				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				}
			}
		}
		config.Allowlist = append(config.Allowlist, ipNet)
	}

	// Parse users
	for _, user := range rawConfig.Users {
		if user.SSHKey != "" {
			parsedKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(user.SSHKey))
			if err != nil {
				log.Printf("Failed to parse SSH key for user %s: %v", user.Username, err)
				continue
			}
			config.ValidSSHKeys[user.Username] = parsedKey
			config.PrivateKeys[user.Username] = user.PrivateKey
			log.Printf("Loaded SSH key for user %s: %s", user.Username, gossh.MarshalAuthorizedKey(parsedKey))
		} else {
			log.Printf("Invalid user configuration: %v", user)
		}
	}

	return nil
}

func isAllowlisted(ip string) bool {
	for _, ipNet := range config.Allowlist {
		if ipNet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func main() {
	configFilePath := "config.yaml" // Path to your config file

	err := loadConfig(configFilePath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	sshServer := &ssh.Server{
		Addr: fmt.Sprintf(":%d", config.SSHPort),
		Handler: func(s ssh.Session) {
			user := s.User()
			clientIP := s.RemoteAddr().String()

			log.Printf("Session started for user %s from IP %s", user, clientIP)

			if isAllowlisted(clientIP) {
				log.Printf("IP %s is allowlisted, forwarding to real server", clientIP)
				forwardConnection(s, config.RealSSHAddr)
				return
			}

			pubKey := s.PublicKey()
			if pubKey != nil {
				marshaledKey := string(gossh.MarshalAuthorizedKey(pubKey))
				log.Printf("Received public key for user %s: %s", user, marshaledKey)
				if validateSSHKey(user, pubKey) {
					log.Printf("SSH key for user %s matches, forwarding to honeypot", user)
					privateKeyPath := config.PrivateKeys[user]
					forwardToHoneypot(s, config.HoneypotAddr, user, privateKeyPath)
					return
				} else {
					log.Printf("SSH key for user %s does not match, forwarding to real server", user)
				}
			} else {
				log.Printf("No public key received for user %s, forwarding to real server", user)
			}
			forwardConnection(s, config.RealSSHAddr)
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			// This will be called during authentication
			return true
		},
	}

	log.Printf("Starting SSH proxy server on :%d", config.SSHPort)
	log.Fatal(sshServer.ListenAndServe())
}

func validateSSHKey(username string, key gossh.PublicKey) bool {
	if storedKey, ok := config.ValidSSHKeys[username]; ok {
		marshaledKey := gossh.MarshalAuthorizedKey(key)
		storedMarshaledKey := gossh.MarshalAuthorizedKey(storedKey)

		log.Printf("Comparing provided key:\n%s\nwith stored key:\n%s", marshaledKey, storedMarshaledKey)

		return string(marshaledKey) == string(storedMarshaledKey)
	}
	log.Printf("No valid SSH key found for user %s", username)
	return false
}

func forwardToHoneypot(s ssh.Session, honeypotAddr, username, privateKeyPath string) {
	privateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Printf("Failed to read private key file: %v", err)
		s.Exit(1)
		return
	}

	signer, err := gossh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Printf("Failed to parse private key: %v", err)
		s.Exit(1)
		return
	}

	config := &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(signer),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := gossh.Dial("tcp", honeypotAddr, config)
	if err != nil {
		log.Printf("Failed to connect to honeypot: %v", err)
		s.Exit(1)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		s.Exit(1)
		return
	}
	defer session.Close()

	// Set up the channels to proxy the data
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Printf("Unable to setup stdin for session: %v", err)
		s.Exit(1)
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Printf("Unable to setup stdout for session: %v", err)
		s.Exit(1)
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		log.Printf("Unable to setup stderr for session: %v", err)
		s.Exit(1)
		return
	}

	go io.Copy(stdin, s)
	go io.Copy(s, stdout)
	go io.Copy(s.Stderr(), stderr)

	err = session.Shell()
	if err != nil {
		log.Printf("Failed to start shell: %v", err)
		s.Exit(1)
		return
	}

	err = session.Wait()
	if err != nil {
		log.Printf("Session ended with error: %v", err)
	}
}

func forwardConnection(s ssh.Session, addr string) {
	client, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", addr, err)
		s.Exit(1)
		return
	}
	defer client.Close()

	go func() {
		io.Copy(client, s)
	}()
	io.Copy(s, client)
}
