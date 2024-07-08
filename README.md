# SSH-Honey-Gateway
![image](https://github.com/referefref/ssh-honey-gateway/assets/56499429/5778c796-ce34-40bb-ad25-116d1764b1a1)


SSH-Honey-Gateway is a lightweight SSH proxy appliance that decides where to forward SSH connections based on the authentication credentials provided. It can forward connections to a honeypot server for specific credentials or to a real SSH server for other connections. Additionally, it supports allowlisting of IPs or IP ranges that bypass the validation and are forwarded directly to the real SSH server.

![ssh-key](https://github.com/referefref/ssh-honey-gateway/assets/56499429/bfe738a6-a14f-4082-baeb-502029e46046)

## Features

- **Credential-Based Forwarding**: Forward connections based on provided SSH keys.
- **Allowlisting**: Allow specific IPs or IP ranges to bypass validation.
- **Configurable Port**: Specify which port the SSH proxy server listens on.
- **Easy Configuration**: Simple YAML configuration file for setting up users, keys, and servers.
- **Logging**: Log all matched key connections, including datetime and source IP, to a file.

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/referefref/ssh-honey-gateway.git
    cd ssh-honey-gateway
    ```

2. **Install dependencies**:
    Ensure you have Go installed, then run:
    ```sh
    go mod tidy
    ```

3. **Build the application**:
    ```sh
    go build
    ```

4. **Generate SSH Key Lure and update the config.yaml to point to the private key and public key content**:
    ```sh
    ssh-keygen -t rsa -b 2048 -f testkey
    ```




