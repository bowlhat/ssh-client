package sshclient

import (
	"fmt"
	"net"
	"time"

	sshagent "github.com/bowlhat/ssh-agent"

	"golang.org/x/crypto/ssh"
)

// SSHConnection ...
type SSHConnection struct {
	Client  *ssh.Client
	SSHConn ssh.Conn
	TCPConn *TCPConnection
}

// TCPConnection ...
type TCPConnection struct {
	Connection net.Conn
}

// New make new ssh client connection
func New(hostname string, port int, username string, password string) (client *SSHConnection, err error) {
	addr := fmt.Sprintf("%s:%d", hostname, port)
	auth := makeAuth(username, password)

	tcp, err := makeTCP(addr, 90)
	if err != nil {
		return nil, err
	}

	ssh, err := tcp.makeSSHConn(addr, auth)
	if err != nil {
		return nil, err
	}

	return ssh, nil
}

func makeAuth(username string, password string) *ssh.ClientConfig {
	var authmethods []ssh.AuthMethod
	if agent := sshagent.New(); agent != nil {
		authmethods = append(authmethods, ssh.PublicKeysCallback(agent))
	}
	if password != "" {
		authmethods = append(authmethods, ssh.Password(password))
	}
	return &ssh.ClientConfig{
		User: username,
		Auth: authmethods,
	}
}

func makeTCP(addr string, timeout time.Duration) (connection *TCPConnection, err error) {
	var tcp net.Conn
	tcp, err = net.DialTimeout("tcp", addr, time.Second*timeout)
	if err != nil {
		return nil, err
	}
	return &TCPConnection{Connection: tcp}, nil
}

func (tcp *TCPConnection) makeSSHConn(addr string, auth *ssh.ClientConfig) (connection *SSHConnection, err error) {
	conn, chans, reqs, err := ssh.NewClientConn(tcp.Connection, addr, auth)
	if err != nil {
		tcp.Close()
		return nil, err
	}

	client := ssh.NewClient(conn, chans, reqs)
	return &SSHConnection{Client: client, SSHConn: conn, TCPConn: tcp}, nil
}

// Close Close the TCP connection
func (tcp *TCPConnection) Close() error {
	return tcp.Connection.Close()
}

// Close close the SSH session
func (ssh *SSHConnection) Close() error {
	if err := ssh.Client.Close(); err != nil {
		return err
	}
	if err := ssh.SSHConn.Close(); err != nil {
		return err
	}
	return ssh.TCPConn.Close()
}
