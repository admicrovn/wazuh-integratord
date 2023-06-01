package integrator

import (
	"encoding/json"
	"github.com/admicrovn/wazuh-integratord/config"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
)

const defaultSockAddr = "/var/ossec/queue/sockets/integrator"

// getIntegrationConfig listen and respond for requests
// get integration config from Wazuh Manager API
func (i *Integrator) getIntegrationConfig(c io.ReadWriteCloser) {
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		log.Errorf("read data err: %s", err)
		c.Close()
		return
	}
	data := buf[0:n]

	// skip first 4 bytes header: [21 0 0 0]
	// validate command
	if string(data[4:n]) == "getconfig integration" {
		// read command then return config
		integrationsConf := make(map[string][]config.Integration, 0)
		integrationsConf["integration"] = i.config.WazuhConfig.Integrations
		var integrationConfB []byte
		integrationConfB, err = json.Marshal(&integrationsConf)
		if err != nil {
			log.Errorf("marshall err: %s", err)
			c.Close()
			return
		}
		// response data must be start with string "ok"
		// https://github.com/wazuh/wazuh/blob/master/src/os_integrator/intgcom.c#L49 (server)
		// https://github.com/wazuh/wazuh/blob/master/framework/wazuh/core/configuration.py#L811 (client)
		okB := []byte("ok")
		// Wazuh Manager API (python) will skip first 4 bytes header: [9 2 0 0]
		// captured from a response of original wazuh-integratord
		// https://github.com/wazuh/wazuh/blob/master/framework/wazuh/core/wazuh_socket.py#L46
		spacesB := []byte{9, 2, 0, 0}
		var respB []byte
		respB = append(respB, spacesB...)
		respB = append(respB, okB...)
		respB = append(respB, []byte{32}...)
		respB = append(respB, integrationConfB...)
		// response something like this:
		// ok {"integration":[{"name":"custom-telegram","hook_url":"...}
		_, err = c.Write(respB)
		if err != nil {
			log.Errorf("write err: %s", err)
			c.Close()
			return
		}
	}
	c.Close()
}

// RunIntegratorSocketServer start a unix socket server
func (i *Integrator) RunIntegratorSocketServer() {
	sockAddr := defaultSockAddr
	// development
	if os.Getenv("ENV") == "dev" {
		sockAddr = "./integrator.sock"
	}
	if err := os.RemoveAll(sockAddr); err != nil {
		log.Fatal(err.Error())
	}

	l, err := net.Listen("unix", sockAddr)
	if err != nil {
		log.Fatalf("listen error: %s", err)
	}
	err = os.Chmod(sockAddr, 0660)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer l.Close()

	for {
		var conn net.Conn
		conn, err = l.Accept()
		if err != nil {
			log.Panicf("accept error: %s", err)
		}

		go i.getIntegrationConfig(conn)
	}
}
