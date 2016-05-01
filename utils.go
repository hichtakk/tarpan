package tarpan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	g "github.com/soniah/gosnmp"
)

// Utility functions
func loadConfig(path string) (*DataSet, error) {
	var dataset DataSet
	fd, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("File Error: ", err)
		return nil, err
	}
	json_err := json.Unmarshal(fd, &dataset)
	if json_err != nil {
		fmt.Println("Config Format Error: ", json_err)
		return nil, json_err
	}

	return &dataset, err
}

func validateIP(address string) error {
	var err error
	err = nil
	addr := net.ParseIP(address)
	if addr == nil {
		return errors.New("invalid ip address was passed")
	}

	return err
}

func validatePort(port uint16) (uint16, error) {
	return port, nil
}

func getSnmpVersionString(snmpVersion g.SnmpVersion) string {
	var version string
	switch snmpVersion {
	case g.Version1:
		version = "1"
	case g.Version2c:
		version = "2c"
	case g.Version3:
		version = "3"
	default:
		version = ""
	}

	return version
}

func getAsn1BERName(ber g.Asn1BER) (string, error) {
	var name string
	switch ber {
	case 0x00:
		name = "UnknownType"
	case 0x01:
		name = "Boolean"
	case 0x02:
		name = "Integer"
	case 0x03:
		name = "BitString"
	case 0x04:
		name = "OctetString"
	case 0x05:
		name = "Null"
	case 0x06:
		name = "ObjectIdentifier"
	case 0x07:
		name = "ObjectDescription"
	case 0x40:
		name = "IPAddress"
	case 0x41:
		name = "Counter32"
	case 0x42:
		name = "Gauge32"
	case 0x43:
		name = "TimeTicks"
	case 0x44:
		name = "Opaque"
	case 0x45:
		name = "NsapAddress"
	case 0x46:
		name = "Counter64"
	case 0x47:
		name = "Uinteger32"
	case 0x80:
		name = "NoSuchObject"
	case 0x81:
		name = "NoSuchInstance"
	case 0x82:
		name = "EndOfMibView"
	default:
		return "", errors.New("Unknown BER")
	}

	return name, nil
}

func formatSnmpValue(ber g.Asn1BER, value string) string {
	switch ber {
	case g.Counter32, g.Gauge32, g.Counter64:
		return value
	case g.NoSuchObject, g.NoSuchInstance:
		return "-"
	default:
		return value
	}

	return ""
}
