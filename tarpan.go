package tarpan

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soniah/gosnmp"
)

// Tarpan constants
const (
	ConcurrentProcesses = 5
)

// Exit code
const (
	ExitCodeOK = iota
	ExitCodeConfError
	ExitCodeParseFlagError
)

// SNMP constants
const (
	community = "public"
	port      = 161
	timeout   = 2
	retry     = 3
	//MaximumPDUBytes = 512
)

// JSON structure definition
type DataSet struct {
	Default Defaults `json:"defaults"`
	Targets []Target `json:"targets"`
}

type Defaults struct {
	Port      uint16 `json:"port"`
	Version   string `json:"version"`
	Community string `json:"community"`
}

type Target struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Version   string `json:"version"`
	Community string `json:"community"`
	OIDs      []OID  `json:"oids"`
}

type OID struct {
	OID         string `json:"oid"`
	Description string `json:"description"`
}

// Tarpan result structures
type TarpanResult struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	Port      uint16    `json:"port"`
	Version   string    `json:"version"`
	Community string    `json:"community"`
	VarBinds  []VarBind `json:"varbinds"`
}

type VarBind struct {
	Description string         `json:"description"`
	OID         string         `json:"oid"`
	Type        gosnmp.Asn1BER `json:"type"`
	Value       interface{}    `json:"value"`
	Time        int64          `json:"time"`
}

type Tarpan interface {
	makeRequestBody()
	SetManager()
	SetParams()
	Get(params map[string]string, oids []string) ([]gosnmp.SnmpPDU, error)
	Run()
}

type TarpanManager struct {
	snmp *gosnmp.GoSNMP
}

type SnmpResult struct {
	index   int
	target  Target
	results []gosnmp.SnmpPDU
	time    int64
}

type Channels struct {
	semaphoe chan int
	results  chan SnmpResult
}

func (t *TarpanManager) Get(params map[string]string,
	oids []string) ([]gosnmp.SnmpPDU, error) {
	t.SetParams(params)
	connection_err := t.snmp.Connect()
	if connection_err != nil {
		log.Fatalf("Connection error: %")
		return nil, errors.New(connection_err.Error())
	}
	result, request_err := t.snmp.Get(oids)
	if request_err != nil {
		return nil, errors.New(request_err.Error())
	}
	t.snmp.Conn.Close()

	return result.Variables, nil
}

func (t *TarpanManager) SetManager(manager *gosnmp.GoSNMP) {
	t.snmp = manager
}

func (t *TarpanManager) SetParams(p map[string]string) {
	if value, ok := p["target"]; ok {
		t.snmp.Target = value
	}
	if value, ok := p["port"]; ok {
		port, _ := strconv.ParseUint(value, 10, 16)
		t.snmp.Port = uint16(port)
	} else {
		t.snmp.Port = uint16(port)
	}
	if value, ok := p["community"]; ok {
		t.snmp.Community = value
	}
	if value, ok := p["version"]; ok {
		if value == "2c" {
			t.snmp.Version = gosnmp.Version2c
		}
	}
	if value, ok := p["timeout"]; ok {
		sec, _ := strconv.Atoi(value)
		t.snmp.Timeout = time.Duration(sec) * time.Second
	} else {
		t.snmp.Timeout = time.Duration(timeout) * time.Second
	}
	if value, ok := p["retries"]; ok {
		retries, _ := strconv.Atoi(value)
		t.snmp.Retries = retries
	} else {
		t.snmp.Retries = retry

	}
}

func getRequestParams(ds *DataSet, idx int) (map[string]string, error) {
	var address string
	err := validateIP(ds.Targets[idx].Address)
	if err == nil {
		address = ds.Targets[idx].Address
	} else {
		return map[string]string{}, err
	}
	community := ds.Targets[idx].Community
	if community == "" {
		community = ds.Default.Community
	}
	version := ds.Targets[idx].Version
	if version == "" {
		version = ds.Default.Version
	}
	port := ds.Targets[idx].Port
	if port == 0 {
		port = ds.Default.Port
	}

	request_body := map[string]string{
		"target":    address,
		"community": community,
		"version":   version,
		"port":      strconv.Itoa(int(port)),
	}

	return request_body, nil
}

func makeChannel(result_buffer_size int) *Channels {
	channel := &Channels{
		semaphoe: make(chan int, ConcurrentProcesses),
		results:  make(chan SnmpResult, result_buffer_size),
	}

	return channel
}

func makeTarpanResult(result SnmpResult) *TarpanResult {
	var varbinds []VarBind
	for _, val := range result.results {
		n := strings.TrimLeft(val.Name, ".")
		desc, _ := getTargetOIDDescription(n, result.target.OIDs)
		v := VarBind{
			Description: desc,
			OID:         val.Name,
			Type:        val.Type,
			Value:       val.Value,
			Time:        result.time,
		}
		varbinds = append(varbinds, v)
	}

	tarpanResult := &TarpanResult{
		Name:      result.target.Name,
		Address:   result.target.Address,
		Port:      result.target.Port,
		Version:   result.target.Version,
		Community: result.target.Community,
		VarBinds:  varbinds,
	}

	return tarpanResult
}

func removeNilResult(tarpanResults []*TarpanResult) []*TarpanResult {
	var responseResult []*TarpanResult
	for _, v := range tarpanResults {
		if v != nil {
			responseResult = append(responseResult, v)
		}
	}

	return responseResult
}

func makeTarpanResults(c *Channels) []*TarpanResult {
	result_length := len(c.results)
	tarpanResults := make([]*TarpanResult, result_length)
	var result SnmpResult
	for i := 0; i < result_length; i++ {
		result = <-c.results
		tarpanResults[result.index] = makeTarpanResult(result)
	}

	return removeNilResult(tarpanResults)
}

func getTargetOIDDescription(oid string, oids []OID) (string, error) {
	for _, o := range oids {
		if o.OID == oid {
			return o.Description, nil
		}
	}

	return "", errors.New("oid not found")
}

func Collect(dataset *DataSet) []*TarpanResult {
	var waitGroup sync.WaitGroup
	var managers []*TarpanManager
	var channels *Channels
	var oids []string

	for i := 0; i < len(dataset.Targets); i++ {
		managers = append(managers, &TarpanManager{
			snmp: &gosnmp.GoSNMP{},
		})
	}

	channels = makeChannel(len(dataset.Targets))
	for index := range dataset.Targets {

		// TODO: split oid slice according to PDU size
		oids = []string{}
		for oid_idx := range dataset.Targets[index].OIDs {
			oids = append(oids, dataset.Targets[index].OIDs[oid_idx].OID)
		}

		waitGroup.Add(1)
		go func(ds *DataSet, idx int, o []string, c *Channels) {
			defer waitGroup.Done()
			c.semaphoe <- 0
			req_body, req_body_err := getRequestParams(ds, idx)
			if req_body_err != nil {
				log.Print(req_body_err)
				<-c.semaphoe
				return
			}
			t := time.Now()
			results, err := managers[idx].Get(req_body, o)
			if err != nil {
				log.Print(err)
				<-c.semaphoe
				return
			}
			c.results <- SnmpResult{
				index:   idx,
				target:  ds.Targets[idx],
				results: results,
				time:    t.Unix(),
			}
			<-c.semaphoe
		}(dataset, index, oids, channels)
	}
	waitGroup.Wait()
	tr := makeTarpanResults(channels)

	return tr
}

func Run(target string, output string, debug bool) (int, error) {
	var err error

	// Load targets
	dataset, loadErr := loadConfig(target)
	if loadErr != nil {
		return ExitCodeConfError, loadErr
	}

	// collect data
	tr := Collect(dataset)

	// output
	Write(output, tr)

	return ExitCodeOK, err
}
