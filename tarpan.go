package tarpan

import (
	"errors"
	"log"
	"strconv"
	//"strings"
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
	COMMUNITY = "public"
	PORT      = 161
	TIMEOUT   = 2
	RETRY     = 3
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

type RequestParams struct {
	target    string
	community string
	version   string
	port      string
	timeout   uint8
	retry     uint8
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

func (t *TarpanManager) Get(params *RequestParams,
	oids []string) ([]gosnmp.SnmpPDU, error) {
	t.SetParams(params)
	connection_err := t.snmp.Connect()
	defer t.snmp.Conn.Close()
	if connection_err != nil {
		log.Fatalf("Connection error: %")
		return nil, errors.New(connection_err.Error())
	}
	snmpPacket, request_err := t.snmp.Get(oids)
	if request_err != nil {
		return nil, errors.New(request_err.Error())
	}
	/*
		now = time.Now()
		&SnmpResult{
			index:   "",
			target:  "",
			results: snmpPacket.Variables,
			time:    now.Unix(),
		}
	*/

	return snmpPacket.Variables, nil
}

func (t *TarpanManager) SetManager(manager *gosnmp.GoSNMP) {
	t.snmp = manager
}

func (t *TarpanManager) SetParams(p *RequestParams) {
	if p.target != "" {
		t.snmp.Target = p.target
	}
	if p.port != "" {
		port, _ := strconv.ParseUint(p.port, 10, 16)
		t.snmp.Port = uint16(port)
	} else {
		t.snmp.Port = uint16(PORT)
	}
	if p.community != "" {
		t.snmp.Community = p.community
	} else {
		t.snmp.Community = COMMUNITY
	}
	if p.version != "" {
		if p.version == "2c" {
			t.snmp.Version = gosnmp.Version2c
		}
	} else {
		t.snmp.Version = gosnmp.Version2c
	}
	if p.timeout != 0 {
		t.snmp.Timeout = time.Duration(p.timeout) * time.Second
	} else {
		t.snmp.Timeout = time.Duration(TIMEOUT) * time.Second
	}
	if p.retry != 0 {
		t.snmp.Retries = int(p.retry)
	} else {
		t.snmp.Retries = RETRY
	}
}

func getRequestParams(ds *DataSet, idx int) (*RequestParams, error) {
	var address string
	err := validateIP(ds.Targets[idx].Address)
	if err == nil {
		address = ds.Targets[idx].Address
	} else {
		return &RequestParams{}, err
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

	requestParams := &RequestParams{
		target:    address,
		community: community,
		version:   version,
		port:      strconv.Itoa(int(port)),
	}

	return requestParams, nil
}

func makeChannel(result_buffer_size int) *Channels {
	channel := &Channels{
		semaphoe: make(chan int, ConcurrentProcesses),
		results:  make(chan SnmpResult, result_buffer_size),
	}

	return channel
}

func getTargetOIDDescription(oid string, oids []OID) (string, error) {
	for _, o := range oids {
		if o.OID == oid {
			return o.Description, nil
		}
	}

	return "", errors.New("oid not found")
}

func makeTarpanResult(result SnmpResult) *TarpanResult {
	var varbinds []VarBind
	for _, val := range result.results {
		//n := strings.TrimLeft(val.Name, ".")
		desc, _ := getTargetOIDDescription(val.Name, result.target.OIDs)
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

func makeManagers(numberOfTargets int) []*TarpanManager {
	var managers []*TarpanManager
	for i := 0; i < numberOfTargets; i++ {
		managers = append(managers, &TarpanManager{
			snmp: &gosnmp.GoSNMP{},
		})
	}

	return managers
}

func Collect(dataset *DataSet) []*TarpanResult {
	var waitGroup sync.WaitGroup
	var oids []string

	managers := makeManagers(len(dataset.Targets))
	channels := makeChannel(len(dataset.Targets))
	for t_idx := range dataset.Targets {

		// TODO: split oid slice depending on PDU size
		oids = []string{}
		for o_idx := range dataset.Targets[t_idx].OIDs {
			oids = append(oids, dataset.Targets[t_idx].OIDs[o_idx].OID)
		}

		waitGroup.Add(1)
		go func(m *TarpanManager, ds *DataSet, idx int, o []string, c *Channels) {
			defer func() {
				waitGroup.Done()
				<-c.semaphoe
			}()
			c.semaphoe <- 0
			param, param_err := getRequestParams(ds, idx)
			if param_err != nil {
				log.Print(param_err)
				return
			}
			results, err := m.Get(param, o)
			t := time.Now()
			if err != nil {
				log.Print(err)
				return
			}
			c.results <- SnmpResult{
				index:   idx,
				target:  ds.Targets[idx],
				results: results,
				time:    t.Unix(),
			}
		}(managers[t_idx], dataset, t_idx, oids, channels)
	}
	waitGroup.Wait()
	tarpanResults := makeTarpanResults(channels)

	return tarpanResults
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
