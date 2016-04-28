package tarpan

import (
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
	Get(params map[string]string, oids []string) []gosnmp.SnmpPDU
	Run()
}

type TarpanManager struct {
	snmp *gosnmp.GoSNMP
}

type SnmpResult struct {
	target  Target
	results []gosnmp.SnmpPDU
	time    int64
}

type Channels struct {
	semaphoe chan int
	results  chan SnmpResult
}

func (t *TarpanManager) Get(params map[string]string,
	oids []string) []gosnmp.SnmpPDU {
	t.SetParams(params)
	connection_err := t.snmp.Connect()
	if connection_err != nil {
		log.Fatalf("Connection error: %")
	}
	result, request_err := t.snmp.Get(oids)
	if request_err != nil {
		log.Println("Get() error: %v", request_err)
	}
	t.snmp.Conn.Close()

	return result.Variables
}

func (t *TarpanManager) SetManager(manager *gosnmp.GoSNMP) {
	t.snmp = manager
	return
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

	return
}

func makeRequestBody(ds *DataSet, idx int) (map[string]string, error) {
	address := ""
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
	request_body := map[string]string{
		"target":    address,
		"community": community,
		"version":   version,
	}

	return request_body, err
}

func makeChannel(result_buffer_length int) *Channels {
	channel := &Channels{
		semaphoe: make(chan int, ConcurrentProcesses),
		results:  make(chan SnmpResult, result_buffer_length),
	}

	return channel
}

func makeTarpanResult(c *Channels) []*TarpanResult {
	var tarpanResults []*TarpanResult
	var varbinds []VarBind
	var result SnmpResult
	length := len(c.results)
	for i := 0; i < length; i++ {
		varbinds = []VarBind{}
		result = <-c.results
		for _, val := range result.results {
			for _, o := range result.target.OIDs {
				n := strings.TrimLeft(val.Name, ".")
				if o.OID == n {
					v := VarBind{
						Description: o.Description,
						OID:         val.Name,
						Type:        val.Type,
						Value:       val.Value,
						Time:        result.time,
					}
					varbinds = append(varbinds, v)
					break
				}
			}
		}
		tr := &TarpanResult{
			Name:      result.target.Name,
			Address:   result.target.Address,
			Port:      result.target.Port,
			Version:   result.target.Version,
			Community: result.target.Community,
			VarBinds:  varbinds,
		}
		tarpanResults = append(tarpanResults, tr)
	}

	return tarpanResults
}

func Collect(dataset *DataSet) []*TarpanResult {
	var waitGroup sync.WaitGroup
	var tm TarpanManager
	var channels *Channels
	var oids []string

	channels = makeChannel(len(dataset.Targets))
	for index := range dataset.Targets {
		tm = TarpanManager{}
		tm.SetManager(new(gosnmp.GoSNMP))

		// TODO: split oid slice according to PDU size
		oids = []string{}
		for oid_idx := range dataset.Targets[index].OIDs {
			oids = append(oids, dataset.Targets[index].OIDs[oid_idx].OID)
		}

		waitGroup.Add(1)
		go func(ds *DataSet, idx int, o []string, c *Channels) {
			c.semaphoe <- 0
			req_body, req_body_err := makeRequestBody(ds, idx)
			if req_body_err != nil {
				log.Print(req_body_err)
				<-c.semaphoe
				return
			}
			t := time.Now()
			results := tm.Get(req_body, o)
			ret := SnmpResult{
				target:  ds.Targets[idx],
				results: results,
				time:    t.Unix(),
			}
			c.results <- ret
			<-c.semaphoe
			waitGroup.Done()
		}(dataset, index, oids, channels)
	}
	waitGroup.Wait()
	tr := makeTarpanResult(channels)

	return tr
}

func Run(target string) (int, error) {
	var err error

	// Load targets
	dataset, loadErr := loadConfig(target)
	if loadErr != nil {
		return ExitCodeConfError, loadErr
	}

	// collect data
	tr := Collect(dataset)

	// output
	Write("aa", tr)

	return ExitCodeOK, err
}
