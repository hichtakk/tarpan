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

type TarpanResults []*TarpanResult

type VarBind struct {
	Description string      `json:"description"`
	OID         string      `json:"oid"`
	Type        string      `json:"type"`
	Value       interface{} `json:"value"`
	Time        int64       `json:"time"`
}

type Tarpan interface {
	makeRequestBody()
	SetManager()
	SetParams()
	Get(params map[string]string, oids []string) ([]gosnmp.SnmpPDU, error)
	Run()
}

type TarpanManager struct {
	target *Target
	snmp   *gosnmp.GoSNMP
}

type TarpanManagers []*TarpanManager

type RequestParams struct {
	managerIndex int
	address      string
	community    string
	version      string
	port         string
	timeout      uint8
	retry        uint8
}

type Channels struct {
	semaphoe chan int
	results  chan TarpanResult
}

func (m *TarpanManager) setTarget(ds *DataSet, target_index int) error {
	params, param_err := getRequestParams(ds, target_index)
	if param_err != nil {
		log.Print(param_err)
		errors.New(param_err.Error())
	}
	m.SetParams(params)
	m.target = &ds.Targets[target_index]

	return nil
}

func (m *TarpanManager) Get(oids []string) (TarpanResult, error) {
	connection_err := m.snmp.Connect()
	defer m.snmp.Conn.Close()
	if connection_err != nil {
		log.Fatalf("Connection error: %")
		return TarpanResult{}, errors.New(connection_err.Error())
	}
	snmpPacket, request_err := m.snmp.Get(oids)
	if request_err != nil {
		return TarpanResult{}, errors.New(request_err.Error())
	}
	tarpanResult := m.makeTarpanResult(snmpPacket)

	return tarpanResult, nil
}

func (t *TarpanManager) SetManager(manager *gosnmp.GoSNMP) {
	t.snmp = manager
}

func (t *TarpanManager) SetParams(p *RequestParams) {
	if p.address != "" {
		t.snmp.Target = p.address
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
		managerIndex: idx,
		address:      address,
		community:    community,
		version:      version,
		port:         strconv.Itoa(int(port)),
	}

	return requestParams, nil
}

func makeChannel(result_buffer_size int) *Channels {
	channel := &Channels{
		semaphoe: make(chan int, ConcurrentProcesses),
		results:  make(chan TarpanResult, result_buffer_size),
	}

	return channel
}

//func getTargetOIDDescription(oid string, oids []OID) (string, error) {
func (m *TarpanManager) getTargetOIDDescription(oid string) (string, error) {
	for _, o := range m.target.OIDs {
		if o.OID == oid {
			return o.Description, nil
		}
	}

	return "", errors.New("oid not found")
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

func (m *TarpanManager) makeTarpanResult(sp *gosnmp.SnmpPacket) TarpanResult {
	now := time.Now()
	var varbinds []VarBind
	for _, val := range sp.Variables {
		//n := strings.TrimLeft(val.Name, ".")
		desc, _ := m.getTargetOIDDescription(val.Name)
		asn1ber_name, _ := getAsn1BERName(val.Type)
		//value := formatSnmpValue(val.Type, val.Value.(string))
		v := VarBind{
			Description: desc,
			OID:         val.Name,
			Type:        asn1ber_name,
			Value:       val.Value,
			Time:        now.Unix(),
		}
		varbinds = append(varbinds, v)
	}
	version := getSnmpVersionString(m.snmp.Version)
	tarpanResult := TarpanResult{
		Name:      m.target.Name,
		Address:   m.target.Address,
		Port:      m.snmp.Port,
		Version:   version,
		Community: m.snmp.Community,
		VarBinds:  varbinds,
	}

	return tarpanResult
}

func makeTarpanResults(c *Channels) []*TarpanResult {
	result_length := len(c.results)
	tarpanResults := make(TarpanResults, result_length)
	for i := 0; i < result_length; i++ {
		tarpanResult := <-c.results
		tarpanResults[i] = &tarpanResult
	}

	return removeNilResult(tarpanResults)
}

func makeManagers(ds *DataSet) []*TarpanManager {
	var manager *TarpanManager
	var managers TarpanManagers
	var oids []string

	// Set Target
	for t_idx := range ds.Targets {
		// TODO: split oid slice depending on PDU size
		oids = []string{}
		for o_idx := range ds.Targets[t_idx].OIDs {
			oids = append(oids, ds.Targets[t_idx].OIDs[o_idx].OID)
		}
		manager = &TarpanManager{
			snmp: &gosnmp.GoSNMP{},
		}
		err := manager.setTarget(ds, t_idx)
		if err != nil {
			log.Println("set target error")
		}
		managers = append(managers, manager)
	}

	return managers
}

func Collect(dataset *DataSet) []*TarpanResult {
	var waitGroup sync.WaitGroup
	var oids []string
	var tarpanResults []*TarpanResult

	managers := makeManagers(dataset)
	channels := makeChannel(len(dataset.Targets))
	for t_idx := range dataset.Targets {

		// TODO: split oid slice depending on PDU size
		oids = []string{}
		for o_idx := range dataset.Targets[t_idx].OIDs {
			oids = append(oids, dataset.Targets[t_idx].OIDs[o_idx].OID)
		}

		waitGroup.Add(1)
		go func(m *TarpanManager, o []string, c *Channels) {
			c.semaphoe <- 0
			defer func() {
				waitGroup.Done()
				<-c.semaphoe
			}()
			result, err := m.Get(o)
			if err != nil {
				log.Print(err)
				return
			}
			c.results <- result
		}(managers[t_idx], oids, channels)
	}
	waitGroup.Wait()
	tarpanResults = makeTarpanResults(channels)

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
