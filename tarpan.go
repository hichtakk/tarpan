package tarpan

import (
	"errors"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	g "github.com/soniah/gosnmp"
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
	Global  Global   `json:"global"`
	Targets []Target `json:"targets"`
}

type Global struct {
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
	setTarget(ds *DataSet, target_index int)
	Get(oids []string)
	setParams(p *RequestParams)
	getTargetOIDDescription(oid string)
	makeTarpanResult(sp *g.SnmpPacket)
	Run()
}

type TarpanManager struct {
	target *Target
	snmp   *g.GoSNMP
}

type TarpanManagers []*TarpanManager

type RequestParams struct {
	managerIndex int
	address      string
	community    string
	version      string
	port         uint16
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
		log.Error(param_err)
		errors.New(param_err.Error())
	}
	m.setParams(params)
	m.target = &ds.Targets[target_index]

	return nil
}

func (m *TarpanManager) Get(oids []string) (TarpanResult, error) {
	connection_err := m.snmp.Connect()
	defer m.snmp.Conn.Close()
	if connection_err != nil {
		log.Error("Connection error: %")
		return TarpanResult{}, errors.New(connection_err.Error())
	}
	snmpPacket, request_err := m.snmp.Get(oids)
	if request_err != nil {
		return TarpanResult{}, errors.New(request_err.Error())
	}
	tarpanResult := m.makeTarpanResult(snmpPacket)

	return tarpanResult, nil
}

func (m *TarpanManager) setParams(p *RequestParams) {
	if p.address != "" {
		m.snmp.Target = p.address
	}
	if p.port != 0 {
		m.snmp.Port = p.port
	} else {
		m.snmp.Port = uint16(PORT)
	}
	if p.community != "" {
		m.snmp.Community = p.community
	} else {
		m.snmp.Community = COMMUNITY
	}
	if p.version != "" {
		if p.version == "2c" {
			m.snmp.Version = g.Version2c
		}
	} else {
		m.snmp.Version = g.Version2c
	}
	if p.timeout != 0 {
		m.snmp.Timeout = time.Duration(p.timeout) * time.Second
	} else {
		m.snmp.Timeout = time.Duration(TIMEOUT) * time.Second
	}
	if p.retry != 0 {
		m.snmp.Retries = int(p.retry)
	} else {
		m.snmp.Retries = RETRY
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
		community = ds.Global.Community
	}
	version := ds.Targets[idx].Version
	if version == "" {
		version = ds.Global.Version
	}
	port := ds.Targets[idx].Port
	if port == 0 {
		port = ds.Global.Port
	}

	requestParams := &RequestParams{
		managerIndex: idx,
		address:      address,
		community:    community,
		version:      version,
		port:         port,
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

func (m *TarpanManager) makeTarpanResult(sp *g.SnmpPacket) TarpanResult {
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

	// Set Target
	for t_idx := range ds.Targets {
		manager = &TarpanManager{
			snmp: &g.GoSNMP{},
		}
		err := manager.setTarget(ds, t_idx)
		if err != nil {
			log.Error("set target error")
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
				log.Error(err)
				return
			}
			c.results <- result
		}(managers[t_idx], oids, channels)
	}
	waitGroup.Wait()
	tarpanResults = makeTarpanResults(channels)

	return tarpanResults
}

func Run(target string, output_type string, debug bool) (int, error) {
	var err error

	// setup logger
	log.SetOutput(os.Stderr)
	if debug == true {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	// load targets
	dataset, loadErr := loadConfig(target)
	if loadErr != nil {
		log.Error(loadErr)
		return ExitCodeConfError, loadErr
	}

	// collect data
	tr := Collect(dataset)

	// output
	Write(output_type, tr)

	return ExitCodeOK, err
}
