package tarpan

import (
	"encoding/json"
	"fmt"

	g "github.com/soniah/gosnmp"
)

func Write(outtype string, tr []*TarpanResult) {
	switch outtype {
	case "json":
		defaultWriter(tr)
	case "sensu":
		sensuWriter(tr)
	default:
		//defaultWriter(tr)
		jsonWriter(tr)
	}
}

func defaultWriter(tr []*TarpanResult) {
	for _, val := range tr {
		fmt.Println(val.Name, val.Address)
		for _, v := range val.VarBinds {
			ber, _ := getAsn1BERName(v.Type)
			switch v.Type {
			case g.Counter32, g.Gauge32, g.Counter64:
				fmt.Printf("%20s\t%s\t%s\t%d\t%d\n", v.Description, v.OID, ber, v.Value, v.Time)
			case g.NoSuchObject, g.NoSuchInstance:
				fmt.Printf("%20s\t%s\t%s\t-\t%d\n", v.Description, v.OID, ber, v.Time)
			default:
				fmt.Printf("%20s\t%s\t%s\t%s\t%d\n", v.Description, v.OID, ber, v.Value, v.Time)
			}
		}
		fmt.Println()
	}
}

func sensuWriter(tr []*TarpanResult) {
	for _, val := range tr {
		for _, v := range val.VarBinds {
			switch v.Type {
			case g.Counter32, g.Gauge32, g.Counter64:
				fmt.Printf("%s.%s %d %d\n", val.Name, v.Description, v.Value, v.Time)
			case g.NoSuchObject, g.NoSuchInstance:
			default:
				fmt.Printf("%s.%s %s %d\n", val.Name, v.Description, v.Value, v.Time)
			}
		}
	}
}

func jsonWriter(tr []*TarpanResult) {
	b, err := json.Marshal(tr)
	if err != nil {
		fmt.Println("json err:", err)
	}
	fmt.Println(string(b))
}
