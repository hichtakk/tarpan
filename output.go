package tarpan

import (
	"encoding/json"
	"fmt"
)

func Write(outtype string, tr []*TarpanResult) {
	switch outtype {
	case "json":
		jsonWriter(tr)
	case "sensu":
		sensuWriter(tr)
	default:
		defaultWriter(tr)
	}
}

func defaultWriter(tr []*TarpanResult) {
	for _, val := range tr {
		fmt.Println(val.Name, val.Address)
		for _, v := range val.VarBinds {
			fmt.Printf("%20s\t%s\t%s\t%s\t%d\n", v.Description, v.OID, v.Type, v.Value, v.Time)
		}
		fmt.Println()
	}
}

func sensuWriter(tr []*TarpanResult) {
	for _, val := range tr {
		for _, v := range val.VarBinds {
			fmt.Printf("%s.%s\t%s\t%d\n", val.Name, v.Description, v.Value, v.Time)
		}
	}
}

func jsonWriter(tr []*TarpanResult) {
	b, err := json.Marshal(tr)
	if err != nil {
		fmt.Println("json error:", err)
	}
	fmt.Println(string(b))
}
