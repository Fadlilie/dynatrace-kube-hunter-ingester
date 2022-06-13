package kubehunter

import (
	"encoding/json"
	"fmt"
	"log"
)

func ParseReport(data []byte) (*Report, error) {
	report := &Report{}
	err := json.Unmarshal(data, report)
	if err != nil {
		log.Fatalln(err.Error())

		return nil, fmt.Errorf("")
	}

	return report, nil
}
