package kubehunter

import (
	"encoding/json"
	"fmt"
)

func ParseReport(data []byte) (*Report, error) {
	report := &Report{}
	err := json.Unmarshal(data, report)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report: %s", err.Error())
	}

	return report, nil
}
