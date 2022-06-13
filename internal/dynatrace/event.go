package dynatrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/pkg/kubehunter"
	"github.com/spf13/viper"
)

type Event struct {
	EventType      string          `json:"eventType"`
	Title          string          `json:"title"`
	EntitySelector string          `json:"entitySelector,omitempty"`
	Properties     EventProperties `json:"properties"`
}

type EventProperties struct {
	Location      string `json:"Location,omitempty"`
	Vid           string `json:"Vulnerability ID,omitempty"` // vulnerability ID
	Category      string `json:"MITRE Category,omitempty"`   // MITRE category
	Severity      string `json:"Severity,omitempty"`
	Vulnerability string `json:"Vulnerability,omitempty"`
	Description   string `json:"Description,omitempty"`
	Evidence      string `json:"Evidence,omitempty"`
	AvdReference  string `json:"AVD Reference,omitempty"`
	Hunter        string `json:"Hunter,omitempty"`
}

func createEventsV2FromKubeHunterReport(report *kubehunter.Report) []*Event {
	entitySelector := GetEntitySelector(viper.GetString("cluster-name"))
	events := make([]*Event, 0, 20)

	// alertFromSeverity := viper.GetString("alert-from-severity")

	for _, v := range report.Vulnerabilities {
		eventType := "CUSTOM_INFO"
		if strings.ToLower(v.Severity) == "high" {
			eventType = "CUSTOM_ALERT"
		}

		events = append(events, &Event{
			EventType:      eventType,
			Title:          fmt.Sprintf("%s %s: %s", viper.GetString("prefix"), v.Vulnerability, v.Description),
			EntitySelector: entitySelector,
			Properties:     EventProperties(v),
		})
	}

	return events
}

func ingestEventV2(url string, token string, event *Event) {
	json, _ := json.Marshal(event)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(json))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Api-Token "+token)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		// TODO think through
		// TODO add counter metrics for failed and ingested events
		log.Printf("Failed to ingest event: %s", err.Error())
	}

	body, _ := ioutil.ReadAll(res.Body)

	// TODO replace log with zerolog, logrus or zap
	log.Println("Response status: ", res.Status)
	log.Println("Response body: ", string(body))
}

func IngestReportAsEventsV2(apiBaseUrl string, token string, report *kubehunter.Report) {
	events := createEventsV2FromKubeHunterReport(report)

	log.Printf("Created %d events", len(events))

	if viper.GetBool("dry-run") {
		json, _ := json.MarshalIndent(events, "  ", "  ")
		log.Printf("EVENTS:\n%s", string(json))
		return
	}

	var wg sync.WaitGroup
	for _, e := range events {
		wg.Add(1)

		go func(e *Event) {
			defer wg.Done()

			ingestEventV2(apiBaseUrl+"/v2/events/ingest", token, e)
		}(e)
	}

	wg.Wait()
}
