package dynatrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/pkg/kubehunter"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Log struct {
	Content  string `json:"content"`
	Source   string `json:"log.source"`
	Severity string `json:"severity"`
	// TODO use dt.* and kubehunter.*
	KubeHunterFields map[string]string `json:"kube-hunter"`
}

func createLogsFromKubeHunterReport(report *kubehunter.Report) []*Log {
	logs := make([]*Log, 0, 20)

	// for _, n := range report.Nodes {
	// 	props := make(map[string]string)

	// 	props["Location"] = n.Location
	// 	props["Type"] = n.Type

	// 	logs = append(logs, &Log{
	// 		Severity:         "info",
	// 		Source:           "kube-hunter",
	// 		Content:          "TBD",
	// 		KubeHunterFields: props,
	// 	})
	// }

	// for _, s := range report.Services {
	// 	props := make(map[string]string)

	// 	props["Location"] = s.Location
	// 	props["Service"] = s.Service

	// 	logs = append(logs, &Log{
	// 		Severity:         "info",
	// 		Source:           "kube-hunter",
	// 		Content:          "TBD",
	// 		KubeHunterFields: props,
	// 	})
	// }

	for _, v := range report.Vulnerabilities {
		props := make(map[string]string)

		props["avdReference"] = v.AvdReference
		props["category"] = v.Category
		props["description"] = v.Description
		props["evidence"] = v.Evidence
		props["kubeHunterType"] = v.Hunter
		props["location"] = v.Location
		props["severity"] = v.Severity
		props["vulnerabilityId"] = v.Vid
		props["vulnerability"] = v.Vulnerability

		logs = append(logs, &Log{
			Severity:         "info",
			Source:           "kube-hunter",
			Content:          fmt.Sprintf("%s %s: %s", viper.GetString("prefix"), v.Vulnerability, v.Description),
			KubeHunterFields: props,
		})
	}

	return logs
}

func ingestLogs(url string, token string, logs []*Log) {
	sugar := zap.L().Sugar()

	json, _ := json.Marshal(logs)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(json))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Api-Token "+token)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		// TODO add counter metrics for failed and ingested events
		sugar.Error("Failed to ingest logs: ", err.Error())
	}

	sugar.Debug("Response status: ", res.Status)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		sugar.Debug("Failed to read body: ", err.Error())
	}
	sugar.Debug("Response body: ", string(body))
}

func IngestReportAsLogs(apiBaseUrl string, token string, report *kubehunter.Report) {
	sugar := zap.L().Sugar()

	logs := createLogsFromKubeHunterReport(report)
	sugar.Infof("Processing %d logs", len(logs))

	if viper.GetBool("dry-run") {
		json, err := json.MarshalIndent(logs, "  ", "  ")
		if err != nil {
			sugar.Error("Failed to marshal logs: ", err.Error())

			return
		}

		sugar.Infow("Dry run output for logs",
			"logs", string(json),
		)

		return
	}

	ingestLogs(apiBaseUrl+"/v2/logs/ingest", token, logs)
}
