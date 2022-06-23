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
	Content              string `json:"content"`
	Source               string `json:"log.source"`
	LogLevel             string `json:"severity"`
	ClusterNameK8s       string `json:"k8s.cluster.name,omitempty"`
	ClusterNameDynatrace string `json:"dt.kubernetes.cluster.name,omitempty"`
	AvdReference         string `json:"kube-hunter.avd_reference,omitempty"`
	Category             string `json:"kube-hunter.mitre_category,omitempty"`
	Description          string `json:"kube-hunter.description,omitempty"`
	Evidence             string `json:"kube-hunter.evidence,omitempty"`
	HunterType           string `json:"kube-hunter.hunter_type,omitempty"`
	Location             string `json:"kube-hunter.location,omitempty"`
	Severity             string `json:"kube-hunter.severity,omitempty"`
	Vulnerability        string `json:"kube-hunter.vulnerability,omitempty"`
	VulnerabilityId      string `json:"kube-hunter.vulnerability_id,omitempty"`
}

func createLogsFromKubeHunterReport(report *kubehunter.Report) []*Log {
	logs := make([]*Log, 0, 20)

	for _, v := range report.Vulnerabilities {
		var content string
		if prefix := viper.GetString("prefix"); prefix != "" {
			content = fmt.Sprintf("%s %s: %s", prefix, v.Vulnerability, v.Description)
		} else {
			content = fmt.Sprintf("%s: %s", v.Vulnerability, v.Description)
		}

		logs = append(logs, &Log{
			Content:              content,
			Source:               "kube-hunter",
			LogLevel:             "info",
			ClusterNameK8s:       viper.GetString("cluster-name"),
			ClusterNameDynatrace: viper.GetString("cluster-name"),
			AvdReference:         v.AvdReference,
			Category:             v.Category,
			Description:          v.Description,
			Evidence:             v.Evidence,
			HunterType:           v.Hunter,
			Location:             v.Location,
			Severity:             v.Severity,
			Vulnerability:        v.Vulnerability,
			VulnerabilityId:      v.Vid,
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

		sugar.Infof("Dry run output for logs:\n  %s", string(json))

		return
	}

	ingestLogs(apiBaseUrl+"/v2/logs/ingest", token, logs)
}
