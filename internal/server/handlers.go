package server

import (
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/internal/dynatrace"
	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/pkg/kubehunter"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func report(w http.ResponseWriter, r *http.Request) {
	sugar := zap.L().Sugar()

	if viper.Get("no-exit") == false {
		defer func() {
			StopServer()
		}()
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sugar.Fatal(err.Error())
	}

	// unquote is necessary as JSON received from kube-hunter is not clean
	unqotedBodyString, _ := strconv.Unquote(string(body))

	report, err := kubehunter.ParseReport([]byte(unqotedBodyString))
	if err != nil {
		sugar.Errorw("Failed to parse report",
			"body", string(body),
			"error", err.Error(),
		)
	}

	apiBaseUrl := viper.GetString("api-url")
	token := viper.GetString("token")

	// TODO run in goroutines
	switch viper.GetString("ingest-as") {
	case "both":
		dynatrace.IngestReportAsEventsV2(apiBaseUrl, token, report)
		dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
	case "events":
		dynatrace.IngestReportAsEventsV2(apiBaseUrl, token, report)
	case "logs":
		dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
	default:
		sugar.Warnf("Invalid argument '%s' for --ingest-as, fallback is 'logs'")
		dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
	}

}
