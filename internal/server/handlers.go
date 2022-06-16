package server

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"

	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/internal/dynatrace"
	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/pkg/kubehunter"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func processReport(body []byte, noExit bool) {
	if !noExit {
		defer func() {
			StopServer()
		}()
	}

	sugar := zap.L().Sugar()

	// unquote is necessary as JSON received from kube-hunter is not proper JSON
	unqotedBodyString, err := strconv.Unquote(string(body))
	if err != nil {
		sugar.Errorw("Failed to unqote body string",
			"body", string(body),
			"error", err.Error(),
		)

		return
	}

	report, err := kubehunter.ParseReport([]byte(unqotedBodyString))
	if err != nil {
		sugar.Errorw("Failed to parse report",
			"body", string(body),
			"error", err.Error(),
		)

		return
	}

	apiBaseUrl := viper.GetString("api-url")
	token := viper.GetString("token")

	switch viper.GetString("ingest-as") {
	case "both":
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			dynatrace.IngestReportAsEventsV2(apiBaseUrl, token, report)
			wg.Done()
		}()
		go func() {
			dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
			wg.Done()
		}()

		wg.Wait()
	case "events":
		dynatrace.IngestReportAsEventsV2(apiBaseUrl, token, report)
	case "logs":
		dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
	default:
		sugar.Warnf("Invalid argument '%s' for --ingest-as, fallback is 'logs'")
		dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
	}

	sugar.Debug("Finished report processing")
}

func report(w http.ResponseWriter, r *http.Request) {
	noExit := viper.GetBool("no-exit")

	sugar := zap.L().Sugar()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		if !noExit {
			sugar.Fatal(err.Error())
		}

		sugar.Error(err.Error())
	}

	go processReport(body, noExit)
}
