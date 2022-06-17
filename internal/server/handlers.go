package server

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
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

	if viper.GetBool("dev-mode") {
		if json, err := json.MarshalIndent(report.Vulnerabilities, "", " "); err == nil {
			sugar.Debugw("Here goes the parsed report",
				"vulnerabilities", string(json),
			)
		}
	}

	apiBaseUrl := viper.GetString("api-url")
	token := viper.GetString("token")

	var wg sync.WaitGroup
	ingestOptions := strings.ReplaceAll(viper.GetString("ingest"), " ", "")
	for _, ingest := range strings.Split(ingestOptions, ",") {
		switch ingest {
		case "logs":
			wg.Add(1)
			go func() {
				dynatrace.IngestReportAsLogs(apiBaseUrl, token, report)
				wg.Done()
			}()

		// case "metrics":
		// 	wg.Add(1)
		// 	go func() {
		// 		dynatrace.IngestReportAsMetrics(apiBaseUrl, token, report)
		// 		wg.Done()
		// 	}()

		default:
			sugar.Warnf("Invalid option '%s' for --ingest; valid values are logs and/or metrics separated by comma")
		}
	}
	wg.Wait()

	sugar.Debug("Finished report processing")
}

func report(w http.ResponseWriter, r *http.Request) {
	noExit := viper.GetBool("no-exit")

	sugar := zap.L().Sugar()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sugar.Error(err.Error())

		if !noExit {
			StopServer()
		}

		return
	}

	go processReport(body, noExit)
}
