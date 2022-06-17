package dynatrace

import (
	"strings"

	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/pkg/kubehunter"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Metric struct {
	key        string
	value      uint8
	dimensions map[string]string
}

func (*Metric) String() string {
	// TODO serialize Metric type to line protocoll: https://www.dynatrace.com/support/help/extend-dynatrace/extend-metrics/reference/metric-ingestion-protocol
	return "foo"
}

func createMetricsFromKubeHunterReport(report *kubehunter.Report) []*Metric {
	return nil
}

func ingestMetrics(url string, token string, metricLines []string) {}

// TODO use metrics from prometheus-go
// TODO add metric reflecting DDU consumption and ingest (Ingest* funcs could return count)
func IngestReportAsMetrics(apiBaseUrl string, token string, report *kubehunter.Report) {
	sugar := zap.L().Sugar()

	metrics := createMetricsFromKubeHunterReport(report)
	sugar.Infof("Processing %d metrics", len(metrics))

	metricLines := make([]string, 0, len(metrics))
	for _, m := range metrics {
		metricLines = append(metricLines, m.String())
	}

	if viper.GetBool("dry-run") {
		sugar.Infow("Dry run output for metrics",
			"metrics", strings.Join(metricLines, "\n"),
		)

		return
	}

	ingestMetrics(apiBaseUrl+"/v2/logs/ingest", token, metricLines)
}
