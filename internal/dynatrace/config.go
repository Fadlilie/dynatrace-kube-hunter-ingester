package dynatrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type LogCustomAttributeConfig struct {
	Summary       string                        `json:"summary"`
	Scope         string                        `json:"scope"`
	SchemaID      string                        `json:"schemaId"`
	SchemaVersion string                        `json:"schemaVersion,omitempty"`
	Value         LogCustomAttributeConfigValue `json:"value"`
}

type LogCustomAttributeConfigValue struct {
	Key                 string `json:"key"`
	AggregableAttribute bool   `json:"aggregableAttribute"`
}

type LogEventConfig struct {
	Summary       string              `json:"summary"`
	Scope         string              `json:"scope"`
	SchemaID      string              `json:"schemaId"`
	SchemaVersion string              `json:"schemaVersion,omitempty"`
	Value         LogEventConfigValue `json:"value"`
}
type LogEventConfigValue struct {
	Enabled       bool                        `json:"enabled"`
	Summary       string                      `json:"summary"`
	Query         string                      `json:"query"`
	EventTemplate LogEventConfigEventTemplate `json:"eventTemplate"`
}
type LogEventConfigEventTemplate struct {
	Title       string                   `json:"title"`
	Description string                   `json:"description"`
	EventType   string                   `json:"eventType"`
	DavisMerge  bool                     `json:"davisMerge"`
	Metadata    []LogEventConfigMetadata `json:"metadata,omitempty"`
}

type LogEventConfigMetadata struct {
	MetadataKey   string `json:"metadataKey"`
	MetadataValue string `json:"metadataValue"`
}

type AlertingProfileConfig struct {
	Summary       string                     `json:"summary"`
	Scope         string                     `json:"scope"`
	SchemaID      string                     `json:"schemaId"`
	SchemaVersion string                     `json:"schemaVersion,omitempty"`
	Value         AlertingProfileConfigValue `json:"value"`
}
type AlertingProfileConfigValue struct {
	Name          string                              `json:"name"`
	SeverityRules []AlertingProfileConfigSeverityRule `json:"severityRules"`
	EventFilters  []AlertingProfileConfigEventFilter  `json:"eventFilters"`
}
type AlertingProfileConfigSeverityRule struct {
	SeverityLevel        string `json:"severityLevel"`
	DelayInMinutes       int    `json:"delayInMinutes"`
	TagFilterIncludeMode string `json:"tagFilterIncludeMode"`
}
type AlertingProfileConfigEventFilter struct {
	Type         string                            `json:"type"`
	CustomFilter AlertingProfileConfigCustomFilter `json:"customFilter"`
}
type AlertingProfileConfigCustomFilter struct {
	TitleFilter AlertingProfileConfigTitleFilter `json:"titleFilter"`
}
type AlertingProfileConfigTitleFilter struct {
	Operator      string `json:"operator"`
	Value         string `json:"value"`
	Negate        bool   `json:"negate"`
	Enabled       bool   `json:"enabled"`
	CaseSensitive bool   `json:"caseSensitive"`
}

type MetricsMetadataConfig struct {
	Summary       string                     `json:"summary,omitempty"`
	Scope         string                     `json:"scope"`
	SchemaID      string                     `json:"schemaId"`
	SchemaVersion string                     `json:"schemaVersion,omitempty"`
	Value         MetricsMetadataConfigValue `json:"value"`
}
type MetricsMetadataConfigValue struct {
	DisplayName      string                                `json:"displayName"`
	Description      string                                `json:"description"`
	Unit             string                                `json:"unit"`
	Tags             []string                              `json:"tags"`
	MetricProperties MetricsMetadataConfigMetricProperties `json:"metricProperties"`
	Dimensions       []MetricsMetadataConfigDimension      `json:"dimensions"`
}
type MetricsMetadataConfigMetricProperties struct {
	MaxValue          int    `json:"maxValue,omitempty"`
	MinValue          int    `json:"minValue"`
	RootCauseRelevant bool   `json:"rootCauseRelevant"`
	ImpactRelevant    bool   `json:"impactRelevant"`
	ValueType         string `json:"valueType"`
	Latency           int    `json:"latency,omitempty"`
}
type MetricsMetadataConfigDimension struct {
	Key         string `json:"key"`
	DisplayName string `json:"displayName"`
}

type LogMetricConfig struct {
	Summary       string               `json:"summary"`
	Scope         string               `json:"scope"`
	SchemaID      string               `json:"schemaId"`
	SchemaVersion string               `json:"schemaVersion,omitempty"`
	Value         LogMetricConfigValue `json:"value"`
}
type LogMetricConfigValue struct {
	Enabled    bool     `json:"enabled"`
	Key        string   `json:"key"`
	Query      string   `json:"query"`
	Measure    string   `json:"measure"`
	Dimensions []string `json:"dimensions"`
}

type ApiResponse struct {
	Code  int `json:"code"`
	Error struct {
		Code                 int    `json:"code"`
		Message              string `json:"message"`
		ConstraintViolations []struct {
			Path              string      `json:"path"`
			Message           string      `json:"message"`
			ParameterLocation string      `json:"parameterLocation"`
			Location          interface{} `json:"location"`
		} `json:"constraintViolations"`
	} `json:"error"`
	InvalidValue struct {
		Key                 string `json:"key"`
		AggregableAttribute bool   `json:"aggregableAttribute"`
	} `json:"invalidValue"`
}

func appendLogCustomAttributeConfig(settings *[]interface{}) {
	attributes := []string{"avd_reference", "mitre_category", "description", "evidence", "hunter_type", "location", "severity", "vulnerability", "vulnerability_id"}

	for _, a := range attributes {
		attributeConfig := LogCustomAttributeConfig{
			Summary:  "[kube-hunter] kube-hunter." + a,
			Scope:    "environment",
			SchemaID: "builtin:logmonitoring.log-custom-attributes",
			Value: LogCustomAttributeConfigValue{
				Key:                 "kube-hunter." + a,
				AggregableAttribute: true,
			},
		}

		*settings = append(*settings, attributeConfig)
	}
}

func appendLogEventConfig(settings *[]interface{}) {
	sugar := zap.L().Sugar()

	severity := []string{"low", "medium", "high"}
	alertSeverity := viper.GetString("alert-severity")

	if !strings.Contains(strings.Join(severity, ""), alertSeverity) && alertSeverity != "none" {
		sugar.Infof("Illegal option for --alert-severity: %s - fallback is 'high'", alertSeverity)

		alertSeverity = "high"
	}

	eventType := "INFO"
	for _, s := range severity {
		summary := fmt.Sprintf("[kube-hunter] Reported vulnerability with %s severity", s)

		if s == alertSeverity {
			eventType = "CUSTOM_ALERT"
		}

		logEventConfig := LogEventConfig{
			Summary:       summary,
			Scope:         "environment",
			SchemaID:      "builtin:logmonitoring.log-events",
			SchemaVersion: "3.1.2",
			Value: LogEventConfigValue{
				Enabled: true,
				Summary: summary,
				Query:   fmt.Sprintf("log.source=\"kube-hunter\" AND kube-hunter.severity=\"%s\"", s),
				EventTemplate: LogEventConfigEventTemplate{
					Title:       summary,
					Description: "{kube-hunter.vulnerability}:\n{kube-hunter.description}\n\nSee properties for further details and links",
					EventType:   eventType,
					// TODO prevent event from timing out
					Metadata: []LogEventConfigMetadata{
						{
							MetadataKey:   "dt.kubernetes.cluster.id",
							MetadataValue: "{dt.kubernetes.cluster.id}",
						},
						{
							MetadataKey:   "kube-hunter.avd_reference",
							MetadataValue: "{kube-hunter.avd_reference}",
						},
						{
							MetadataKey:   "kube-hunter.mitre_category",
							MetadataValue: "{kube-hunter.mitre_category}",
						},
						{
							MetadataKey:   "kube-hunter.description",
							MetadataValue: "{kube-hunter.description}",
						},
						{
							MetadataKey:   "kube-hunter.evidence",
							MetadataValue: "{kube-hunter.evidence}",
						},
						{
							MetadataKey:   "kube-hunter.hunter_type",
							MetadataValue: "{kube-hunter.hunter_type}",
						},
						{
							MetadataKey:   "kube-hunter.location",
							MetadataValue: "{kube-hunter.location}",
						},
						{
							MetadataKey:   "kube-hunter.severity",
							MetadataValue: "{kube-hunter.severity}",
						},
						{
							MetadataKey:   "kube-hunter.vulnerability",
							MetadataValue: "{kube-hunter.vulnerability}",
						},
						{
							MetadataKey:   "kube-hunter.vulnerability_id",
							MetadataValue: "{kube-hunter.vulnerability_id}",
						},
					},
				},
			},
		}

		*settings = append(*settings, logEventConfig)
	}
}

func appendAlertingProfileConfig(settings *[]interface{}) {
	// TODO check for existing alerting profile

	alertingProfileConfig := AlertingProfileConfig{
		Summary:  "[kube-hunter] Report alerts",
		Scope:    "environment",
		SchemaID: "builtin:alerting.profile",
		Value: AlertingProfileConfigValue{
			Name: "[kube-hunter] Report alerts",
			SeverityRules: []AlertingProfileConfigSeverityRule{
				{
					SeverityLevel:        "CUSTOM_ALERT",
					DelayInMinutes:       0,
					TagFilterIncludeMode: "NONE",
				},
			},
			EventFilters: []AlertingProfileConfigEventFilter{
				{
					Type: "CUSTOM",
					CustomFilter: AlertingProfileConfigCustomFilter{
						TitleFilter: AlertingProfileConfigTitleFilter{
							Operator:      "BEGINS_WITH",
							Value:         "[kube-hunter]",
							Negate:        false,
							Enabled:       true,
							CaseSensitive: false,
						},
					},
				},
			},
		},
	}

	*settings = append(*settings, alertingProfileConfig)
}

// {
// 	"scope": "metric-business.shop.revenue",
// 	"schemaId": "builtin:metric.metadata",
// 	"value": {
// 			"displayName": "Total revenue",
// 			"description": "Total store revenue by region, city, and store",
// 			"unit": "Unspecified",
// 			"tags": [
// 					"KPI",
// 					"Business"
// 			],
// 			"metricProperties": {
// 					"maxValue": 1000000,
// 					"minValue": 0,
// 					"rootCauseRelevant": false,
// 					"impactRelevant": true,
// 					"valueType": "score",
// 					"latency": 1
// 			},
// 			"dimensions": [
// 					{
// 							"key": "city",
// 							"displayName": "City name"
// 					}
// 			]
// 	}
// }
// {
//   "summary": "",
//   "scope": "metric-app_signups_unconfirmed_total.count",
//   "schemaId": "builtin:metric.metadata",
//   "schemaVersion": "4.23",
//   "value": {
//     "displayName": "User signups unconfirmed",
//     "description": "Total amount of unconfirmed user signups",
//     "unit": "Count",
//     "dimensions": [
//       {
//         "key": "trace_id",
//         "displayName": "Trace ID"
//       }
//     ],
//     "tags": []
//   }
// }
func appendMetricsMetadataConfig(settings *[]interface{}) {
	metricsMetadataConfig := MetricsMetadataConfig{
		// Summary:       "[kube-hunter] log.kube-hunter.vulnerabilities",
		Scope:         "log.kube-hunter.vulnerabilities",
		SchemaID:      "builtin:metric.metadata",
		SchemaVersion: "4.23",
		Value: MetricsMetadataConfigValue{
			DisplayName: "",
			Description: "",
			Unit:        "[1]",
			Tags:        []string{"kube-hunter"},
			MetricProperties: MetricsMetadataConfigMetricProperties{
				MinValue:          0,
				RootCauseRelevant: false,
				ImpactRelevant:    false,
				ValueType:         "count",
			},
			Dimensions: []MetricsMetadataConfigDimension{
				{
					Key:         "kube-hunter.location",
					DisplayName: "Location",
				},
				{
					Key:         "kube-hunter.mitre_category",
					DisplayName: "MITRE Category",
				},
				{
					Key:         "kube-hunter.severity",
					DisplayName: "Severity",
				},
			},
		},
	}

	*settings = append(*settings, metricsMetadataConfig)
}

func appendLogMetricsConfig(settings *[]interface{}) {
	logMetricConfig := LogMetricConfig{
		Summary:  "[kube-hunter] log.kube-hunter.vulnerabilities",
		Scope:    "environment",
		SchemaID: "builtin:logmonitoring.schemaless-log-metric",
		// SchemaVersion: "8.0.41",
		Value: LogMetricConfigValue{
			Enabled:    true,
			Key:        "log.kube-hunter.vulnerabilities",
			Query:      "log.source=\"kube-hunter\"",
			Measure:    "OCCURRENCE",
			Dimensions: []string{"kube-hunter.location", "kube-hunter.mitre_category", "kube-hunter.severity"},
		},
	}

	*settings = append(*settings, logMetricConfig)
}

func applyConfig(url string, token string, settings *[]interface{}) {
	sugar := zap.L().Sugar()

	byteArray, err := json.Marshal(*settings)
	if err != nil {
		sugar.Error("Failed to marshal configuration: ", err.Error())

		return
	}
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(byteArray))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Api-Token "+token)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		sugar.Error("Failed to apply configuration: ", err.Error())
	}

	if res.StatusCode >= 400 {
		sugar.Info("Failed to apply configuration: ", res.Status)
	}

	apiResponse := make([]ApiResponse, 0)
	json.NewDecoder(res.Body).Decode(&apiResponse)
	if err != nil {
		sugar.Error(err.Error())

		return
	}

	for _, entry := range apiResponse {
		if entry.Code >= 400 {
			sugar.Infow(entry.Error.ConstraintViolations[0].Message,
				"value", entry.InvalidValue.Key,
			)
		}
	}

	stringified, _ := json.MarshalIndent(apiResponse, "  ", "  ")
	sugar.Debugf("Response body:\n  %s", stringified)
}

func ApplyConfiguration() {
	sugar := zap.L().Sugar()

	settings := make([]interface{}, 0, 10)

	if !viper.GetBool("skip-log-events") {
		appendLogCustomAttributeConfig(&settings)
		appendLogEventConfig(&settings)
	}

	if !viper.GetBool("skip-alerting-profile") {
		appendAlertingProfileConfig(&settings)
	}

	if !viper.GetBool("skip-metrics") {
		// appendMetricsMetadataConfig(&settings) // TODO cannot be applied since no metric data
		appendLogMetricsConfig(&settings)
	}

	if viper.GetBool("dry-run") {
		json, err := json.MarshalIndent(settings, "  ", "  ")
		if err != nil {
			sugar.Error("Failed to marshal configuration: ", err.Error())

			return
		}

		sugar.Infof("Dry run output for configuration:\n  %s", string(json))

		return
	}

	apiBaseUrl := viper.GetString("api-url")
	token := viper.GetString("token")

	applyConfig(apiBaseUrl+"/v2/settings/objects", token, &settings)
}
