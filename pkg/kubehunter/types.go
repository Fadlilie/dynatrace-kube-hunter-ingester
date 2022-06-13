package kubehunter

// type Node struct {
// 	Location string
// 	Type     string `json:"type"` // vulnerability ID
// }

// type Service struct {
// 	Location string
// 	Service  string `json:"service"` // vulnerability ID
// }

type Vulnerability struct {
	Location      string `json:"location"`
	Vid           string `json:"vid"`      // vulnerability ID
	Category      string `json:"category"` // MITRE category
	Severity      string `json:"severity"`
	Vulnerability string `json:"vulnerability"`
	Description   string `json:"description"`
	Evidence      string `json:"evidence"`
	AvdReference  string `json:"avd_reference"`
	Hunter        string `json:"hunter"`
}

type Report struct {
	// Nodes           []Node          `json:"nodes"`
	// Services        []Service       `json:"services"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
