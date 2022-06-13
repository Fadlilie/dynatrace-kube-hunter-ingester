package dynatrace

import "fmt"

func GetEntitySelector(clusterName string) string {
	if clusterName == "" {
		return ""
	}

	return fmt.Sprintf("type(KUBERNETES_CLUSTER),entityName(%s)", clusterName)
}
