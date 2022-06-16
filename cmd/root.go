/*
Copyright © 2022 Martin Nirtl <martin.nirtl@dynatrace.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"log"
	"os"

	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var rootCmd = &cobra.Command{
	Use:   "dynatrace-kube-hunter-ingester",
	Short: "Send kube-hunter reports received over http to Dynatrace",
	Long: `Send a kube-hunter report received over http to Dynatrace. 
After parsing the kube-hunter report and transforming it to a Dynatrace Event v2, the event will be ingested via Dynatrace API.`,
	Run: func(cmd *cobra.Command, args []string) {
		server.StartServer()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func initLogger() {
	var logger *zap.Logger
	var err error
	if viper.GetBool("dev-mode") {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		log.Fatalln(err.Error())
	}

	zap.ReplaceGlobals(logger)
}

func init() {
	cobra.OnInitialize(initLogger)

	rootCmd.PersistentFlags().Bool("dev-mode", false, "Enable development mode")
	rootCmd.PersistentFlags().MarkHidden("dev-mode")

	rootCmd.Flags().Uint16P("port", "p", 8080, "Listening port")
	rootCmd.Flags().String("api-url", "", "Dynatrace API URL e.g. https://xxxxxxxx.live.dynatrace.com/api")
	rootCmd.Flags().String("token", "", "Dynatrace API token with event ingest permission assigned")
	rootCmd.Flags().String("cluster-name", "", "Set cluster name (same as in Dynatrace)")
	rootCmd.Flags().String("prefix", "[Kube Hunter]", "Prefix for ingested events/logs (default: [Kube Hunter])")
	rootCmd.Flags().String("ingest-as", "logs", "Ingest report as events, logs or both (default: logs)")
	// rootCmd.Flags().String("alert-from-severity", "", "Create events that trigger a custom alert (default: high)")
	rootCmd.Flags().Bool("dry-run", false, "Run a dry-run and get events/logs printed only")
	// rootCmd.Flags().Bool("add-k8s", false, "Add Kubernetes entity information to properties of events/logs")
	rootCmd.Flags().Bool("no-exit", false, "Keep server running")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(rootCmd.Flags())
}
