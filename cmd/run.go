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
	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Ingest logs generated from kube-hunter reports into Dynatrace",
	Long: `Ingest logs generated from a kube-hunter report into Dynatrace. 
The command will run a server to receive the report over HTTP. When the report is received, it will be parsed to logs which get ingested via the Dynatrace Log Ingest API.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// TODO check if this approach is a recommended/best practise
		viper.BindPFlags(cmd.Flags())
	},
	Run: func(cmd *cobra.Command, args []string) {
		server.StartServer()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().Uint16P("port", "p", 8080, "Listening port")
	runCmd.Flags().Bool("no-exit", false, "Keep server running")
	runCmd.Flags().String("api-url", "", "Dynatrace API URL e.g. https://xxxxxxxx.live.dynatrace.com/api")
	runCmd.Flags().String("token", "", "Dynatrace API token with 'Ingest logs' and optionally 'Ingest metrics' permissions assigned")
	runCmd.Flags().String("cluster-name", "", "Set cluster name (same as in Dynatrace)")
	// runCmd.Flags().String("prefix", "[kube-hunter]", "Prefix for ingested logs (default: [kube-hunter])")
	runCmd.Flags().String("ingest", "logs", "Ingest report as logs and/or metrics (default: logs)")
	runCmd.Flags().Bool("dry-run", false, "Run a dry-run and get events/logs printed only")
}
