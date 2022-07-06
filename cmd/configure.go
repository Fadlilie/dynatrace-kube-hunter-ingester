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
	"github.com/martinnirtl/dynatrace-kube-hunter-ingester/internal/dynatrace"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configureCmd represents the configure command
var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configures metric metadata, log events and a matching alerting profile",
	Long:  `Configures metric metadata, log events and a matching alerting profile in specified Dynatrace environment`,
	PreRun: func(cmd *cobra.Command, args []string) {
		viper.BindPFlags(cmd.Flags())
	},
	Run: func(cmd *cobra.Command, args []string) {
		dynatrace.ApplyConfiguration()
	},
}

func init() {
	rootCmd.AddCommand(configureCmd)

	configureCmd.Flags().String("api-url", "", "Dynatrace API URL e.g. https://xxxxxxxx.live.dynatrace.com/api")
	configureCmd.Flags().String("token", "", "Dynatrace API token with 'Write settings' permission assigned")
	// configureCmd.Flags().String("prefix", "[kube-hunter]", "Prefix for log events and alerting profile configurations (default: [kube-hunter])")
	configureCmd.Flags().String("alert-severity", "high", "Create log events of type CUSTOM_ALERT when matching severity (default: high)")
	configureCmd.Flags().Bool("dry-run", false, "Run a dry-run and all configuration printed")

	configureCmd.Flags().Bool("skip-log-events", false, "Skip creation of log event and log custom attribute configuration")
	configureCmd.Flags().Bool("skip-metrics", false, "Skip creation of metrics metadata configuration")
	configureCmd.Flags().Bool("skip-alerting-profile", false, "Skip creation of alerting profile configuration")

	configureCmd.MarkFlagsRequiredTogether("api-url", "token")
}
