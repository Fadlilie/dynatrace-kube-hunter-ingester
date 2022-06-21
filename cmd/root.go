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
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	version = "development"
	commit  = "na"
	date    = "-"
	builtBy = "go build"
)

var rootCmd = &cobra.Command{
	Use:     "dynatrace-kube-hunter-ingester",
	Version: fmt.Sprintf("%s (commit %s, date: %s) built by %s", version, commit, date, builtBy),
	Short:   "Send kube-hunter reports to Dynatrace",
	Long:    `Send kube-hunter reports to Dynatrace. For more information visit https://github.com/martinnirtl/dynatrace-kube-hunter-ingester.`,
	// Run: func(cmd *cobra.Command, args []string) {},
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

	rootCmd.SetVersionTemplate("Version: {{ .Version }}\n")

	rootCmd.PersistentFlags().Bool("dev-mode", false, "Enable development mode")
	rootCmd.PersistentFlags().MarkHidden("dev-mode")

	viper.BindPFlags(rootCmd.PersistentFlags())
}
