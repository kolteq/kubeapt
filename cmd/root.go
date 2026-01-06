// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/kolteq/kubeapt/internal/cmd"
	"github.com/kolteq/kubeapt/internal/kubernetes"
)

var (
	rootCmd = &cobra.Command{
		Use:   "kubeapt",
		Short: "Kubernetes Admission Policy Toolkit",
		Long:  `CLI toolkit for validating Kubernetes admission policies, Pod Security Admission labels, and cluster webhook safeguards.`,
	}
	logLevel       string
	kubeconfigPath string
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(func() {
		kubernetes.SetKubeconfig(kubeconfigPath)
	})
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Set logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file")
	rootCmd.AddCommand(cmd.ValidateCmd(getLogLevel))
	rootCmd.AddCommand(cmd.ScanCmd())
	rootCmd.AddCommand(cmd.PoliciesCmd())
}

func getLogLevel() string {
	return logLevel
}
