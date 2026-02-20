// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import (
	"os"
	"strings"
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfigPath  string
	activeNamespace = "default"
	warningsOnce    sync.Once
)

func SetKubeconfig(path string) {
	if path == "" {
		kubeconfigPath = ""
		return
	}
	kubeconfigPath = path
}

func ActiveNamespace() string {
	return activeNamespace
}

func Config() (*rest.Config, error) {
	warningsOnce.Do(func() {
		rest.SetDefaultWarningHandler(rest.NoWarnings{})
	})

	var config *rest.Config
	var err error

	if kubeconfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, err
		}
		activeNamespace = detectNamespace(kubeconfigPath)
		config.QPS = 50
		config.Burst = 100
		return config, nil
	}

	config, err = rest.InClusterConfig()
	if err != nil {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		kubeconfig := loadingRules.GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		kubeconfigPath = kubeconfig
		activeNamespace = detectNamespace(kubeconfig)
		config.QPS = 50
		config.Burst = 100
		return config, nil
	}
	activeNamespace = detectInClusterNamespace()
	config.QPS = 50
	config.Burst = 100
	return config, nil
}

func Init() (*kubernetes.Clientset, error) {
	config, err := Config()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func detectNamespace(path string) string {
	if path == "" {
		return "default"
	}
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	configOverrides := &clientcmd.ConfigOverrides{}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	ns, _, err := clientConfig.Namespace()
	if err == nil && ns != "" {
		return ns
	}
	return "default"
}

func detectInClusterNamespace() string {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		if ns := strings.TrimSpace(string(data)); ns != "" {
			return ns
		}
	}
	if kubeconfigPath != "" {
		return detectNamespace(kubeconfigPath)
	}
	return "default"
}

func ClusterName() string {
	if kubeconfigPath != "" {
		return detectClusterName(kubeconfigPath)
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeconfig := loadingRules.GetDefaultFilename()
	return detectClusterName(kubeconfig)
}

func detectClusterName(path string) string {
	if path == "" {
		return ""
	}
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	configOverrides := &clientcmd.ConfigOverrides{}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return ""
	}
	if rawConfig.CurrentContext == "" {
		return ""
	}
	ctx, ok := rawConfig.Contexts[rawConfig.CurrentContext]
	if !ok || ctx == nil {
		return ""
	}
	return ctx.Cluster
}
