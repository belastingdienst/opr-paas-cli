/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/version"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrNoPaasConfigs is raised when there are no PaasConfigs in k8s.
	// It makes the client run without k8s info
	ErrNoPaasConfigs = errors.New("no paasconfigs defined")

	// ErrNoSecret is raised when there are no Secret Name or Namespace in the PaasConfig.
	ErrNoSecret = errors.New("no paas decrypt key secret defined")
)

var (
	// Namespace to operate in
	Namespace string

	// KubeContext to operate with
	KubeContext string

	// NamespaceExplicitlyPassed indicates if the namespace was passed manually
	NamespaceExplicitlyPassed bool

	// Config is the Kubernetes configuration used
	Config *rest.Config

	// Client is the controller-runtime client
	Client client.Client

	// ClientInterface contains the interface used i the plugin
	ClientInterface kubernetes.Interface
)

// SetupKubernetesClient creates a k8s client to be used inside the kubectl-paas utility
func SetupKubernetesClient(configFlags *genericclioptions.ConfigFlags) error {
	var err error

	kubeconfig := configFlags.ToRawKubeConfigLoader()

	Config, err = kubeconfig.ClientConfig()
	if err != nil {
		return err
	}

	err = createClient(Config)
	if err != nil {
		return err
	}

	Namespace, NamespaceExplicitlyPassed, err = kubeconfig.Namespace()
	if err != nil {
		return err
	}

	KubeContext = *configFlags.Context

	ClientInterface = kubernetes.NewForConfigOrDie(Config)

	return nil
}

func createClient(cfg *rest.Config) error {
	var err error

	scheme := runtime.NewScheme()
	for _, addToSchemeFunc := range []func(*runtime.Scheme) error{
		corev1.AddToScheme,
		v1alpha2.AddToScheme,
	} {
		if err = addToSchemeFunc(scheme); err != nil {
			return err
		}
	}

	cfg.UserAgent = fmt.Sprintf("kubectl-paas/v%s", version.Version)

	Client, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	return nil
}

// CreateAndGenerateObjects creates provided k8s object or generate manifest collectively
func CreateAndGenerateObjects(ctx context.Context, k8sObject []client.Object, option bool) error {
	for _, item := range k8sObject {
		switch option {
		case true:
			if err := Print(item, paasfile.YAMLFormat, os.Stdout); err != nil {
				return err
			}
			fmt.Println("---")
		default:
			objectType := item.GetObjectKind().GroupVersionKind().Kind
			if err := Client.Create(ctx, item); err != nil {
				return err
			}
			fmt.Printf("%v/%v created\n", objectType, item.GetName())
		}
	}

	return nil
}

// RequiresArguments will show the help message in case no argument has been provided
func RequiresArguments(nArgs int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < nArgs {
			_ = cmd.Help()
			os.Exit(0)
		}
		return nil
	}
}

// GetPaasSecret tries to get PaasConfig and retrieve the secret it points to.
// If name and/or namespace is set, it will return a secret with that name and/or namespace
// If it would return and incomplete secret, it will return an error
func GetPaasSecret(ctx context.Context, secretNsName *types.NamespacedName) (*corev1.Secret, error) {
	logrus.Debugf("secret: %v", secretNsName)
	if secretNsName == nil {
		config, err := GetConfig(ctx)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("config: %v", config)
		dk := config.Spec.DecryptKeysSecret
		if dk.Name == "" || dk.Namespace == "" {
			return nil, ErrNoSecret
		}
		secretNsName = &types.NamespacedName{
			Name:      dk.Name,
			Namespace: dk.Namespace,
		}
	}
	logrus.Debugf("secret: %v", secretNsName)
	if secretNsName.Name == "" || secretNsName.Namespace == "" {
		return nil, errors.New("could not read from k8s, and no name and/or namespace defined on commandline")
	}
	var secret = corev1.Secret{}
	if err := Client.Get(ctx, *secretNsName, &secret); err != nil {
		return &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Namespace: secretNsName.Namespace, Name: secretNsName.Name},
		}, err
	}
	secret.ManagedFields = nil
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	return &secret, nil
}

// GetConfig returns the PaasConfig or returns an error.
// If there are no PaasConfig's defined, it returns NoPaasConfigs, in which case the cli runs in a simple mode
func GetConfig(ctx context.Context) (*v1alpha2.PaasConfig, error) {
	var configs v1alpha2.PaasConfigList
	// check if the cluster exists
	if err := Client.List(ctx, &configs); err != nil {
		return nil, err
	}
	if len(configs.Items) < 1 {
		return nil, ErrNoPaasConfigs
	}
	return &configs.Items[0], nil
}
