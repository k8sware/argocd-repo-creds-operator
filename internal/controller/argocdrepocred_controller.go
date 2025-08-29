/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	argocdv1alpha1 "github.com/k8sware/argocd-repo-creds-operator/api/v1alpha1"

	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"k8s.io/apimachinery/pkg/api/errors"
)

// ArgoCDRepoCredReconciler reconciles a ArgoCDRepoCred object
type ArgoCDRepoCredReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=argocd.repocreds.io,resources=argocdrepocreds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=argocd.repocreds.io,resources=argocdrepocreds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=argocd.repocreds.io,resources=argocdrepocreds/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ArgoCDRepoCred object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *ArgoCDRepoCredReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// TODO(user): your logic here
	var repoCred argocdv1alpha1.ArgoCDRepoCred
	if err := r.Get(ctx, req.NamespacedName, &repoCred); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Validate required fields
	if repoCred.Spec.ClientID == "" || repoCred.Spec.TenantID == "" || repoCred.Spec.RepoURL == "" ||
		repoCred.Spec.ClientSecretRef.Name == "" || repoCred.Spec.ClientSecretRef.Key == "" {
		logger.Error(fmt.Errorf("missing required spec fields"), "Validation error")
		return ctrl.Result{}, nil
	}

	secretVal, err := getClientSecret(ctx, r.Client, repoCred.Spec.ClientSecretRef, req.Namespace)
	if err != nil {
		fmt.Println("Error fetching secret:", err)
	} else {
		fmt.Println("Fetched secret value:", secretVal)
	}

	accessToken, expiresIn, err := getAuthToken(repoCred.Spec.ClientID, secretVal, repoCred.Spec.TenantID)
	if err != nil {
		fmt.Println("Error fetching access token:", err)
		return ctrl.Result{}, err
	}

	fmt.Println("Fetched access token:", accessToken)

	err = createOrUpdateSecret(ctx, r.Client, accessToken, repoCred.Name, "argocd", repoCred.Spec.RepoURL, "repo-creds")
	if err != nil {
		fmt.Println("Error creating/updating secret:", err)
		return ctrl.Result{}, err
	}
	fmt.Println("Secret created/updated successfully")

	expiryTime := time.Now().Add(time.Duration(expiresIn) * time.Second)
	logger.Info("Token expiry time", "expiresAt", expiryTime.Format(time.RFC3339))

	// Update status
	repoCred.Status.TokenExpiry = metav1.NewTime(expiryTime)
	repoCred.Status.LastSynced = metav1.NewTime(time.Now())
	if err := r.Status().Update(ctx, &repoCred); err != nil {
		logger.Error(err, "Failed to update status")
	}

	// Calculate refresh delay from now until 5 minutes before expiry
	refreshDelay := time.Until(expiryTime.Add(-5 * time.Minute))
	if refreshDelay < time.Minute {
		refreshDelay = time.Minute
	}

	return ctrl.Result{RequeueAfter: refreshDelay}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ArgoCDRepoCredReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&argocdv1alpha1.ArgoCDRepoCred{}).
		Named("argocdrepocred").
		Complete(r)
}

func getClientSecret(ctx context.Context, k8sClient client.Client, secretRef argocdv1alpha1.SecretKeyReference, namespace string) (string, error) {
	var secret corev1.Secret
	err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: namespace,
	}, &secret)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretRef.Name, err)
	}

	secretData, exists := secret.Data[secretRef.Key]
	if !exists {
		return "", fmt.Errorf("key %s not found in secret %s/%s", secretRef.Key, namespace, secretRef.Name)
	}

	return string(secretData), nil
}

// TokenResponse represents the structure of the response from Azure AD
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // in seconds
}

// getAuthToken fetches an access token from Azure AD
func getAuthToken(clientID, clientSecret, tenantID string) (string, int, error) {
	endpoint := "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "499b84ac-1321-427f-aa17-267ca6975798/.default")

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("received non-200 response: %s", resp.Status)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

func createOrUpdateSecret(ctx context.Context, k8sClient client.Client, token, name, namespace, gitURL, secretType string) error {
	secretName := fmt.Sprintf("%s-token", name) // simpler name since it's scoped to the tenant
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace, // deploy to tenant namespace
			Labels: map[string]string{
				"argocd.argoproj.io/secret-type": secretType,
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"password": token,
			"url":      gitURL,
			"project":  namespace,
		},
	}

	var existingSecret corev1.Secret
	err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, &existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			return k8sClient.Create(ctx, secret)
		}
		return fmt.Errorf("failed to get secret: %w", err)
	}

	secret.ResourceVersion = existingSecret.ResourceVersion
	return k8sClient.Update(ctx, secret)
}
