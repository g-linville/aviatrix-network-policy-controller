package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	aviatrixv1alpha1 "github.com/obot-platform/aviatrix-network-policy-controller/pkg/apis/networking.aviatrix.com/v1alpha1"
	obotv1 "github.com/obot-platform/aviatrix-network-policy-controller/pkg/apis/obot.obot.ai/v1"
	"github.com/obot-platform/aviatrix-network-policy-controller/pkg/translate"
	"github.com/obot-platform/nah/pkg/apply"
	nahrouter "github.com/obot-platform/nah/pkg/router"
	"github.com/obot-platform/nah/pkg/router/tester"
	metarest "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type triggerCall struct {
	gvk schema.GroupVersionKind
	key string
}

type recordingTrigger struct {
	calls []triggerCall
}

func (r *recordingTrigger) Trigger(_ context.Context, gvk schema.GroupVersionKind, key string, _ time.Duration) error {
	r.calls = append(r.calls, triggerCall{gvk: gvk, key: key})
	return nil
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := obotv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := aviatrixv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func newHandler(t *testing.T, objs ...kclient.Object) *Handler {
	t.Helper()
	scheme := newScheme(t)
	mapper := metarest.NewDefaultRESTMapper([]schema.GroupVersion{
		obotv1.SchemeGroupVersion,
		aviatrixv1alpha1.SchemeGroupVersion,
	})
	mapper.Add(obotv1.SchemeGroupVersion.WithKind("MCPNetworkPolicy"), metarest.RESTScopeNamespace)
	mapper.Add(aviatrixv1alpha1.SchemeGroupVersion.WithKind("FirewallPolicy"), metarest.RESTScopeNamespace)

	return &Handler{
		RuntimeClient:    fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(mapper).WithObjects(objs...).Build(),
		RuntimeNamespace: "obot-mcp",
	}
}

func TestHandlerCreatesManagedFirewallPolicy(t *testing.T) {
	scheme := newScheme(t)
	policy := &obotv1.MCPNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "default", UID: "uid-a"},
		Spec: obotv1.MCPNetworkPolicySpec{
			MCPServerName: "server-a",
			PodSelector:   map[string]string{"app": "server-a"},
			EgressDomains: []string{"*.google.com"},
		},
	}

	handler := newHandler(t)
	if _, err := (&tester.Harness{Scheme: scheme, ExpectedDelay: resyncInterval}).InvokeFunc(t, policy, handler.Reconcile); err != nil {
		t.Fatal(err)
	}

	var created aviatrixv1alpha1.FirewallPolicy
	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-a-fw"}, &created); err != nil {
		t.Fatal(err)
	}
	if created.Labels["obot.ai/mcp-server-name"] != "server-a" {
		t.Fatalf("unexpected labels: %v", created.Labels)
	}
	if got := created.Spec.WebGroups[0].Domains; len(got) != 1 || got[0] != "*.google.com" {
		t.Fatalf("expected wildcard domain to be preserved, got %v", got)
	}
}

func TestHandlerRejectsEmptyPodSelector(t *testing.T) {
	scheme := newScheme(t)
	policy := &obotv1.MCPNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-empty", Namespace: "default", UID: "uid-empty"},
		Spec: obotv1.MCPNetworkPolicySpec{
			MCPServerName: "server-empty",
			EgressDomains: []string{"api.example.com"},
		},
	}

	handler := newHandler(t)
	if _, err := (&tester.Harness{Scheme: scheme}).InvokeFunc(t, policy, handler.Reconcile); err == nil {
		t.Fatal("expected empty podSelector to fail reconciliation")
	}

	var created aviatrixv1alpha1.FirewallPolicy
	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-empty-fw"}, &created); err == nil {
		t.Fatal("expected no FirewallPolicy to be created for invalid source policy")
	}
}

func TestHandlerLifecycle(t *testing.T) {
	scheme := newScheme(t)
	policy := &obotv1.MCPNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "default", UID: "uid-a"},
		Spec: obotv1.MCPNetworkPolicySpec{
			MCPServerName: "server-a",
			PodSelector:   map[string]string{"app": "server-a"},
			EgressDomains: []string{"api.example.com"},
		},
	}

	handler := newHandler(t)
	if _, err := (&tester.Harness{Scheme: scheme, ExpectedDelay: resyncInterval}).InvokeFunc(t, policy, handler.Reconcile); err != nil {
		t.Fatal(err)
	}

	var created aviatrixv1alpha1.FirewallPolicy
	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-a-fw"}, &created); err != nil {
		t.Fatal(err)
	}

	policy.Spec.EgressDomains = []string{"new.example.com"}
	if _, err := (&tester.Harness{Scheme: scheme, ExpectedDelay: resyncInterval}).InvokeFunc(t, policy, handler.Reconcile); err != nil {
		t.Fatal(err)
	}
	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-a-fw"}, &created); err != nil {
		t.Fatal(err)
	}
	if created.Spec.WebGroups[0].Domains[0] != "new.example.com" {
		t.Fatalf("expected updated domain, got %v", created.Spec.WebGroups[0].Domains)
	}

	policy.Spec.MCPServerName = "server-b"
	if _, err := (&tester.Harness{Scheme: scheme, ExpectedDelay: resyncInterval}).InvokeFunc(t, policy, handler.Reconcile); err != nil {
		t.Fatal(err)
	}
	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-a-fw"}, &created); err != nil {
		t.Fatal(err)
	}
	if created.Labels["obot.ai/mcp-server-name"] != "server-b" {
		t.Fatalf("expected source server label to be updated after server rename, got %v", created.Labels)
	}

	policy.Spec.EgressDomains = nil
	policy.Spec.DenyAllEgress = false
	if _, err := (&tester.Harness{Scheme: scheme, ExpectedDelay: resyncInterval}).InvokeFunc(t, policy, handler.Reconcile); err != nil {
		t.Fatal(err)
	}
	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-a-fw"}, &created); err != nil {
		t.Fatal(err)
	}
	if got := created.Spec.WebGroups[0].Domains; len(got) != 1 || got[0] != "*" {
		t.Fatalf("expected wildcard domain fallback, got %v", got)
	}
}

func TestHandlerDeletesManagedFirewallPolicyWhenSourceRemoved(t *testing.T) {
	scheme := newScheme(t)
	labels, annotations, err := apply.GetLabelsAndAnnotations(scheme, sourceSubContext("default", "policy-a"), nil)
	if err != nil {
		t.Fatal(err)
	}

	existing := &aviatrixv1alpha1.FirewallPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "obot-policy-a-fw",
			Namespace:   "obot-mcp",
			Annotations: annotations,
			Labels:      labels,
		},
	}
	handler := newHandler(t, existing)
	req := nahrouter.Request{
		Ctx:       t.Context(),
		Name:      "policy-a",
		Namespace: "default",
	}
	if err := handler.Reconcile(req, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}

	if err := handler.RuntimeClient.Get(t.Context(), kclient.ObjectKey{Namespace: "obot-mcp", Name: "obot-policy-a-fw"}, &aviatrixv1alpha1.FirewallPolicy{}); err == nil {
		t.Fatal("expected FirewallPolicy to be deleted on source removal")
	}
}

func TestFirewallPolicyWatcherTriggersSourceOnDelete(t *testing.T) {
	scheme := newScheme(t)
	labels, annotations, err := apply.GetLabelsAndAnnotations(scheme, sourceSubContext("default", "policy-a"), nil)
	if err != nil {
		t.Fatal(err)
	}

	trigger := &recordingTrigger{}
	watcher := NewFirewallPolicyWatcher(trigger, nil, "obot-mcp")
	firewallPolicy := &aviatrixv1alpha1.FirewallPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "obot-policy-a-fw",
			Namespace:   "obot-mcp",
			Annotations: annotations,
			Labels:      labels,
		},
	}

	if err := watcher.Handle(nahrouter.Request{
		Ctx:       t.Context(),
		Object:    firewallPolicy,
		Name:      firewallPolicy.Name,
		Namespace: firewallPolicy.Namespace,
	}, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Handle(nahrouter.Request{
		Ctx:       t.Context(),
		Name:      firewallPolicy.Name,
		Namespace: firewallPolicy.Namespace,
	}, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}

	if len(trigger.calls) != 2 {
		t.Fatalf("expected update and delete to trigger source reconciles, got %d", len(trigger.calls))
	}
	for _, call := range trigger.calls {
		if call.gvk != obotv1.SchemeGroupVersion.WithKind("MCPNetworkPolicy") {
			t.Fatalf("unexpected gvk: %s", call.gvk)
		}
		if call.key != "default/policy-a" {
			t.Fatalf("unexpected source key: %s", call.key)
		}
	}
	if len(watcher.sourceByFirewall) != 0 {
		t.Fatalf("expected cached source mapping to be removed after delete, got %d entries", len(watcher.sourceByFirewall))
	}
}

func TestFirewallPolicyWatcherIgnoresUnmanagedDelete(t *testing.T) {
	trigger := &recordingTrigger{}
	watcher := NewFirewallPolicyWatcher(trigger, nil, "obot-mcp")

	if err := watcher.Handle(nahrouter.Request{
		Ctx:       t.Context(),
		Name:      "unmanaged",
		Namespace: "obot-mcp",
	}, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}
	if len(trigger.calls) != 0 {
		t.Fatalf("expected no trigger calls for unmanaged delete, got %d", len(trigger.calls))
	}
}

func TestFirewallPolicyWatcherFindsSourceForUnindexedDelete(t *testing.T) {
	trigger := &recordingTrigger{}
	watcher := NewFirewallPolicyWatcher(trigger, nil, "obot-mcp", "default")

	if err := watcher.Handle(nahrouter.Request{
		Ctx:       t.Context(),
		Name:      "obot-policy-a-fw",
		Namespace: "obot-mcp",
	}, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}

	if len(trigger.calls) != 1 {
		t.Fatalf("expected one trigger call, got %d", len(trigger.calls))
	}
	if trigger.calls[0].key != "default/policy-a" {
		t.Fatalf("unexpected source key: %s", trigger.calls[0].key)
	}
}

func TestFirewallPolicyWatcherFallsBackToSourceListForHashedName(t *testing.T) {
	scheme := newScheme(t)
	longName := "policy-" + strings.Repeat("a", 80)
	sourceClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&obotv1.MCPNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: longName, Namespace: "default"},
	}).Build()
	trigger := &recordingTrigger{}
	watcher := NewFirewallPolicyWatcher(trigger, sourceClient, "obot-mcp", "default")

	if err := watcher.Handle(nahrouter.Request{
		Ctx:       t.Context(),
		Name:      translate.NameForMCPNetworkPolicy(longName),
		Namespace: "obot-mcp",
	}, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}

	if len(trigger.calls) != 1 {
		t.Fatalf("expected one trigger call, got %d", len(trigger.calls))
	}
	if trigger.calls[0].key != "default/"+longName {
		t.Fatalf("unexpected source key: %s", trigger.calls[0].key)
	}
}

func TestFirewallPolicyWatcherScopesFallbackListToSourceNamespace(t *testing.T) {
	scheme := newScheme(t)
	longName := "policy-" + strings.Repeat("a", 80)
	sourceClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&obotv1.MCPNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: longName, Namespace: "other"},
	}).Build()
	trigger := &recordingTrigger{}
	watcher := NewFirewallPolicyWatcher(trigger, sourceClient, "obot-mcp", "default")

	if err := watcher.Handle(nahrouter.Request{
		Ctx:       t.Context(),
		Name:      translate.NameForMCPNetworkPolicy(longName),
		Namespace: "obot-mcp",
	}, &nahrouter.ResponseWrapper{}); err != nil {
		t.Fatal(err)
	}

	if len(trigger.calls) != 0 {
		t.Fatalf("expected no trigger calls outside source namespace, got %d", len(trigger.calls))
	}
}
