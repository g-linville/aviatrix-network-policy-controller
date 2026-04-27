package controller

import (
	"fmt"
	"time"

	aviatrixv1alpha1 "github.com/obot-platform/aviatrix-network-policy-controller/pkg/apis/networking.aviatrix.com/v1alpha1"
	obotv1 "github.com/obot-platform/aviatrix-network-policy-controller/pkg/apis/obot.obot.ai/v1"
	"github.com/obot-platform/aviatrix-network-policy-controller/pkg/translate"
	"github.com/obot-platform/nah/pkg/apply"
	"github.com/obot-platform/nah/pkg/router"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

var controllerLog = ctrlruntimelog.Log.WithName("controller")

// resyncInterval is how often to re-reconcile each MCPNetworkPolicy even if no
// watch event is received. Obot's internal storage API does not reliably emit
// watch events for UPDATE operations, so without this the controller would only
// pick up domain changes on a full re-list (e.g. controller restart).
const resyncInterval = 30 * time.Second

type Handler struct {
	RuntimeClient    kclient.Client
	RuntimeNamespace string
}

func (h *Handler) Reconcile(req router.Request, resp router.Response) error {
	log := controllerLog.WithValues(
		"sourceNamespace", req.Namespace,
		"sourceName", req.Name,
		"runtimeNamespace", h.RuntimeNamespace)

	app := apply.New(h.RuntimeClient).
		WithNamespace(h.RuntimeNamespace).
		WithOwnerSubContext(sourceSubContext(req.Namespace, req.Name)).
		WithPruneTypes(&aviatrixv1alpha1.FirewallPolicy{})

	if req.Object == nil {
		if err := app.Apply(req.Ctx, nil); err != nil {
			log.Error(err, "failed to prune managed FirewallPolicy")
			return err
		}
		return nil
	}

	policy, ok := req.Object.(*obotv1.MCPNetworkPolicy)
	if !ok {
		err := fmt.Errorf("unexpected object type %T", req.Object)
		log.Error(err, "failed to reconcile MCPNetworkPolicy")
		return err
	}

	desired, err := translate.ToFirewallPolicy(policy, h.RuntimeNamespace)
	if err != nil {
		log.Error(err, "failed to translate MCPNetworkPolicy")
		return err
	}

	log = log.WithValues("firewallPolicyNamespace", desired.Namespace, "firewallPolicyName", desired.Name)
	if err := app.Apply(req.Ctx, nil, desired); err != nil {
		log.Error(err, "failed to apply managed FirewallPolicy")
		return err
	}

	// Re-trigger after resyncInterval to pick up any domain changes that were
	// written to Obot's storage but whose watch event was not delivered.
	resp.RetryAfter(resyncInterval)
	return nil
}

func sourceSubContext(namespace, name string) string {
	return fmt.Sprintf("mcp-network-policy/%s/%s", namespace, name)
}
