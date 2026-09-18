// Package controller reconciles juggernaut.yaml and Session objects into pods.
// It owns pod creation, per-pod secrets (and, from milestone 2, network
// policies), status reporting, and the idle reaper.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/wrapper"
)

// RenderServerType converts one servers[] entry into a ServerType object.
func RenderServerType(l *config.Loaded, s *config.Server, namespace string) (*jugv1.ServerType, error) {
	c := l.Config
	wcfg := wrapper.ConfigFromServer(s, s.Wrapper.Port, s.Wrapper.ReadinessPort, "/run/juggernaut-secret/pod-token")
	wjson, err := json.Marshal(wcfg)
	if err != nil {
		return nil, err
	}
	res, err := resources(s.Resources)
	if err != nil {
		return nil, fmt.Errorf("servers[%s].resources: %w", s.Name, err)
	}
	st := &jugv1.ServerType{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.Name, Namespace: namespace,
			Labels: map[string]string{jugv1.LabelManagedBy: jugv1.ManagedByValue, jugv1.LabelConfigHash: l.Hash},
		},
		Spec: jugv1.ServerTypeSpec{
			ConfigHash:        l.Hash,
			Description:       s.Description,
			Image:             s.Image,
			Transport:         string(s.Transport),
			Command:           s.Command,
			Args:              s.Args,
			Env:               s.Env,
			WrapperPort:       int32(s.Wrapper.Port),
			ReadinessPort:     int32(s.Wrapper.ReadinessPort),
			TokenMode:         string(s.Token.Mode),
			TokenEnv:          s.Token.Env,
			TokenFile:         s.Token.File,
			TokenHeader:       s.Token.Header,
			Resources:         res,
			RuntimeClassName:  s.RuntimeClassName,
			IdleTimeout:       metav1.Duration{Duration: s.IdleTimeout.Or(c.Gateway.IdleTimeout.Duration)},
			MaxSessionAge:     metav1.Duration{Duration: s.MaxSessionAge.Or(c.Gateway.MaxSessionAge.Duration)},
			MaxPods:           int32(s.MaxPods),
			WrapperConfigJSON: string(wjson),
			Security: jugv1.SecuritySpec{
				WritableTmp:            s.Security.WritableTmp,
				RunAsUser:              s.Security.RunAsUser,
				RunAsGroup:             s.Security.RunAsGroup,
				ReadOnlyRootFilesystem: s.Security.ReadOnlyRootFilesystem == nil || *s.Security.ReadOnlyRootFilesystem,
				ExtraWritablePaths:     s.Security.ExtraWritablePaths,
			},
		},
	}
	if s.HTTP != nil {
		st.Spec.HTTPPort = int32(s.HTTP.Port)
		st.Spec.HTTPPath = s.HTTP.Path
	}
	for _, e := range s.Egress {
		r := jugv1.EgressRule{Host: e.Host, Protocol: e.Protocol}
		for _, p := range e.Ports {
			r.Ports = append(r.Ports, int32(p))
		}
		st.Spec.Egress = append(st.Spec.Egress, r)
	}
	return st, nil
}

func resources(r config.Resources) (corev1.ResourceRequirements, error) {
	out := corev1.ResourceRequirements{Requests: corev1.ResourceList{}, Limits: corev1.ResourceList{}}
	set := func(list corev1.ResourceList, name corev1.ResourceName, q config.Quantity) error {
		if q == "" {
			return nil
		}
		parsed, err := resource.ParseQuantity(q.String())
		if err != nil {
			return fmt.Errorf("%s=%q: %w", name, q, err)
		}
		list[name] = parsed
		return nil
	}
	for _, e := range []error{
		set(out.Requests, corev1.ResourceCPU, r.Requests.CPU),
		set(out.Requests, corev1.ResourceMemory, r.Requests.Memory),
		set(out.Requests, corev1.ResourceEphemeralStorage, r.Requests.EphemeralStorage),
		set(out.Limits, corev1.ResourceCPU, r.Limits.CPU),
		set(out.Limits, corev1.ResourceMemory, r.Limits.Memory),
		set(out.Limits, corev1.ResourceEphemeralStorage, r.Limits.EphemeralStorage),
	} {
		if e != nil {
			return out, e
		}
	}
	return out, nil
}

// ConfigSyncer upserts ServerType objects whenever the config store reloads and
// prunes the ones that disappeared from the file. Running sessions keep their
// pods (they reference the old config hash) and age out through the reaper.
type ConfigSyncer struct {
	Client    client.Client
	Namespace string
	Log       *slog.Logger
}

// Sync renders and applies every server type of l.
func (cs *ConfigSyncer) Sync(ctx context.Context, l *config.Loaded) error {
	want := map[string]bool{}
	for i := range l.Config.Servers {
		s := &l.Config.Servers[i]
		st, err := RenderServerType(l, s, cs.Namespace)
		if err != nil {
			return err
		}
		want[st.Name] = true
		var existing jugv1.ServerType
		err = cs.Client.Get(ctx, client.ObjectKeyFromObject(st), &existing)
		switch {
		case err == nil:
			if existing.Spec.ConfigHash == st.Spec.ConfigHash {
				continue
			}
			existing.Spec = st.Spec
			existing.Labels = st.Labels
			if err := cs.Client.Update(ctx, &existing); err != nil {
				return fmt.Errorf("update servertype %s: %w", st.Name, err)
			}
		default:
			if err := cs.Client.Create(ctx, st); err != nil {
				return fmt.Errorf("create servertype %s: %w", st.Name, err)
			}
		}
		cs.Log.Info("servertype synced", "name", st.Name, "hash", l.Hash)
	}
	var list jugv1.ServerTypeList
	if err := cs.Client.List(ctx, &list, client.InNamespace(cs.Namespace)); err != nil {
		return err
	}
	for i := range list.Items {
		if !want[list.Items[i].Name] {
			cs.Log.Info("servertype removed from config; deleting", "name", list.Items[i].Name)
			if err := cs.Client.Delete(ctx, &list.Items[i]); err != nil {
				return err
			}
		}
	}
	return nil
}
