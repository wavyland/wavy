// Copyright 2023 the Wavy authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/metalmatze/signal/internalserver"
	"github.com/metalmatze/signal/server/signalhttp"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

const (
	containerNameNoVNC           = "wavy-novnc"
	containerNameSway            = "wavy-sway"
	containerNameWayVNC          = "wavy-wayvnc"
	envNameDisplay               = "DISPLAY"
	envNameWaylandDisplay        = "WAYLAND_DISPLAY"
	envNameWLRBackends           = "WLR_BACKENDS"
	envNameXDGRuntimeDir         = "XDG_RUNTIME_DIR"
	portNameVNC                  = "wavy-vnc"
	portNameHTTP                 = "wavy-http"
	volumeNameRunUdevData        = "wavy-run-udev-data"
	volumeNameTLS                = "wavy-tls"
	volumeNameTmp                = "wavy-tmp"
	volumeNameXDGRuntimeDir      = "wavy-xdg-runtime-dir"
	pathRunUdevData              = "/run/udev/data"
	pathTLS                      = "/var/lib/wavy/tls"
	pathTmp                      = "/tmp"
	pathXDGRuntimeDir            = "/var/lib/wavy/xdg"
	defaultWaylandDisplay        = "wayland-1"
	annotationKeyEnable          = "wavy.squat.ai/enable"
	annotationKeyTLSSecret       = "wavy.squat.ai/tls-secret"
	annotationKeyBasicAuthSecret = "wavy.squat.ai/basic-auth-secret"
	annotationKeyHost            = "wavy.squat.ai/host"
	annotationKeyX               = "wavy.squat.ai/x"
	annotationValueTrue          = "true"
	annotationValueFalse         = "false"
	resourceNameDRI              = v1.ResourceName("squat.ai/dri")
	resourceNameInput            = v1.ResourceName("squat.ai/input")
	resourceNameTTY              = v1.ResourceName("squat.ai/tty")
)

var (
	certificate string
	key         string
	metricsAddr string
	listenAddr  string
)

var deserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

func webhookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "webhook",
		PreRunE: func(c *cobra.Command, a []string) error {
			if c.HasParent() {
				return c.Parent().PreRunE(c, a)
			}
			return nil
		},
		Short: "webhook starts a HTTPS server to mutate Kubernetes workloads with Wavy components.",
		RunE:  webhook,
	}

	cmd.Flags().StringVar(&listenAddr, "listen", ":8443", "The address at which the webhook server should listen.")
	cmd.Flags().StringVar(&metricsAddr, "listen-metrics", ":9090", "The address at which to listen for health and metrics.")
	cmd.Flags().StringVar(&certificate, "certificate", "", "The path to a certificate file.")
	cmd.Flags().StringVar(&key, "key", "", "The path to a key file.")
	return cmd
}

var (
	errorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "The total number of errors",
		},
	)
)

func mutateHandler(w http.ResponseWriter, r *http.Request) {
	level.Debug(logger).Log("msg", "handling request", "source", r.RemoteAddr)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorCounter.Inc()
		level.Error(logger).Log("err", "failed to parse body from incoming request", "source", r.RemoteAddr)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var admissionReview admissionv1.AdmissionReview

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		errorCounter.Inc()
		msg := fmt.Sprintf("received Content-Type=%s, expected application/json", contentType)
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	response := admissionv1.AdmissionReview{}

	_, gvk, err := deserializer.Decode(body, nil, &admissionReview)
	if err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if *gvk != admissionv1.SchemeGroupVersion.WithKind("AdmissionReview") {
		errorCounter.Inc()
		msg := "only API v1 is supported"
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if admissionReview.Request == nil || admissionReview.Request.UID == "" {
		errorCounter.Inc()
		msg := "invalid admission review request"
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	response.SetGroupVersionKind(*gvk)
	response.Response = &admissionv1.AdmissionResponse{
		Allowed: true,
		UID:     admissionReview.Request.UID,
	}

	ps, om, getObject, err := getPodSpec(admissionReview.Request)
	if err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("could not unmarshal extension to pod spec: %v:", err)
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if requiresPatch(om) {
		o := patchOptions{
			basicAuthSecret: om.Annotations[annotationKeyBasicAuthSecret],
			host:            om.Annotations[annotationKeyHost] == annotationValueTrue,
			tlsSecret:       om.Annotations[annotationKeyTLSSecret],
			x:               om.Annotations[annotationKeyHost] != annotationValueFalse,
		}
		ps = patchPodSpec(ps, &o)
		newBytes, err := json.Marshal(getObject(ps))
		if err != nil {
			errorCounter.Inc()
			msg := fmt.Sprintf("could not marshal new pod: %v:", err)
			level.Error(logger).Log("err", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		ops, err := jsonpatch.CreatePatch(admissionReview.Request.Object.Raw, newBytes)
		if err != nil {
			errorCounter.Inc()
			msg := fmt.Sprintf("could not create patch: %v:", err)
			level.Error(logger).Log("err", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		if len(ops) != 0 {
			patch, err := json.Marshal(ops)
			if err != nil {
				errorCounter.Inc()
				msg := fmt.Sprintf("could not marshal patch: %v:", err)
				level.Error(logger).Log("err", msg)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}
			ptjp := admissionv1.PatchTypeJSONPatch
			response.Response.Patch = patch
			response.Response.PatchType = &ptjp
		}
	}

	res, err := json.Marshal(response)
	if err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("failed to marshal response: %v", err)
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(res); err != nil {
		level.Error(logger).Log("err", err, "msg", "failed to write response")
	}
}

func getPodSpec(ar *admissionv1.AdmissionRequest) (*v1.PodSpec, *metav1.ObjectMeta, func(*v1.PodSpec) runtime.Object, error) {
	var ps v1.PodSpec
	var om metav1.ObjectMeta
	var fn func(*v1.PodSpec) runtime.Object
	switch {
	case ar.Kind.Group == "" && ar.Kind.Version == "v1" && ar.Kind.Kind == "Pod":
		var pod v1.Pod
		if err := json.Unmarshal(ar.Object.Raw, &pod); err != nil {
			return nil, nil, nil, err
		}
		ps = pod.Spec
		om = pod.ObjectMeta
		fn = func(ps *v1.PodSpec) runtime.Object {
			pod.Spec = *ps
			return &pod
		}
	case ar.Kind.Group == "apps" && ar.Kind.Version == "v1":
		switch ar.Kind.Kind {
		case "Deployment":
			var d appsv1.Deployment
			if err := json.Unmarshal(ar.Object.Raw, &d); err != nil {
				return nil, nil, nil, err
			}
			ps = d.Spec.Template.Spec
			om = d.ObjectMeta
			fn = func(ps *v1.PodSpec) runtime.Object {
				d.Spec.Template.Spec = *ps
				return &d
			}
		case "DaemonSet":
			var d appsv1.DaemonSet
			if err := json.Unmarshal(ar.Object.Raw, &d); err != nil {
				return nil, nil, nil, err
			}
			ps = d.Spec.Template.Spec
			om = d.ObjectMeta
			fn = func(ps *v1.PodSpec) runtime.Object {
				d.Spec.Template.Spec = *ps
				return &d
			}
		case "ReplicaSet":
			var r appsv1.ReplicaSet
			if err := json.Unmarshal(ar.Object.Raw, &r); err != nil {
				return nil, nil, nil, err
			}
			ps = r.Spec.Template.Spec
			om = r.ObjectMeta
			fn = func(ps *v1.PodSpec) runtime.Object {
				r.Spec.Template.Spec = *ps
				return &r
			}
		case "StatefulSet":
			var s appsv1.StatefulSet
			if err := json.Unmarshal(ar.Object.Raw, &s); err != nil {
				return nil, nil, nil, err
			}
			ps = s.Spec.Template.Spec
			om = s.ObjectMeta
			fn = func(ps *v1.PodSpec) runtime.Object {
				s.Spec.Template.Spec = *ps
				return &s
			}
		}
	case ar.Kind.Group == "batch" && ar.Kind.Version == "v1":
		switch ar.Kind.Kind {
		case "Job":
			var j batchv1.Job
			if err := json.Unmarshal(ar.Object.Raw, &j); err != nil {
				return nil, nil, nil, err
			}
			ps = j.Spec.Template.Spec
			om = j.ObjectMeta
			fn = func(ps *v1.PodSpec) runtime.Object {
				j.Spec.Template.Spec = *ps
				return &j
			}
		case "CronJob":
			var j batchv1.CronJob
			if err := json.Unmarshal(ar.Object.Raw, &j); err != nil {
				return nil, nil, nil, err
			}
			ps = j.Spec.JobTemplate.Spec.Template.Spec
			om = j.ObjectMeta
			fn = func(ps *v1.PodSpec) runtime.Object {
				j.Spec.JobTemplate.Spec.Template.Spec = *ps
				return &j
			}
		}
	default:
		return nil, nil, nil, errors.New("this resource is not supported")
	}

	return &ps, &om, fn, nil
}

func requiresPatch(meta *metav1.ObjectMeta) bool {
	return meta.Annotations[annotationKeyEnable] == annotationValueTrue
}

type patchOptions struct {
	basicAuthSecret string
	host            bool
	tlsSecret       string
	x               bool
}

func sliceHasElementWithName(slice any, name string) bool {
	switch s := slice.(type) {
	case []v1.EnvVar:
		for i := range s {
			if s[i].Name == name {
				return true
			}
		}
	case []v1.Volume:
		for i := range s {
			if s[i].Name == name {
				return true
			}
		}
	case []v1.VolumeMount:
		for i := range s {
			if s[i].Name == name {
				return true
			}
		}
	}
	return false
}

func patchPodSpec(old *v1.PodSpec, o *patchOptions) *v1.PodSpec {
	ps := old.DeepCopy()
	var hasNoVNC bool
	var hasSway bool
	var hasWayVNC bool
	for i := range ps.Containers {
		switch ps.Containers[i].Name {
		case containerNameNoVNC:
			hasNoVNC = true
		case containerNameSway:
			hasSway = true
		case containerNameWayVNC:
			hasWayVNC = true
		default:
			if o.x && !sliceHasElementWithName(ps.Containers[i].Env, envNameDisplay) {
				ps.Containers[i].Env = append(ps.Containers[i].Env, v1.EnvVar{
					Name:  envNameDisplay,
					Value: ":0",
				})
			}
			if !sliceHasElementWithName(ps.Containers[i].Env, envNameXDGRuntimeDir) {
				ps.Containers[i].Env = append(ps.Containers[i].Env, v1.EnvVar{
					Name:  envNameXDGRuntimeDir,
					Value: pathXDGRuntimeDir,
				})
			}
			if !sliceHasElementWithName(ps.Containers[i].Env, envNameWaylandDisplay) {
				ps.Containers[i].Env = append(ps.Containers[i].Env, v1.EnvVar{
					Name:  envNameWaylandDisplay,
					Value: defaultWaylandDisplay,
				})
			}
			if o.x && !sliceHasElementWithName(ps.Containers[i].VolumeMounts, volumeNameTmp) {
				ps.Containers[i].VolumeMounts = append(ps.Containers[i].VolumeMounts, v1.VolumeMount{
					Name:      volumeNameTmp,
					MountPath: pathTmp,
				})
			}
			if !sliceHasElementWithName(ps.Containers[i].VolumeMounts, volumeNameXDGRuntimeDir) {
				ps.Containers[i].VolumeMounts = append(ps.Containers[i].VolumeMounts, v1.VolumeMount{
					Name:      volumeNameXDGRuntimeDir,
					MountPath: pathXDGRuntimeDir,
				})
			}
		}
	}

	if !hasNoVNC {
		args := []string{"--file-only"}
		port := int32(8080)
		var vs []v1.VolumeMount
		if o.tlsSecret != "" {
			port = 8443
			args = append(args,
				"--ssl-only",
				"--cert",
				filepath.Join(pathTLS, "tls.crt"),
				"--key",
				filepath.Join(pathTLS, "tls.key"),
			)
			vs = append(vs, v1.VolumeMount{
				Name:      volumeNameTLS,
				MountPath: pathTLS,
			})
			ps.Volumes = append(ps.Volumes, v1.Volume{
				Name: volumeNameTLS,
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: o.tlsSecret,
					},
				},
			})
		}

		var es []v1.EnvVar
		if o.basicAuthSecret != "" {
			args = append(args,
				"--web-auth",
				"--auth-plugin",
				"BasicHTTPAuth",
				"--auth-source",
				"$(USERNAME):$(PASSWORD)",
			)
			es = append(es, []v1.EnvVar{
				{
					Name: "USERNAME",
					ValueFrom: &v1.EnvVarSource{
						SecretKeyRef: &v1.SecretKeySelector{
							LocalObjectReference: v1.LocalObjectReference{
								Name: o.basicAuthSecret,
							},
							Key: "username",
						},
					},
				},
				{
					Name: "PASSWORD",
					ValueFrom: &v1.EnvVarSource{
						SecretKeyRef: &v1.SecretKeySelector{
							LocalObjectReference: v1.LocalObjectReference{
								Name: o.basicAuthSecret,
							},
							Key: "password",
						},
					},
				},
			}...,
			)
		}

		args = append(args, strconv.Itoa(int(port)), "localhost:5900")
		ps.Containers = append(ps.Containers, v1.Container{
			Name:  containerNameNoVNC,
			Image: "ghcr.io/wavyland/novnc",
			Args:  args,
			Env:   es,
			Ports: []v1.ContainerPort{
				{
					Name:          portNameHTTP,
					ContainerPort: port,
					Protocol:      v1.ProtocolTCP,
				},
			},
			VolumeMounts: vs,
		})
	}

	if !hasSway {
		es := []v1.EnvVar{
			{
				Name:  envNameXDGRuntimeDir,
				Value: pathXDGRuntimeDir,
			},
		}
		vs := []v1.VolumeMount{
			{
				Name:      volumeNameXDGRuntimeDir,
				MountPath: pathXDGRuntimeDir,
			},
		}
		if o.x {
			vs = append(vs, v1.VolumeMount{
				Name:      volumeNameTmp,
				MountPath: pathTmp,
			})
		}
		var cmd []string
		var rs v1.ResourceList
		var sc *v1.SecurityContext
		if o.host {
			cmd = append(cmd, "seatd-launch", "sway")
			vs = append(vs, []v1.VolumeMount{
				{
					Name:      volumeNameRunUdevData,
					MountPath: pathRunUdevData,
				},
			}...)
			rs = v1.ResourceList{
				resourceNameDRI:   *resource.NewQuantity(1, resource.DecimalSI),
				resourceNameInput: *resource.NewQuantity(1, resource.DecimalSI),
				resourceNameTTY:   *resource.NewQuantity(1, resource.DecimalSI),
			}
			sc = &v1.SecurityContext{
				Capabilities: &v1.Capabilities{
					Add: []v1.Capability{
						v1.Capability("SYS_TTY_CONFIG"),
					},
				},
			}
		} else {
			es = append(es, v1.EnvVar{
				Name:  envNameWLRBackends,
				Value: "headless",
			})
		}
		ps.Containers = append(ps.Containers, v1.Container{
			Name:    containerNameSway,
			Image:   "ghcr.io/wavyland/sway",
			Command: cmd,
			Env:     es,
			Resources: v1.ResourceRequirements{
				Limits: rs,
			},
			SecurityContext: sc,
			VolumeMounts:    vs,
		})
	}

	if !hasWayVNC {
		ps.Containers = append(ps.Containers, v1.Container{
			Name:  containerNameWayVNC,
			Image: "ghcr.io/wavyland/wayvnc",
			Args:  []string{"127.0.0.1", "5900"},
			Env: []v1.EnvVar{
				{
					Name:  envNameXDGRuntimeDir,
					Value: pathXDGRuntimeDir,
				},
				{
					Name:  envNameWaylandDisplay,
					Value: defaultWaylandDisplay,
				},
			},
			VolumeMounts: []v1.VolumeMount{
				{
					Name:      volumeNameXDGRuntimeDir,
					MountPath: pathXDGRuntimeDir,
				},
			},
		})
	}

	if ps.SecurityContext == nil {
		ps.SecurityContext = &v1.PodSecurityContext{}
	}
	if ps.SecurityContext.FSGroup == nil {
		fsGroup := int64(65534)
		ps.SecurityContext.FSGroup = &fsGroup
	}
	if o.x && !sliceHasElementWithName(ps.Volumes, volumeNameTmp) {
		ps.Volumes = append(ps.Volumes, v1.Volume{
			Name: volumeNameTmp,
			VolumeSource: v1.VolumeSource{
				EmptyDir: &v1.EmptyDirVolumeSource{},
			},
		})
	}
	if !sliceHasElementWithName(ps.Volumes, volumeNameXDGRuntimeDir) {
		ps.Volumes = append(ps.Volumes, v1.Volume{
			Name: volumeNameXDGRuntimeDir,
			VolumeSource: v1.VolumeSource{
				EmptyDir: &v1.EmptyDirVolumeSource{},
			},
		})
	}
	if o.host && !sliceHasElementWithName(ps.Volumes, volumeNameRunUdevData) {
		hostPathDirectory := v1.HostPathDirectory
		ps.Volumes = append(ps.Volumes, v1.Volume{
			Name: volumeNameRunUdevData,
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: pathRunUdevData,
					Type: &hostPathDirectory,
				},
			},
		})
	}

	return ps
}

func webhook(_ *cobra.Command, _ []string) error {
	registry.MustRegister(
		errorCounter,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()
	i := signalhttp.NewHandlerInstrumenter(registry, []string{"handler"})
	var g run.Group
	g.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))
	{
		h := internalserver.NewHandler(
			internalserver.WithName("Internal Kilo API"),
			internalserver.WithPrometheusRegistry(registry),
			internalserver.WithPProf(),
		)
		h.AddEndpoint("/health", "Exposes health checks", i.NewHandler(prometheus.Labels{"handler": "health"}, http.HandlerFunc(healthHandler)))

		s := &http.Server{
			Addr:    metricsAddr,
			Handler: h,
		}

		g.Add(
			func() error {
				level.Info(logger).Log("msg", "starting metrics server", "address", s.Addr)
				err := s.ListenAndServe()
				level.Info(logger).Log("msg", "metrics server exited", "err", err)
				return err

			},
			func(err error) {
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					level.Info(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					level.Error(logger).Log("msg", "received error", "err", err.Error())
				}
				level.Info(logger).Log("msg", "shutting down metrics server gracefully")
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer func() {
					cancel()
				}()
				if err := s.Shutdown(ctx); err != nil {
					level.Error(logger).Log("msg", "failed to shut down metrics server gracefully", "err", err.Error())
					s.Close()
				}
			},
		)
	}

	{
		mux := http.NewServeMux()
		mux.Handle("/", i.NewHandler(prometheus.Labels{"handler": "mutate"}, http.HandlerFunc(mutateHandler)))
		s := &http.Server{
			Addr:    listenAddr,
			Handler: mux,
		}
		g.Add(
			func() error {
				level.Info(logger).Log("msg", "starting webhook server", "address", s.Addr)
				err := s.ListenAndServeTLS(certificate, key)
				level.Info(logger).Log("msg", "webhook server exited", "err", err)
				return err
			},
			func(err error) {
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					level.Info(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					level.Error(logger).Log("msg", "received error", "err", err.Error())
				}
				level.Info(logger).Log("msg", "shutting down webhook server gracefully")
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer func() {
					cancel()
				}()
				if err := s.Shutdown(ctx); err != nil {
					level.Error(logger).Log("msg", "failed to shut down webhook server gracefully", "err", err.Error())
					s.Close()
				}
			},
		)
	}

	err := g.Run()
	var serr run.SignalError
	if ok := errors.As(err, &serr); ok {
		return nil
	}
	return err
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
