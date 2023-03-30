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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

const (
	containerNameNoVNC        = "wavy-novnc"
	containerNameSway         = "wavy-sway"
	containerNameWayVNC       = "wavy-wayvnc"
	envNameXDGRuntimeDir      = "XDG_RUNTIME_DIR"
	envNameWaylandDisplay     = "WAYLAND_DISPLAY"
	envNameWLRBackends        = "WLR_BACKENDS"
	portNameVNC               = "wavy-vnc"
	portNameHTTP              = "wavy-http"
	volumeNameXDGRuntimeDir   = "wavy-xdg-runtime-dir"
	volumeNameTLS             = "wavy-tls"
	pathXDGRuntimeDir         = "/var/lib/wavy/xdg"
	pathTLS                   = "/var/lib/wavy/tls"
	defaultWaylandDisplay     = "wayland-1"
	annotationKeyEnable       = "wavy.squat.ai/enable"
	annotationKeyTLSSecret    = "wavy.squat.ai/tls-secret"
	annotationValueEnableTrue = "true"
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

	var pod v1.Pod
	if err := json.Unmarshal(admissionReview.Request.Object.Raw, &pod); err != nil {
		errorCounter.Inc()
		msg := fmt.Sprintf("could not unmarshal extension to pod spec: %v:", err)
		level.Error(logger).Log("err", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if requiresPatch(&pod.ObjectMeta) {
		o := patchOptions{
			tlsSecret: pod.ObjectMeta.Annotations[annotationKeyTLSSecret],
		}
		pod.Spec = *patchPodSpec(&pod.Spec, &o)
		newBytes, err := json.Marshal(pod)
		if err != nil {
			errorCounter.Inc()
			msg := fmt.Sprintf("could not marshal new pod: %v:", err)
			level.Error(logger).Log("err", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		op, err := jsonpatch.CreatePatch(admissionReview.Request.Object.Raw, newBytes)
		if err != nil {
			errorCounter.Inc()
			msg := fmt.Sprintf("could not create patch: %v:", err)
			level.Error(logger).Log("err", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		patch, err := json.Marshal(op)
		if err != nil {
			errorCounter.Inc()
			msg := fmt.Sprintf("could not marshal patch: %v:", err)
			level.Error(logger).Log("err", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		if len(patch) != 0 {
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

func requiresPatch(meta *metav1.ObjectMeta) bool {
	return meta.Annotations[annotationKeyEnable] == annotationValueEnableTrue
}

type patchOptions struct {
	tlsSecret string
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
			ps.Containers[i].Env = append(ps.Containers[i].Env, []v1.EnvVar{
				{
					Name:  envNameXDGRuntimeDir,
					Value: pathXDGRuntimeDir,
				},
				{
					Name:  envNameWaylandDisplay,
					Value: defaultWaylandDisplay,
				},
			}...)
			ps.Containers[i].VolumeMounts = append(ps.Containers[i].VolumeMounts, v1.VolumeMount{
				Name:      volumeNameXDGRuntimeDir,
				MountPath: pathXDGRuntimeDir,
			})
		}
	}

	if !hasNoVNC {
		args := []string{"--file-only"}
		port := int32(8080)
		var vs []v1.VolumeMount
		if o.tlsSecret != "" {
			port = 8443
			args = append(args, []string{
				"--ssl-only",
				"--cert",
				filepath.Join(pathTLS, "tls.crt"),
				"--key",
				filepath.Join(pathTLS, "tls.key"),
			}...)
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

		args = append(args, []string{strconv.Itoa(int(port)), "localhost:5900"}...)
		ps.Containers = append(ps.Containers, v1.Container{
			Name:  containerNameNoVNC,
			Image: "ghcr.io/wavyland/novnc",
			Args:  args,
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
		ps.Containers = append(ps.Containers, v1.Container{
			Name:  containerNameSway,
			Image: "ghcr.io/wavyland/sway",
			Env: []v1.EnvVar{
				{
					Name:  envNameXDGRuntimeDir,
					Value: pathXDGRuntimeDir,
				},
				{
					Name:  envNameWLRBackends,
					Value: "headless",
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

	if !hasNoVNC || !hasSway || !hasWayVNC {
		if ps.SecurityContext == nil {
			ps.SecurityContext = &v1.PodSecurityContext{}
		}
		if ps.SecurityContext.FSGroup == nil {
			fsGroup := int64(65534)
			ps.SecurityContext.FSGroup = &fsGroup
		}
		ps.Volumes = append(ps.Volumes, v1.Volume{
			Name: volumeNameXDGRuntimeDir,
			VolumeSource: v1.VolumeSource{
				EmptyDir: &v1.EmptyDirVolumeSource{},
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
