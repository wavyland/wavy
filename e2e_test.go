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
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/n7olkachev/imgdiff/pkg/imgdiff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func kind(ctx context.Context, e e2e.Environment, extraArgs ...string) *exec.Cmd {
	args := []string{"--name", e.Name()}
	return exec.CommandContext(ctx, "kind", append(args, extraArgs...)...)
}

func kubectl(ctx context.Context, e e2e.Environment, extraArgs ...string) *exec.Cmd {
	args := []string{"--kubeconfig", filepath.Join(e.SharedDir(), "kubeconfig")}
	return exec.CommandContext(ctx, "kubectl", append(args, extraArgs...)...)
}

func TestE2EWebhook(t *testing.T) {
	t.Parallel()
	e, err := e2e.NewKindEnvironment()
	require.NoError(t, err)
	t.Cleanup(e.Close)
	out, err := kind(t.Context(), e, "load", "docker-image", "ghcr.io/wavyland/wavy").CombinedOutput()
	require.NoError(t, err, string(out))
	signal := e.Runnable("signal").WithPorts(map[string]int{"vnc": 5900}).Init(e2e.StartOptions{
		Image: "tianon/signal-desktop:7.69",
		Command: e2e.Command{
			Cmd:  "signal-desktop",
			Args: []string{"--no-sandbox", "--user-data-dir=/root"},
		},
	})
	require.NoError(t, signal.Start())
	out, err = kubectl(t.Context(), e, "apply", "--filename", "manifests/webhook.yaml").CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = kubectl(t.Context(), e, "wait", "--for", "condition=complete", "job", "cert-gen", "--namespace", "wavy", "--timeout", "1m").CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = kubectl(t.Context(), e, "rollout", "status", "deployment", "wavy-webhook", "--namespace", "wavy").CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = kubectl(t.Context(), e, "patch", "deployment", "signal", "--patch", `{"metadata": {"annotations": {"wavy.squat.ai/enable": "true", "wavy.squat.ai/expose-vnc": "true"}}}`).CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = kubectl(t.Context(), e, "rollout", "status", "deployment", "signal").CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = kubectl(t.Context(), e, "create", "job", "vncdotool", "--image", "ghcr.io/wavyland/vncdotool", "--", "vncdotool", "-s", "signal::5900", "move", "200", "10", "click", "1", "pause", "1", "move", "200", "250", "click", "1", "pause", "1", "move", "1000", "285", "mousedown", "1", "pause", "1", "mousemove", "800", "285", "mouseup", "1").CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = kubectl(t.Context(), e, "wait", "--for", "condition=complete", "job", "vncdotool", "--timeout", "1m").CombinedOutput()
	require.NoError(t, err, string(out))
	capture := filepath.Join(e.SharedDir(), "capture.png")
	out, err = kubectl(t.Context(), e, "run", "vnccapture", "--image", "ghcr.io/wavyland/vnccapture", "--restart", "Never", "--overrides", `{
  "apiVersion": "v1",
  "spec": {
    "containers": [
      {
	"name": "vnccapture",
	"image": "ghcr.io/wavyland/vnccapture",
	"args": ["-H", "signal", "-o", "`+capture+`"],
	"volumeMounts": [{
	  "mountPath": "`+e.SharedDir()+`",
	  "name": "working-directory"
	}]
      }
    ],
    "volumes": [{
      "name":"working-directory",
      "hostPath": {
	  "path": "`+e.SharedDir()+`"
      }
    }]
  }
}`).CombinedOutput()
	require.NoError(t, err, string(out), "should successfully create vnccapture pod")
	out, err = kubectl(t.Context(), e, "wait", "--for", "jsonpath={.status.phase}=Succeeded", "pod", "vnccapture", "--timeout", "1m").CombinedOutput()
	require.NoError(t, err, string(out), "vnccapture pod should finish running within 1 minute")
	err = compareImages("test/signal.png", capture)
	assert.NoError(t, err, "images should be identical")
	if err != nil {
		data, err := os.ReadFile(capture)
		assert.NoError(t, err)
		err = os.WriteFile("capture.png", data, 0644)
		assert.NoError(t, err)
	}
}

func loadImages(paths ...string) ([]image.Image, error) {
	images := make([]image.Image, len(paths))
	errs := make([]error, len(paths))
	wg := sync.WaitGroup{}
	for i, path := range paths {
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			f, err := os.Open(path)
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = f.Close() }()
			img, _, err := image.Decode(f)
			if err != nil {
				errs[i] = err
				return
			}
			images[i] = img
		}(i, path)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return images, nil
}

func compareImages(a, b string) error {
	images, err := loadImages(a, b)
	if err != nil {
		return fmt.Errorf("failed to load images: %w", err)
	}
	result := imgdiff.Diff(images[0], images[1], &imgdiff.Options{
		Threshold: 0.1,
	})
	if !result.Equal {
		return errors.New("images are different")
	}
	return nil
}
