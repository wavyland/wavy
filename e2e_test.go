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
	"image"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/n7olkachev/imgdiff/pkg/imgdiff"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

func kind(ctx context.Context, e e2e.Environment, extraArgs ...string) *exec.Cmd {
	args := []string{"--name", e.Name()}
	return exec.CommandContext(ctx, "kind", append(args, extraArgs...)...)
}

func kubectl(ctx context.Context, e e2e.Environment, extraArgs ...string) *exec.Cmd {
	args := []string{"--kubeconfig", filepath.Join(e.SharedDir(), "kubeconfig")}
	return exec.CommandContext(ctx, "kubectl", append(args, extraArgs...)...)
}

func TestWebhook(t *testing.T) {
	t.Parallel()
	e, err := e2e.NewKindEnvironment()
	testutil.Ok(t, err)
	t.Cleanup(e.Close)
	out, err := kind(context.Background(), e, "load", "docker-image", "ghcr.io/wavyland/wavy").CombinedOutput()
	testutil.Ok(t, err, string(out))
	s := e.Runnable("signal").WithPorts(map[string]int{"vnc": 5900}).Init(e2e.StartOptions{
		Image: "tianon/signal-desktop:6",
		Command: e2e.Command{
			Cmd:  "signal-desktop",
			Args: []string{"--no-sandbox", "--user-data-dir=/root"},
		},
	})
	testutil.Ok(t, s.Start())
	out, err = kubectl(context.Background(), e, "apply", "--filename", "manifests/webhook.yaml").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "wait", "--for", "condition=complete", "job", "cert-gen", "--namespace", "wavy", "--timeout", "1m").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "rollout", "status", "deployment", "wavy-webhook", "--namespace", "wavy").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "patch", "deployment", "signal", "--patch", `{"metadata": {"annotations": {"wavy.squat.ai/enable": "true"}}}`).CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "rollout", "status", "deployment", "signal").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "create", "job", "vncdotool", "--image", "ghcr.io/wavyland/vncdotool", "--", "vncdotool", "-s", "signal::5900", "move", "20", "10", "click", "1", "move", "20", "100", "click", "1", "move", "1000", "300").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "wait", "--for", "condition=complete", "job", "vncdotool", "--timeout", "1m").CombinedOutput()
	testutil.Ok(t, err, string(out))
	capture := filepath.Join(e.SharedDir(), "capture.png")
	out, err = kubectl(context.Background(), e, "run", "vnccapture", "--image", "ghcr.io/wavyland/vnccapture", "--restart", "Never", "--overrides", `{
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
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "wait", "--for", "jsonpath={.status.phase}=Succeeded", "pod", "vnccapture", "--timeout", "1m").CombinedOutput()
	testutil.Ok(t, err, string(out))
	defer os.Remove(capture)
	testutil.Ok(t, compareImages("test/signal.png", capture))
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
			defer f.Close()
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
		return err
	}
	result := imgdiff.Diff(images[0], images[1], &imgdiff.Options{
		Threshold: 0.1,
	})
	if !result.Equal {
		return errors.New("images are different")
	}
	return nil
}
