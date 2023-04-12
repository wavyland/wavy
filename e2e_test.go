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
	"os/exec"
	"path/filepath"
	"testing"

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
	a := e.Runnable("alpine").Init(e2e.StartOptions{
		Image: "alpine",
		Command: e2e.Command{
			Cmd:  "/usr/bin/tail",
			Args: []string{"-f", "/dev/null"},
		},
	})
	testutil.Ok(t, a.Start())
	out, err = kubectl(context.Background(), e, "apply", "--filename", "manifests/webhook.yaml").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "rollout", "status", "deployment", "wavy-webhook", "--namespace", "wavy").CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "patch", "deployment", "alpine", "--patch", `{"metadata": {"annotations": {"wavy.squat.ai/enable": "true"}}}`).CombinedOutput()
	testutil.Ok(t, err, string(out))
	out, err = kubectl(context.Background(), e, "rollout", "status", "deployment", "alpine").CombinedOutput()
	testutil.Ok(t, err, string(out))
}
