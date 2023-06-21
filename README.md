<p align="center"><img src="https://avatars.githubusercontent.com/u/128749691" width="150" /></p>

# Wavy

Wavy is a toolset for running GUI applications on Kubernetes.

[![Build Status](https://github.com/wavyland/wavy/workflows/CI/badge.svg)](https://github.com/wavyland/wavy/actions?query=workflow%3ACI)
[![Go Report Card](https://goreportcard.com/badge/github.com/wavyland/wavy)](https://goreportcard.com/report/github.com/wavyland/wavy)

## Overview

Wavy makes it possible to run containerized GUI desktop applications &mdash; think VS Code, or Libreoffice &mdash; on Kubernetes and makes them accessible via the browser or on a display connected to a node.
This workflow allows users to run applications in the cloud and access them from any device without needing to install any software.
Wavy works by patching Kubernetes workloads that are annotated with `wavy.squat.ai/enable=true` to include the necessary tools.

## Getting Started

To install Wavy, deploy the included Kubernetes admission webhook:

```shell
kubectl apply -f https://raw.githubusercontent.com/wavyland/wavy/main/manifests/webhook.yaml
```

Now, deploy an application that renders a GUI and ensure it is annotated with `wavy.squat.ai/enable=true`
For example, the following script could be used to deploy Signal Desktop:

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  annotations:
    wavy.squat.ai/enable: "true"
    wavy.squat.ai/basic-auth-secret: signal
  labels:
    app.kubernetes.io/name: signal
  name: signal
spec:
  containers:
  - image: tianon/signal-desktop:6.18.0
    name: signal
    command:
    - signal-desktop
    args:
    - --no-sandbox
    - --user-data-dir=/root
---
apiVersion: v1
kind: Secret
metadata:
  labels:
    app.kubernetes.io/name: signal
  name: signal
type: kubernetes.io/basic-auth
stringData:
  username: user
  password: pass
EOF
```

Once the application is ready, it can be accessed by connecting to the Service, for example by defining an Ingress or by port-forwarding:

```shell
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=signal --timeout=-1s
kubectl port-forward signal 8080
```

Now, Signal can be used pointing a browser to [http://localhost:8080](http://localhost:8080) and logging in with the username `user` and the password `pass`.

## Annotations

The following annotations can be added to any Kubernetes Pod, DaemonSet, Deployment, ReplicaSet, StatefulSet, CronJob, or Job to configure Wavy:

|Name|type|examples|
|----|----|-------|
|[wavy.squat.ai/enable](#enable)|boolean|`"true"`|
|[wavy.squat.ai/basic-auth-secret](#basic-auth-secret)|string|`app-secret`|
|[wavy.squat.ai/tls-secret](#tls-secret)|string|`app-tls`|
|[wavy.squat.ai/host](#host)|boolean|`"true"`|
|[wavy.squat.ai/x](#x)|boolean|`"true"`|

### enable

When annotated with `wavy.squat.ai/enable=true`, workloads are patched by Wavy so that the applications running in them can render their GUI and the GUI is exposed on a port named `wavy-http`.

> **Note**: Kubernetes annotation values are required to be strings; this means the value of this annotation must be the YAML string literal `"true"` rather than the YAML boolean `true`.

### basic-auth-secret

Access to an application can be guarded with basic authentication by annotating the workload with `wavy.squat.ai/basic-auth-secret`.
When basic authentication is activated, access is only permitted with the username and password contained in the secret referenced in the annotation.
The secret is expected to be a Kubernetes secret of type `kubernetes.io/basic-auth` and must provide values for the `username` and `password` keys.
See the [Kubernetes documentation on secrets](https://kubernetes.io/docs/concepts/configuration/secret/#basic-authentication-secret) for more information.

### tls-secret

Workloads annotated with `wavy.squat.ai/tls-secret` will expose the HTTP service over TLS using the certificate and key contained in the referenced secret.
The secret is expected to be a Kubernetes secret of type `kubernetes.io/tls` and must provide values for the `tls.crt` and `tls.key` keys.
See the [Kubernetes documentation on secrets](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets) for more information.

### host

When workloads are annotated with `wavy.squat.ai/host=true`, Wavy renders their applications on a physical device connected to the host, for example a monitor connected to a server.
This mode of operation allows nodes in a Kubernetes cluster to serve as display kiosks rendering an application on a display.

> **Note**: Wavy accesses the host's devices without using privileged Pods. This is made possible by the [generic-device-plugin](https://github.com/squat/generic-device-plugin), which enables the Kubernetes scheduler to allocate access to Linux devices. The generic-device-plugin must be configured with the following flags to discover the devices needed by Wavy:
1. `--device={"name": "tty", "groups": [{"paths": [{"limit": 10, "path": "/dev/tty0"}, {"path": "/dev/tty[1-9]"}]}]}`
2. `--device={"name": "input", "groups": [{"count": 10, "paths": [{"path": "/dev/input"}]}]}`
3. `--device={"name": "dri", "groups": [{"count": 10, "paths": [{"path": "/dev/dri"}]}]}`

### x

Support for X is enabled by default.
The `wavy.squat.ai/x=false` annotation can be used to disable support for X in the workload.

> **Note**: Kubernetes annotation values are required to be strings; this means the value of this annotation must be the YAML string literal `"false"` rather than the YAML boolean `false`.
