<p align="center"><img src="https://avatars.githubusercontent.com/u/128749691?s=150&v=4" width="150" /></p>

# Wavy

Wavy is a toolset for running GUI applications on Kubernetes.

[![Build Status](https://github.com/wavyland/wavy/workflows/CI/badge.svg)](https://github.com/wavyland/wavy/actions?query=workflow%3ACI)
[![Go Report Card](https://goreportcard.com/badge/github.com/wavyland/wavy)](https://goreportcard.com/report/github.com/wavyland/wavy)

## Overview

Wavy makes it possible to run containerized GUI applications, think Inkscape or Libreoffice, on Kubernetes and makes them accessible via the browser.
This workflow allows users to run applications in the cloud and access them from any device without needing to install any software.
Wavy works by patching Kubernetes Pods that are annotated with `wavy.squat.ai/inject=enabled` to include the necessary tools.

## Getting Started

To install Wavy, deploy the included Kubernetes admission webhook:

```shell
kubectl apply -f https://raw.githubusercontent.com/wavyland/wavy/main/manifests/webhook.yaml
```

Now, deploy an application that requires a GUI and ensure it is annotated with `wavy.squat.ai/inject=enabled`
For example, the following script could be used to deploy Inkscape:

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  annotations:
    wavy.squat.ai/inject: enabled
  labels:
    app.kubernetes.io/name: inkscape
  name: inkscape
spec:
  containers:
  - image: debian:stable-slim
    name: inkscape
    args:
    - /bin/bash
    - -c
    - apt-get update && apt-get install -y procps inkscape && inkscape
    readinessProbe:
      exec:
        command:
        - /bin/bash
        - -c
        - ps -o command | grep ^inkscape | grep -v grep
      periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: inkscape
  labels:
    app.kubernetes.io/name: inkscape
spec:
  selector:
    app.kubernetes.io/name: inkscape
  ports:
    - port: 6080
      name: http
      targetPort: wavy-http
EOF
```

Once the application is ready, it can be accessed by connecting to the Service, for example by defining an Ingress or by port-forwarding:

```shell
kubectl wait --for=condition=Ready pod/inkscape --timeout=-1s
kubectl port-forward svc/inkscape http
```

Now, Inkscape can be used pointing a browser to [http://localhost:6080](http://localhost:6080).
