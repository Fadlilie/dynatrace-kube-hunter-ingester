# Shameless copy from https://github.com/tilt-dev/tilt-example-go/blob/master/3-recommended/Tiltfile

# -*- mode: Python -*-

# For more on Extensions, see: https://docs.tilt.dev/extensions.html
load('ext://restart_process', 'docker_build_with_restart')

compile_cmd = 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/app ./'
# if os.name == 'nt':
#   compile_cmd = 'build.bat'

local_resource(
  'app-compile',
  compile_cmd,
  deps=['./main.go', './cmd', './internal', './pkg'],
)

docker_build_with_restart(
  'martinnirtl/dynatrace-kube-hunter-ingester',
  '.',
  entrypoint=['/app'],
  dockerfile='./dev/Dockerfile',
  only=['./build'],
  live_update=[
    sync('./build/app', '/app'),
  ],
)

# allow_k8s_contexts(k8s_context())
context = os.getenv('TILT_K8S_CONTEXT')
allow_k8s_contexts(context)

k8s_yaml('dev/kubernetes.yaml')
k8s_resource(
  workload='dynatrace-kube-hunter-ingester', 
  port_forwards=8080,
  resource_deps=['app-compile']
)