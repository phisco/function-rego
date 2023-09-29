# function-rego

A [Crossplane] Composition Function to run
[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies.

## What is this?

Here's an example of a Composition that uses this Composition Function.

```yaml
apiVersion: apiextensions.crossplane.io/v1
kind: Composition
metadata:
  name: test-crossplane
spec:
  compositeTypeRef:
    apiVersion: database.example.com/v1alpha1
    kind: NoSQL
  mode: Pipeline
  pipeline:
  - step: checkEverythingIsLegal
    functionRef:
      name: function-rego
    input:
      apiVersion: rego.fn.crossplane.io/v1beta1
      kind: Input
      spec:
        policy: |
          package crossplane

          results = [
            {"severity": "SEVERITY_NORMAL", "message": "Hello World!"},
          ]

          response = object.union(input.response, {"results": results})
```

## Developing a Function

This template doesn't use the typical Crossplane build submodule and Makefile,
since we'd like Functions to have a less heavyweight developer experience.
It mostly relies on regular old Go tools:

```shell
# Run code generation - see input/generate.go
$ go generate ./...

# Run tests
$ go test -cover ./...
?       github.com/crossplane/function-rego/input/v1beta1      [no test files]
ok      github.com/crossplane/function-rego    0.006s  coverage: 25.8% of statements

# Lint the code
$ docker run --rm -v $(pwd):/app -v ~/.cache/golangci-lint/v1.54.2:/root/.cache -w /app golangci/golangci-lint:v1.54.2 golangci-lint run

# Build a Docker image - see Dockerfile
$ docker build .
```

This Function can be pushed to any Docker registry. To push to xpkg.upbound.io
use `docker push` and `docker-credential-up` from
https://github.com/upbound/up/.

To turn this template into a working Function, the process is:

1. Replace `function-rego` with your Function's name in
   `package/crossplane.yaml`, `go.mod`, and any Go imports
1. Update `input/v1beta1/input.go` to reflect your desired input
1. Run `go generate ./...`
1. Add your Function logic to `RunFunction` in `fn.go`
1. Add tests for your Function logic in `fn_test.go`
1. Update this file, `README.md`, to be about your Function!

## Testing a Function

You can try your function out locally using [`xrender`][xrender]. With `xrender`
you can run a Function pipeline on your laptop.

First you'll need to create a `functions.yaml` file. This tells `xrender` what
Functions to run, and how. In this case we want to run the Function you're
developing in 'Development mode'. That pretty much means you'll run the Function
manually and tell `xrender` where to find it.

```yaml
---
apiVersion: pkg.crossplane.io/v1beta1
kind: Function
metadata:
  name: function-rego
  annotations:
    # xrender will try to talk to your Function at localhost:9443
    xrender.crossplane.io/runtime: Development
    xrender.crossplane.io/runtime-development-target: localhost:9443
```

Next, run your Function locally:

```shell
# Run your Function in insecure mode
go run . --insecure --debug
```

Once your Function is running, in another window you can use `xrender`.

```shell
# Install xrender
$ go install github.com/crossplane-contrib/xrender@latest

# Run it! See the xrender repo for these examples.
$ xrender examples/xr.yaml examples/composition.yaml examples/functions.yaml
xrender: error: main.CLI.Run(): cannot render composite resource: pipeline step "checkEverythingIsLegal" returned a fatal result: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
```

You can see an example Composition above. There's also some examples in the
`xrender` repo's examples directory.

## Pushing a Function

Once you feel your Function is ready, use `docker build`, `docker tag`, and
`docker push`to push it. Remember to use `docker-credential-up` (see above) if
you want to push to `xpkg.upbound.io`!

## Tips and Tricks for Writing Functions

In no particular order, here's some things to keep in mind when writing a
Function.

### Take a look at function-sdk-go

* https://github.com/crossplane/function-sdk-go
* https://pkg.go.dev/github.com/crossplane/function-sdk-go

`function-sdk-go` is an MVP SDK for building Functions. Its API is early, and
will almost certainly change! This template uses it. We hope it will help make
writing Functions in Go easier. Eventually we intend to have SDKs for other
languages to (such as Python or TypeScript).

### Understand RunFunctionRequest and RunFunctionResponse

Behind the scenes, Crossplane will make a gRPC call to run your Function. It
sends a `RunFunctionRequest`, and expects a `RunFunctionResponse`. You can see
[the schema of these types][proto-schema] in `function-sdk-go.` Unlike the
`function-sdk-go` _Go_ API, we think these types are pretty stable and don't
expect to make big changes in future.

Crossplane sends three important things in a `RunFunctionRequest`:

1. The observed state of the XR, and any existing composed resources.
1. The desired state of the XR, and any existing composed resources.
1. The input to your Function (if any), as specified in the Composition.

The `RunFunctionResponse` your Function returns can include two important
things:

 * The desired state, as created or mutated by your Function.
 * An array of results. Crossplane emits these as events, except for Fatal
   results which will immediately stop the pipeline and cause Crossplane to
   return an error.

 ### Always pass through desired state

Keep in mind that Functions are run in a pipeline - they're run in the order
specified in the `pipeline` array of the Composition. Each Function is passed
any desired state accumulated by previous Functions. This means:

* If your Function is the first or only Function in the pipeline, the
  `RunFunctionRequest` will contain no desired state.
* If your Function is not the first Function in the pipeline, the
  `RunFunctionRequest` will contain whatever desired state previous Functions
  produced. __It's important that your Function pass this state through
  unmodified, _unless_ it has opinions about it (i.e. it wants to intentionally
  undo or change desired state produced by a previous Function).__

### Always return your desired state

Let's say your Function wants to create a composed resource like this:

```yaml
apiVersion: example.crossplane.io/v1
kind: CoolResource
spec:
  coolness: 9001
  resourcefulness: 42
```

It's important that your Function return a composed resource just like this
every time it's run. If your Function doesn't return the composed resource at
all, Crossplane will assume it no longer desires it and it will be deleted. The
same if your Function doesn't return a spec field - say `coolness` - Crossplane
will assume it should try to delete this field.

### Only update XR status, and don't update composed resource status

Composition Functions can only update the status of the XR. If you include spec
or metadata for the XR in your desired state, it will be ignored.

Composed resources are the opposite. Composition Functions can only update the
spec and metadata of a composed resource. If you include composed resource
status in your desired state, it will be ignored.

### Remember to tell Crossplane when your composed resources are ready

Crossplane considers an XR to be ready when all composed resources are ready.
Remember to set the `ready` field for each composed resource in your desired
state to let Crossplane know whether they're ready.

### Input is optional

Your Function can take input (from the Composition), but doing so is optional.
If you don't need it, you can just delete the `input` directory. Make sure to
delete the corresponding generated CRD under `package/` too.

### Don't worry about 'Composition machinery'

Your Function doesn't need to worry about Composition machinery. Crossplane will
take care of the following:

* Generating a unique name for all composed resources. You can omit
  `metadata.name` when you return a desired composed resource.
* Tracking which desired composed resources correspond to which existing,
  observed composed resource (using the `crossplane.io/composed-resource-name`
  annotation).
* Managing the `spec.resourceRefs` of the XR.

### Debugging your Function

This template plumbs a logger up to your Function. Any logs you emit will show
up in the Function's pod logs. Look for the Function pod in `crossplane-system`.

You can also use `response.Normal` and `response.Warning` to return results.
Crossplane will emit these results as Kubernetes events, associated with your
XR. Be careful with this! You don't want to emit too many events - try to only
emit events when something changes, not every time your Function is called.

[`grpcurl`][grpcurl] is another handy tool for debugging your Function. With it,
you can `docker run` your Function locally, and send it a `RunFunctionRequest`
in JSON form.

[Crossplane]: https://crossplane.io
[function-design]: https://github.com/crossplane/crossplane/blob/3996f20/design/design-doc-composition-functions.md
[function-pr]: https://github.com/crossplane/crossplane/pull/4500
[new-crossplane-issue]: https://github.com/crossplane/crossplane/issues/new?assignees=&labels=enhancement&projects=&template=feature_request.md
[install-master-docs]: https://docs.crossplane.io/v1.13/software/install/#install-pre-release-crossplane-versions
[proto-schema]: https://github.com/crossplane/function-sdk-go/blob/main/proto/v1beta1/run_function.proto
[grpcurl]: https://github.com/fullstorydev/grpcurl
[xrender]: https://github.com/crossplane-contrib/xrender