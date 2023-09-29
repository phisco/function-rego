package main

import (
	"context"
	"testing"

	"github.com/crossplane/function-rego/input/v1beta1"
	"github.com/crossplane/function-sdk-go"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	fnv1beta1 "github.com/crossplane/function-sdk-go/proto/v1beta1"
	"github.com/crossplane/function-sdk-go/resource"
	"github.com/crossplane/function-sdk-go/response"
)

func TestRunFunction(t *testing.T) {
	log, err := function.NewLogger(true)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	type args struct {
		ctx context.Context
		req *fnv1beta1.RunFunctionRequest
	}
	type want struct {
		rsp *fnv1beta1.RunFunctionResponse
		err error
	}

	cases := map[string]struct {
		reason string
		args   args
		want   want
	}{
		"ResponseIsReturned": {
			reason: "The Function should return a fatal result if no input script was specified",
			args: args{
				ctx: context.Background(),
				req: &fnv1beta1.RunFunctionRequest{
					Meta: &fnv1beta1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "dummy.fn.crossplane.io",
						"kind": "Input"
					}`),
				},
			},
			want: want{
				rsp: &fnv1beta1.RunFunctionResponse{
					Meta: &fnv1beta1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(response.DefaultTTL)},
					Results: []*fnv1beta1.Result{
						{
							Severity: fnv1beta1.Severity_SEVERITY_FATAL,
							Message:  "no scripts supplied",
						},
					},
				},
			},
		},
		"ResponseIsReturnedWithScript": {
			reason: "The Function should properly return results with a script",
			args: args{
				ctx: context.Background(),
				req: &fnv1beta1.RunFunctionRequest{
					Meta: &fnv1beta1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructObject(
						&v1beta1.Input{
							Spec: v1beta1.InputSpec{
								Scripts: map[string]string{
									"hello.rego": `
package crossplane

response.results = [
		{"severity": "SEVERITY_NORMAL", "message": "Hello World!"},
]
`,
								},
							},
						}),
				},
			},
			want: want{
				rsp: &fnv1beta1.RunFunctionResponse{
					Meta: &fnv1beta1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(response.DefaultTTL)},
					Results: []*fnv1beta1.Result{
						{
							Severity: fnv1beta1.Severity_SEVERITY_NORMAL,
							Message:  "Hello World!",
						},
					},
				},
			},
		},
		"ResponseIsReturnedWithScriptSettingDesiredResourceShouldBeIgnored": {
			reason: "The Function should properly return desired resources",
			args: args{
				ctx: context.Background(),
				req: &fnv1beta1.RunFunctionRequest{
					Meta: &fnv1beta1.RequestMeta{Tag: "hello"},
					Observed: &fnv1beta1.State{
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
									"metadata": {
										"annotations": {
											"dummy.fn.crossplane.io/illegal": "true"
										}
									}
								}`),
						},
					},
					Input: resource.MustStructObject(
						&v1beta1.Input{
							Spec: v1beta1.InputSpec{
								Scripts: map[string]string{
									"hello.rego": `
package crossplane

import future.keywords.if

formatResult(meta) := {"severity": meta.custom.severity, "message": meta.description}

# METADATA
# title: Deny illegal composite resources
# description: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
# custom:
#  severity: SEVERITY_FATAL
results[formatResult(rego.metadata.rule())] {
	input.request.observed.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
}

response = object.union(input.response, {"results": results})
`,
								},
							},
						}),
				},
			},
			want: want{
				rsp: &fnv1beta1.RunFunctionResponse{
					Meta: &fnv1beta1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(response.DefaultTTL)},
					Results: []*fnv1beta1.Result{
						{
							Severity: fnv1beta1.Severity_SEVERITY_FATAL,
							Message:  "Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed",
						},
					},
				},
			},
		},
		"ResponseIsReturnedWithScriptSettingDesiredResourcePreservingInputDesiredResources": {
			reason: "The Function should properly return desired resources",
			args: args{
				ctx: context.Background(),
				req: &fnv1beta1.RunFunctionRequest{
					Meta: &fnv1beta1.RequestMeta{Tag: "hello"},
					Observed: &fnv1beta1.State{
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
									"metadata": {
										"annotations": {
											"dummy.fn.crossplane.io/illegal": "true"
										}
									}
								}`),
						},
					},
					Desired: &fnv1beta1.State{
						Resources: map[string]*fnv1beta1.Resource{
							"foo": {
								Resource: resource.MustStructJSON(`{
									"metadata": {
										"name": "foo"
									}
								}`),
							},
						},
					},
					Input: resource.MustStructObject(
						&v1beta1.Input{
							Spec: v1beta1.InputSpec{
								Scripts: map[string]string{
									"hello.rego": `
package crossplane

import future.keywords.if

formatResult(meta) := {"severity": meta.custom.severity, "message": meta.description}

# METADATA
# title: Deny illegal composite resources
# description: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
# custom:
#  severity: SEVERITY_FATAL
results[formatResult(rego.metadata.rule())] {
	input.request.observed.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
}

response = object.union(input.response, {"results": results})
`,
								},
							},
						}),
				},
			},
			want: want{
				rsp: &fnv1beta1.RunFunctionResponse{
					Meta: &fnv1beta1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(response.DefaultTTL)},
					Results: []*fnv1beta1.Result{
						{
							Severity: fnv1beta1.Severity_SEVERITY_FATAL,
							Message:  "Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed",
						},
					},
					Desired: &fnv1beta1.State{
						Resources: map[string]*fnv1beta1.Resource{
							"foo": {
								Resource: resource.MustStructJSON(`{
									"metadata": {
										"name": "foo"
									}
								}`),
							},
						},
					},
				},
			},
		},
		"ResponseIsReturnedWithScriptSettingDesiredResourcePreservingInputDesiredResourcesAccept": {
			reason: "The Function should properly return desired resources",
			args: args{
				ctx: context.Background(),
				req: &fnv1beta1.RunFunctionRequest{
					Meta: &fnv1beta1.RequestMeta{Tag: "hello"},
					Observed: &fnv1beta1.State{
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
									"metadata": {
										"annotations": {
											"dummy.fn.crossplane.io/illegal": "false"
										}
									}
								}`),
						},
					},
					Desired: &fnv1beta1.State{
						Resources: map[string]*fnv1beta1.Resource{
							"foo": {
								Resource: resource.MustStructJSON(`{
									"metadata": {
										"name": "foo"
									}
								}`),
							},
						},
					},
					Input: resource.MustStructObject(
						&v1beta1.Input{
							Spec: v1beta1.InputSpec{
								Scripts: map[string]string{
									"hello.rego": `
package crossplane

import future.keywords.if

formatResult(meta) := {"severity": meta.custom.severity, "message": meta.description}

# METADATA
# title: Deny illegal composite resources
# description: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
# custom:
#  severity: SEVERITY_FATAL
results[formatResult(rego.metadata.rule())] {
	input.request.observed.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
}

response = object.union(input.response, {"results": results})
`,
								},
							},
						}),
				},
			},
			want: want{
				rsp: &fnv1beta1.RunFunctionResponse{
					Meta:    &fnv1beta1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(response.DefaultTTL)},
					Results: []*fnv1beta1.Result{},
					Desired: &fnv1beta1.State{
						Resources: map[string]*fnv1beta1.Resource{
							"foo": {
								Resource: resource.MustStructJSON(`{
									"metadata": {
										"name": "foo"
									}
								}`),
							},
						},
					},
				},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &Function{log: log}
			rsp, err := f.RunFunction(tc.args.ctx, tc.args.req)

			if diff := cmp.Diff(tc.want.rsp, rsp, protocmp.Transform()); diff != "" {
				t.Errorf("%s\nf.RunFunction(...): -want rsp, +got rsp:\n%s", tc.reason, diff)
			}

			if diff := cmp.Diff(tc.want.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s\nf.RunFunction(...): -want err, +got err:\n%s", tc.reason, diff)
			}
		})
	}
}
