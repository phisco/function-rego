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
		"FataIfNoInputScripts": {
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
		"NormalSeverityWithScript": {
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

results = [
		{"severity": "SEVERITY_NORMAL", "message": "Hello World!"},
]

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
							Severity: fnv1beta1.Severity_SEVERITY_NORMAL,
							Message:  "Hello World!",
						},
					},
				},
			},
		},
		"FatalIfRuleTrueNoPreviousDesired": {
			reason: "The Function should return a fatal result if the rule is true, without a previous desired state",
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
	not input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"]
} 

# METADATA
# title: Deny illegal composite resources even if patched
# description: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
# custom:
#  severity: SEVERITY_FATAL
results[formatResult(rego.metadata.rule())] {
	input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
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
		"FatalIfRuleTrueWithPreviousDesired": {
			reason: "The Function should properly return desired resources, even on fatal",
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
	not input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"]
} {
	input.request.observed.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
	input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
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
		"NoFatalIfRuleFalseWithPreviousDesired": {
			reason: "The Function should properly no result if the rule is false, with a previous desired state",
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
	not input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"]
} 

# METADATA
# title: Deny illegal composite resources even if patched
# description: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
# custom:
#  severity: SEVERITY_FATAL
results[formatResult(rego.metadata.rule())] {
	input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
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
		"FatalIfRuleTrueDueToDesired": {
			reason: "The function should return fatal even if the rule is true due to the desired state only",
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
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
									"metadata": {
										"annotations": {
											"dummy.fn.crossplane.io/illegal": "true"
										}
									}
								}`),
						},
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
	not input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"]
} 

# METADATA
# title: Deny illegal composite resources even if patched
# description: Composite resources with the annotation dummy.fn.crossplane.io/illegal set to true are not allowed
# custom:
#  severity: SEVERITY_FATAL
results[formatResult(rego.metadata.rule())] {
	input.request.desired.composite.resource.metadata.annotations["dummy.fn.crossplane.io/illegal"] == "true"
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
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
									"metadata": {
										"annotations": {
											"dummy.fn.crossplane.io/illegal": "true"
										}
									}
								}`),
						},
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
		"ShouldBeAbleToPatchDesiredState": {
			reason: "The function should be able to patch the desired state preserving the input one",
			args: args{
				ctx: context.Background(),
				req: &fnv1beta1.RunFunctionRequest{
					Meta: &fnv1beta1.RequestMeta{Tag: "hello"},
					Observed: &fnv1beta1.State{
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
										"spec":
											{
												"specFoo": "specBar"
											}
										}`),
						},
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
					Desired: &fnv1beta1.State{
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
					Input: resource.MustStructObject(
						&v1beta1.Input{
							Spec: v1beta1.InputSpec{
								Scripts: map[string]string{
									"hello.rego": `
package crossplane

import future.keywords.if

names[name] {
	input.request.desired.resources[name]
} {
	input.request.observed.resources[name]
}

resources := { key : {"resource": {"metadata": {"annotations": {"dummy.fn.crossplane.io/specFoo": "specBar"}}}} | key := names[_]}

patch := { 
	"desired": {
		"resources": resources,
		"composite": {
			"resource": {
				"metadata": {
					"annotations": {
						"dummy.fn.crossplane.io/specFoo": "specBar"
					},
				},
			},
		},
    },
}

response := object.union(input.response, patch) if input.request.observed.composite.resource.spec.specFoo == "specBar" else := input.response
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
						Composite: &fnv1beta1.Resource{
							Resource: resource.MustStructJSON(`{
											"metadata": {
												"annotations": {
													"dummy.fn.crossplane.io/illegal": "false",
													"dummy.fn.crossplane.io/specFoo": "specBar"
												}
											}
										}`),
						},
						Resources: map[string]*fnv1beta1.Resource{
							"foo": {
								Resource: resource.MustStructJSON(`{
											"metadata": {
												"annotations": {
													"dummy.fn.crossplane.io/specFoo": "specBar"
												}
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
