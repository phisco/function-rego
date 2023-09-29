package main

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/json"

	"github.com/crossplane/crossplane-runtime/pkg/errors"
	"github.com/crossplane/crossplane-runtime/pkg/logging"

	fnv1beta1 "github.com/crossplane/function-sdk-go/proto/v1beta1"
	"github.com/crossplane/function-sdk-go/request"
	"github.com/crossplane/function-sdk-go/response"

	"github.com/crossplane/function-rego/input/v1beta1"
)

// Function returns whatever response you ask it to.
type Function struct {
	fnv1beta1.UnimplementedFunctionRunnerServiceServer

	log logging.Logger
}

type queryInput struct {
	Request  *fnv1beta1.RunFunctionRequest  `json:"request"`
	Response *fnv1beta1.RunFunctionResponse `json:"response"`
}

// RunFunction runs the Function.
func (f *Function) RunFunction(ctx context.Context, req *fnv1beta1.RunFunctionRequest) (*fnv1beta1.RunFunctionResponse, error) {
	f.log.Info("Running Function", "tag", req.GetMeta().GetTag())

	// This creates a new response to the supplied request. Note that Functions
	// are run in a pipeline! Other Functions may have run before this one. If
	// they did, response.To will copy their desired state from req to rsp. Be
	// sure to pass through any desired state your Function is not concerned
	// with unmodified.
	rsp := response.To(req, response.DefaultTTL)
	meta := rsp.GetMeta()
	rsp.Meta = nil
	defer func() { rsp.Meta = meta }()

	// Input is supplied by the author of a Composition when they choose to run
	// your Function. Input is arbitrary, except that it must be a KRM-like
	// object. Supporting input is also optional - if you don't need to you can
	// delete this, and delete the input directory.
	in := &v1beta1.Input{}
	if err := request.GetInput(req, in); err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot get Function input from %T", req))
		return rsp, nil
	}

	if len(in.Spec.Scripts) == 0 {
		response.Fatal(rsp, errors.New("no scripts supplied"))
		return rsp, nil
	}

	opts := []func(*rego.Rego){
		rego.Query("response = data.crossplane.response"),
	}
	for n, s := range in.Spec.Scripts {
		opts = append(opts, rego.Module(n, s))
	}

	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot prepare rego query"))
		return rsp, nil
	}

	rs, err := q.Eval(ctx, rego.EvalInput(queryInput{Request: req, Response: rsp}))

	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot evaluate rego query"))
		return rsp, nil
	}

	if len(rs) != 1 {
		response.Fatal(rsp, errors.Errorf("expected a single result from rego query, got %d", len(rs)))
		return rsp, nil
	}

	resp := rs[0].Bindings["response"]
	out, err := json.Marshal(resp)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot marshal rego result"))
		return rsp, nil
	}
	if err := protojson.Unmarshal(out, rsp); err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot unmarshal rego result into RunFunctionResponse: %s", out))
		return rsp, nil
	}

	return rsp, nil
}
