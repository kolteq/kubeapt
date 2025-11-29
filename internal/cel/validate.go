// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cel

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

func Check(celExpr string, payload map[string]any) (bool, error) {
	val, err := Evaluate(celExpr, payload)
	if err != nil {
		return false, err
	}
	boolResult, ok := val.(bool)
	if !ok {
		return false, ErrNonBooleanResult
	}
	return boolResult, nil
}

var ErrNonBooleanResult = fmt.Errorf("expression did not return a boolean")

func Evaluate(expr string, payload map[string]any) (interface{}, error) {
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("params", cel.DynType),
		cel.Variable("namespaceObject", cel.DynType),
		cel.Variable("variables", cel.DynType),
		cel.Variable("resource", cel.DynType),
		ext.Strings(),
	)
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	result, _, err := prg.Eval(payload)
	if err != nil {
		return nil, err
	}
	return result.Value(), nil
}
