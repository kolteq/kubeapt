package cel

import "testing"

func TestEvaluateAndCheck(t *testing.T) {
    payload := map[string]any{
        "object": map[string]any{"name": "demo"},
    }

    val, err := Evaluate("object.name", payload)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if val.(string) != "demo" {
        t.Fatalf("unexpected value: %v", val)
    }

    ok, err := Check("object.name == 'demo'", payload)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !ok {
        t.Fatalf("expected expression to be true")
    }
}

func TestCheckNonBoolean(t *testing.T) {
    payload := map[string]any{}
    _, err := Check("1 + 2", payload)
    if err == nil {
        t.Fatalf("expected error")
    }
    if err != ErrNonBooleanResult {
        t.Fatalf("expected ErrNonBooleanResult, got %v", err)
    }
}

func TestEvaluateInvalidExpression(t *testing.T) {
    payload := map[string]any{}
    if _, err := Evaluate("1 + ", payload); err == nil {
        t.Fatalf("expected compile error")
    }
}
