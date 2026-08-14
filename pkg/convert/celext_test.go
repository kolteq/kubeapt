// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"reflect"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

// names reduces findings to their extension names for readable assertions.
func names(found []convert.KyvernoCELExtension) []string {
	var out []string
	for _, extension := range found {
		out = append(out, extension.Name)
	}
	return out
}

// TestDetectKyvernoCELExtensionsTableCoverage exercises one expression per
// table entry, so a new entry without a test fails here.
func TestDetectKyvernoCELExtensionsTableCoverage(t *testing.T) {
	expressions := map[string]string{
		"resource.Get":        `resource.Get("v1", "configmaps", "default", "settings").data.mode == "strict"`,
		"resource.List":       `size(resource.List("apps/v1", "deployments", "").items) > 0`,
		"resource.Post":       `resource.Post("authorization.k8s.io/v1", "subjectaccessreviews", {}).status.allowed`,
		"http.Get":            `http.Get("https://example.internal/health").ok`,
		"http.Post":           `http.Post("https://example.internal/log", {}).ok`,
		"http.Client":         `http.Client("ca").Get("https://example.internal").ok`,
		"globalContext.Get":   `globalContext.Get("deployments", "").exists`,
		"image.GetMetadata":   `image.GetMetadata(object.spec.containers[0].image).os == "linux"`,
		"image":               `image(object.spec.containers[0].image).registry == "ghcr.io"`,
		"isImage":             `isImage(object.spec.containers[0].image)`,
		"parseServiceAccount": `parseServiceAccount(request.userInfo.username).Name == "builder"`,
		"x509.decode":         `x509.decode(object.data.crt).Subject.CommonName == "internal"`,
		"json.unmarshal":      `json.unmarshal(object.data.config).enabled`,
		"yaml.parse":          `yaml.parse(object.data.values).replicas > 1`,
		"time.now":            `time.now().getHours() < 18`,
		"time.truncate":       `time.truncate(time.now(), duration("1h")) == object.spec.window`,
		"time.toCron":         `time.toCron(object.spec.at) == "0 * * * *"`,
		"md5":                 `md5(object.metadata.name) == object.metadata.labels.hash`,
		"sha1":                `sha1(object.metadata.name) != ""`,
		"sha256":              `sha256(object.metadata.name) != ""`,
		"random":              `random("[a-z]{5}") != ""`,
		"listObjToMap":        `size(listObjToMap(object.spec.ports, "name", "port")) > 0`,
		"math.round":          `math.round(object.spec.ratio) == 1`,
	}

	if len(expressions) != len(convert.KyvernoCELExtensions) {
		t.Fatalf("table has %d entries but the test covers %d; add the missing expression",
			len(convert.KyvernoCELExtensions), len(expressions))
	}

	for _, extension := range convert.KyvernoCELExtensions {
		t.Run(extension.Name, func(t *testing.T) {
			expr, ok := expressions[extension.Name]
			if !ok {
				t.Fatalf("no expression covers %s", extension.Name)
			}
			found := names(convert.DetectKyvernoCELExtensions(expr))
			if len(found) == 0 {
				t.Fatalf("expression %q did not flag %s", expr, extension.Name)
			}
			var matched bool
			for _, name := range found {
				if name == extension.Name {
					matched = true
				}
			}
			if !matched {
				t.Errorf("expression %q flagged %v, want %s among them", expr, found, extension.Name)
			}
		})
	}
}

func TestDetectKyvernoCELExtensionsIgnoresStringLiterals(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{name: "single quotes", expr: `object.metadata.name != 'http.Get()'`},
		{name: "double quotes", expr: `object.metadata.name != "resource.Get(x)"`},
		{name: "escaped quote inside", expr: `object.metadata.name != 'it\'s not http.Get()'`},
		{name: "raw string", expr: `object.metadata.name != r'\d image(x)'`},
		{name: "triple quoted", expr: `object.metadata.name != """md5(x) and sha256(y)"""`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if found := convert.DetectKyvernoCELExtensions(tc.expr); found != nil {
				t.Errorf("expression %q flagged %v, want nothing", tc.expr, names(found))
			}
		})
	}
}

func TestDetectKyvernoCELExtensionsRespectsIdentifierBoundaries(t *testing.T) {
	cases := []string{
		`myhttp.Get(x)`,
		`fooimage(x)`,
		`object.image(x)`,
		`resource.GetOwner(x)`,
		`x.md5(y)`,
		`notrandom(y)`,
	}

	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			if found := convert.DetectKyvernoCELExtensions(expr); found != nil {
				t.Errorf("expression %q flagged %v, want nothing", expr, names(found))
			}
		})
	}
}

func TestDetectKyvernoCELExtensionsAllowsWhitespaceBeforeCall(t *testing.T) {
	if found := convert.DetectKyvernoCELExtensions(`md5 (object.metadata.name) != ""`); len(found) != 1 {
		t.Errorf("got %v, want md5", names(found))
	}
}

func TestDetectKyvernoCELExtensionsDedupesAndOrders(t *testing.T) {
	expr := `md5(a) == md5(b) && http.Get(c).ok && resource.Get(d) != null`
	got := names(convert.DetectKyvernoCELExtensions(expr))
	want := []string{"resource.Get", "http.Get", "md5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (table order, deduped)", got, want)
	}
}

func TestDetectKyvernoCELExtensionsEmpty(t *testing.T) {
	if found := convert.DetectKyvernoCELExtensions(""); found != nil {
		t.Errorf("got %v, want nothing", names(found))
	}
	if found := convert.DetectKyvernoCELExtensions(`object.spec.replicas >= 2`); found != nil {
		t.Errorf("plain CEL flagged %v, want nothing", names(found))
	}
}

// TestDetectKyvernoCELExtensionsKeepsValidVAPCEL guards the precision tradeoff:
// upstream ValidatingAdmissionPolicy CEL must never be flagged.
func TestDetectKyvernoCELExtensionsKeepsValidVAPCEL(t *testing.T) {
	cases := []string{
		`quantity(object.spec.limit) < quantity("2Gi")`,
		`authorizer.group("").resource("pods").check("create").allowed()`,
		`sets.contains(object.spec.roles, ["admin"])`,
		`url(object.spec.endpoint).getHostname() == "example.com"`,
		`object.metadata.name.matches("^[a-z]+$")`,
		`ip(object.spec.address).family() == 4`,
	}

	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			if found := convert.DetectKyvernoCELExtensions(expr); found != nil {
				t.Errorf("valid VAP CEL %q flagged %v", expr, names(found))
			}
		})
	}
}

func TestDetectInSpecFieldPaths(t *testing.T) {
	spec := kyverno.ValidatingPolicySpec{
		MatchConditions: []admissionregistrationv1.MatchCondition{
			{Name: "clean", Expression: `request.operation == "CREATE"`},
			{Name: "dirty", Expression: `http.Get("https://x").ok`},
		},
		Variables: []admissionregistrationv1.Variable{
			{Name: "meta", Expression: `image.GetMetadata(object.spec.containers[0].image)`},
		},
		Validations: []admissionregistrationv1.Validation{
			{Expression: `object.spec.replicas >= 2`},
			{Expression: `true`, MessageExpression: `"hash " + sha256(object.metadata.name)`},
			{Expression: `resource.Get("v1", "configmaps", "default", "c").data.ok == "yes"`},
		},
		AuditAnnotations: []admissionregistrationv1.AuditAnnotation{
			{Key: "digest", ValueExpression: `md5(object.metadata.name)`},
		},
	}

	got := convert.DetectInSpec(spec)
	want := []convert.SpecCELFinding{
		{Field: "spec.matchConditions[1].expression", Extension: extensionNamed(t, "http.Get")},
		{Field: "spec.variables[0].expression", Extension: extensionNamed(t, "image.GetMetadata")},
		{Field: "spec.validations[1].messageExpression", Extension: extensionNamed(t, "sha256")},
		{Field: "spec.validations[2].expression", Extension: extensionNamed(t, "resource.Get")},
		{Field: "spec.auditAnnotations[0].valueExpression", Extension: extensionNamed(t, "md5")},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestDetectInSpecClean(t *testing.T) {
	spec := kyverno.ValidatingPolicySpec{
		Validations: []admissionregistrationv1.Validation{{Expression: `object.spec.replicas >= 2`}},
	}
	if got := convert.DetectInSpec(spec); got != nil {
		t.Errorf("got %+v, want nothing", got)
	}
}

func extensionNamed(t *testing.T, name string) convert.KyvernoCELExtension {
	t.Helper()
	for _, extension := range convert.KyvernoCELExtensions {
		if extension.Name == name {
			return extension
		}
	}
	t.Fatalf("no table entry named %s", name)
	return convert.KyvernoCELExtension{}
}
