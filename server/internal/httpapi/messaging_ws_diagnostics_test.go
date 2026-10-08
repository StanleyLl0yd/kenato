package httpapi

import (
    "go/ast"
    "go/parser"
    "go/token"
    "strconv"
    "testing"
)

// Every emitted WSS diagnostic must be a static stage code, not request-derived
// text, an exception, an identity, a header or other secret-bearing value.
func TestMessagingWssDiagnosticsHaveOnlyLiteralCodes(t *testing.T) {
    parsed, err := parser.ParseFile(token.NewFileSet(), "messaging_ws.go", nil, 0)
    if err != nil {
        t.Fatal(err)
    }
    found := 0
    ast.Inspect(parsed, func(node ast.Node) bool {
        call, ok := node.(*ast.CallExpr)
        if !ok {
            return true
        }
        name, ok := call.Fun.(*ast.Ident)
        if !ok || name.Name != "logMessagingWssDiagnostic" {
            return true
        }
        found++
        if len(call.Args) != 2 {
            t.Errorf("WSS diagnostic requires exactly two constant codes")
            return true
        }
        for _, arg := range call.Args {
            literal, ok := arg.(*ast.BasicLit)
            if !ok || literal.Kind != token.STRING {
                t.Errorf("WSS diagnostics cannot contain dynamic expressions")
                continue
            }
            value, err := strconv.Unquote(literal.Value)
            if err != nil || len(value) == 0 || len(value) > 64 {
                t.Errorf("WSS diagnostic code is invalid")
                continue
            }
            for _, r := range value {
                if (r < 'a' || r > 'z') && r != '_' {
                    t.Errorf("WSS diagnostic code must be lowercase ASCII words")
                    break
                }
            }
        }
        return true
    })
    if found < 4 {
        t.Fatalf("expected WSS auth and error-stage diagnostics, got %d", found)
    }
}
