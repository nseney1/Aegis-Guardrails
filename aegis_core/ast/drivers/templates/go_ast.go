// Aegis's stdlib-only Go AST driver: protocol v2, NormalizedAST schema 1.0.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/scanner"
	"go/token"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxBytes = 8 * 1024 * 1024

var capabilities = []string{"allow_comments", "args"}
var versionSuffix = regexp.MustCompile(`\.v[0-9]+$`)
var allowPattern = regexp.MustCompile(`(?i)^\s*aegis:\s*allow(?:\[([^\]]*)\])?(?:\s*[:\-]?\s*(.*))?$`)

type DefinitionNode struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Line       int    `json:"line"`
	IsExported bool   `json:"is_exported"`
	ClassName  string `json:"class_name,omitempty"`
}

type CallSiteNode struct {
	Target      string            `json:"target"`
	Line        int               `json:"line"`
	CallerScope string            `json:"caller_scope,omitempty"`
	Args        map[string]string `json:"args"`
	Kind        string            `json:"kind,omitempty"`
}

type ImportNode struct {
	Source          string      `json:"source"`
	ImportedSymbols []string    `json:"imported_symbols"`
	Aliases         [][2]string `json:"aliases,omitempty"`
	Line            int         `json:"line"`
}

type MutationPoint struct {
	Line          int    `json:"line"`
	Col           int    `json:"col"`
	OriginalOp    string `json:"original_op"`
	ReplacementOp string `json:"replacement_op"`
	MutationType  string `json:"mutation_type"`
}

type AllowComment struct {
	Rules  []string `json:"rules"`
	Reason string   `json:"reason"`
}

type NormalizedAST struct {
	Version        string           `json:"version"`
	FilePath       string           `json:"file_path"`
	Language       string           `json:"language"`
	Definitions    []DefinitionNode `json:"definitions"`
	CallSites      []CallSiteNode   `json:"call_sites"`
	Imports        []ImportNode     `json:"imports"`
	MutationPoints []MutationPoint  `json:"mutation_points"`
	Metadata       map[string]any   `json:"metadata"`
}

type DriverError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

type Request struct {
	Version int    `json:"aegis_ast"`
	Op      string `json:"op"`
	ID      *int64 `json:"id"`
	Path    string `json:"path"`
}

type Response struct {
	Op    string         `json:"op"`
	ID    int64          `json:"id"`
	OK    bool           `json:"ok"`
	AST   *NormalizedAST `json:"ast,omitempty"`
	Error *DriverError   `json:"error,omitempty"`
}

func main() {
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve() error {
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 64*1024), maxBytes+1)
	hello := false
	for input.Scan() {
		var request Request
		if err := json.Unmarshal(input.Bytes(), &request); err != nil {
			return fmt.Errorf("invalid protocol request: %w", err)
		}
		if !hello {
			if request.Op != "hello" || request.Version != 2 {
				return fmt.Errorf("protocol v2 hello required")
			}
			hello = true
			message := map[string]any{"aegis_ast": 2, "op": "hello", "driver": "go_ast",
				"driver_version": "2.0.0", "languages": []string{"go"}, "capabilities": capabilities}
			if err := writeJSON(message); err != nil {
				return err
			}
			continue
		}
		if request.Op != "parse" || request.ID == nil || *request.ID < 0 || request.Path == "" {
			return fmt.Errorf("invalid parse request")
		}
		norm, parseError := parseFile(request.Path)
		response := Response{Op: "parse", ID: *request.ID, OK: parseError == nil, AST: norm, Error: parseError}
		encoded, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if len(encoded) > maxBytes {
			response = Response{Op: "parse", ID: *request.ID,
				Error: &DriverError{Kind: "limit", Message: "response exceeds 8 MiB"}}
		}
		if err := writeJSON(response); err != nil {
			return err
		}
	}
	return input.Err()
}

func writeJSON(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > maxBytes {
		return fmt.Errorf("response exceeds 8 MiB")
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

func parseFile(filePath string) (*NormalizedAST, *DriverError) {
	if !filepath.IsAbs(filePath) {
		return nil, &DriverError{Kind: "io", Message: "parse path must be absolute"}
	}
	input, err := os.Open(filePath)
	if err != nil {
		return nil, &DriverError{Kind: "io", Message: err.Error()}
	}
	defer input.Close()
	source, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return nil, &DriverError{Kind: "io", Message: err.Error()}
	}
	if len(source) > maxBytes {
		return nil, &DriverError{Kind: "limit", Message: "source exceeds 8 MiB"}
	}
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, filePath, source, parser.ParseComments)
	if err != nil {
		line := 1
		if list, ok := err.(scanner.ErrorList); ok && len(list) > 0 {
			line = list[0].Pos.Line
		}
		return nil, &DriverError{Kind: "syntax", Message: err.Error(), Line: line}
	}
	if invalid := duplicateFields(file, positions); invalid != nil {
		return nil, invalid
	}
	norm := &NormalizedAST{Version: "1.0", FilePath: filePath, Language: "go",
		Definitions: []DefinitionNode{}, CallSites: []CallSiteNode{}, Imports: []ImportNode{},
		MutationPoints: []MutationPoint{}, Metadata: map[string]any{
			"capabilities": capabilities, "allow_comments": allowComments(file, positions)}}
	bindings := extractImports(file, positions, norm)
	ast.Walk(&collector{norm: norm, positions: positions, bindings: bindings}, file)
	return norm, nil
}

func extractImports(file *ast.File, positions *token.FileSet, norm *NormalizedAST) map[string]string {
	bindings := map[string]string{}
	for _, imp := range file.Imports {
		source, _ := strconv.Unquote(imp.Path.Value)
		name := strings.TrimPrefix(strings.TrimSuffix(versionSuffix.ReplaceAllString(path.Base(source), ""), "-go"), "go-")
		if imp.Name != nil {
			name = imp.Name.Name
		}
		node := ImportNode{Source: source, ImportedSymbols: []string{}, Line: positions.Position(imp.Pos()).Line}
		if name != "_" && name != "." {
			bindings[name] = source
			node.ImportedSymbols = append(node.ImportedSymbols, name)
			node.Aliases = append(node.Aliases, [2]string{name, source})
		}
		norm.Imports = append(norm.Imports, node)
	}
	return bindings
}

func allowComments(file *ast.File, positions *token.FileSet) map[int][]AllowComment {
	allows := map[int][]AllowComment{}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			text := strings.TrimPrefix(strings.TrimPrefix(comment.Text, "//"), "/*")
			text = strings.TrimSuffix(text, "*/")
			for offset, part := range strings.Split(text, "\n") {
				part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "*"))
				match := allowPattern.FindStringSubmatch(part)
				if match == nil {
					continue
				}
				var rules []string
				if allowPattern.FindStringSubmatchIndex(part)[2] >= 0 {
					rules = []string{}
					seen := map[string]bool{}
					for _, value := range strings.Split(match[1], ",") {
						value = strings.TrimSpace(value)
						if value != "" && !seen[value] {
							rules = append(rules, value)
							seen[value] = true
						}
					}
					sort.Strings(rules)
				}
				line := positions.Position(comment.Pos()).Line + offset
				allows[line] = append(allows[line], AllowComment{Rules: rules, Reason: strings.TrimSpace(match[2])})
			}
		}
	}
	return allows
}

func duplicateFields(file *ast.File, positions *token.FileSet) *DriverError {
	var invalid *DriverError
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok || invalid != nil {
			return invalid == nil
		}
		seen := map[string]bool{}
		_, isMap := literal.Type.(*ast.MapType)
		_, isArray := literal.Type.(*ast.ArrayType)
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key := renderLiteral(field.Key)
			if name, ok := field.Key.(*ast.Ident); ok && !isMap && !isArray {
				key = "name:" + name.Name
			}
			if key == "<expr>" {
				continue
			}
			if seen[key] {
				invalid = &DriverError{Kind: "syntax", Message: "duplicate composite literal field: " + key,
					Line: positions.Position(field.Pos()).Line}
				return false
			}
			seen[key] = true
		}
		return true
	})
	return invalid
}

type collector struct {
	norm      *NormalizedAST
	positions *token.FileSet
	bindings  map[string]string
	scope     string
}

func (c *collector) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}
	switch item := node.(type) {
	case *ast.FuncDecl:
		kind, class := "function", ""
		if item.Recv != nil {
			kind = "method"
			if len(item.Recv.List) > 0 {
				class = receiverName(item.Recv.List[0].Type)
			}
		}
		c.norm.Definitions = append(c.norm.Definitions, DefinitionNode{Name: item.Name.Name, Kind: kind,
			Line: c.positions.Position(item.Pos()).Line, IsExported: item.Name.IsExported(), ClassName: class})
		child := *c
		child.scope = item.Name.Name
		ast.Walk(&child, item.Type)
		if item.Body != nil {
			ast.Walk(&child, item.Body)
		}
		return nil
	case *ast.TypeSpec:
		c.norm.Definitions = append(c.norm.Definitions, DefinitionNode{Name: item.Name.Name, Kind: "type",
			Line: c.positions.Position(item.Pos()).Line, IsExported: item.Name.IsExported()})
	case *ast.CallExpr:
		if target := c.target(item.Fun); target != "" {
			c.norm.CallSites = append(c.norm.CallSites, CallSiteNode{Target: target,
				Line: c.positions.Position(item.Pos()).Line, CallerScope: c.scope, Args: callArgs(item)})
		}
	case *ast.CompositeLit:
		if target := c.target(item.Type); target != "" {
			c.norm.CallSites = append(c.norm.CallSites, CallSiteNode{Target: target, Kind: "construct",
				Line: c.positions.Position(item.Pos()).Line, CallerScope: c.scope, Args: compositeFields(item)})
		}
	case *ast.BinaryExpr:
		if replacement, kind := mutation(item.Op); replacement != "" {
			position := c.positions.Position(item.OpPos)
			c.norm.MutationPoints = append(c.norm.MutationPoints, MutationPoint{Line: position.Line,
				Col: position.Column - 1, OriginalOp: item.Op.String(), ReplacementOp: replacement, MutationType: kind})
		}
	}
	return c
}

func receiverName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return receiverName(value.X)
	case *ast.IndexExpr:
		return receiverName(value.X)
	case *ast.IndexListExpr:
		return receiverName(value.X)
	}
	return ""
}

func (c *collector) target(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		if source, bound := c.importedPath(value.X); bound {
			return source + "." + value.Sel.Name
		}
		return "." + value.Sel.Name
	case *ast.ParenExpr:
		return c.target(value.X)
	case *ast.IndexExpr:
		return c.target(value.X)
	case *ast.IndexListExpr:
		return c.target(value.X)
	}
	return ""
}

func (c *collector) importedPath(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.Ident:
		if value.Obj == nil {
			source, bound := c.bindings[value.Name]
			return source, bound
		}
	case *ast.SelectorExpr:
		if source, bound := c.importedPath(value.X); bound {
			return source + "." + value.Sel.Name, true
		}
	case *ast.ParenExpr:
		return c.importedPath(value.X)
	case *ast.IndexExpr:
		return c.importedPath(value.X)
	case *ast.IndexListExpr:
		return c.importedPath(value.X)
	}
	return "", false
}

func callArgs(call *ast.CallExpr) map[string]string {
	args := map[string]string{}
	for index, argument := range call.Args {
		args["#"+strconv.Itoa(index)] = renderLiteral(argument)
		if literal := compositeArgument(argument); literal != nil {
			for name, value := range compositeFields(literal) {
				if _, exists := args[name]; exists {
					args[name] = "<expr>"
				} else {
					args[name] = value
				}
			}
		}
	}
	if call.Ellipsis.IsValid() {
		args["*"] = "<expr>"
	}
	return args
}

func compositeArgument(expr ast.Expr) *ast.CompositeLit {
	switch value := expr.(type) {
	case *ast.CompositeLit:
		return value
	case *ast.ParenExpr:
		return compositeArgument(value.X)
	case *ast.UnaryExpr:
		if value.Op == token.AND {
			return compositeArgument(value.X)
		}
	}
	return nil
}

func compositeFields(literal *ast.CompositeLit) map[string]string {
	fields := map[string]string{}
	_, isMap := literal.Type.(*ast.MapType)
	_, isArray := literal.Type.(*ast.ArrayType)
	for _, element := range literal.Elts {
		pair, keyed := element.(*ast.KeyValueExpr)
		if keyed && !isMap && !isArray {
			if name, ok := pair.Key.(*ast.Ident); ok {
				fields[name.Name] = renderLiteral(pair.Value)
				continue
			}
		}
		fields["**"] = "<expr>"
	}
	return fields
}

func renderLiteral(expr ast.Expr) string {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return renderLiteral(paren.X)
	}
	if name, ok := expr.(*ast.Ident); ok && name.Obj == nil {
		switch name.Name {
		case "true":
			return "True"
		case "false":
			return "False"
		case "nil":
			return "None"
		}
	}
	if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
		value, err := strconv.Unquote(literal.Value)
		if err == nil && utf8.ValidString(value) {
			return pythonString(value)
		}
		return "<expr>"
	}
	value := numericValue(expr)
	switch value.Kind() {
	case constant.Int:
		return value.ExactString()
	case constant.Float:
		if number, exact := constant.Float64Val(value); exact && !math.IsInf(number, 0) && !math.IsNaN(number) {
			return strconv.FormatFloat(number, 'g', -1, 64)
		}
	}
	return "<expr>"
}

func pythonString(value string) string {
	quote := '\''
	if strings.ContainsRune(value, '\'') && !strings.ContainsRune(value, '"') {
		quote = '"'
	}
	var out strings.Builder
	out.WriteRune(quote)
	for _, character := range value {
		switch character {
		case '\\', quote:
			out.WriteByte('\\')
			out.WriteRune(character)
		case '\t':
			out.WriteString("\\t")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		default:
			if unicode.IsPrint(character) && (character == ' ' || !unicode.Is(unicode.Zs, character)) {
				out.WriteRune(character)
			} else if character < 0x100 {
				fmt.Fprintf(&out, "\\x%02x", character)
			} else if character < 0x10000 {
				fmt.Fprintf(&out, "\\u%04x", character)
			} else {
				fmt.Fprintf(&out, "\\U%08x", character)
			}
		}
	}
	out.WriteRune(quote)
	return out.String()
}

func numericValue(expr ast.Expr) constant.Value {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind == token.INT || value.Kind == token.FLOAT || value.Kind == token.CHAR {
			return constant.MakeFromLiteral(value.Value, value.Kind, 0)
		}
	case *ast.ParenExpr:
		return numericValue(value.X)
	case *ast.UnaryExpr:
		if value.Op == token.ADD || value.Op == token.SUB {
			inner := numericValue(value.X)
			if inner.Kind() == constant.Int || inner.Kind() == constant.Float {
				return constant.UnaryOp(value.Op, inner, 0)
			}
		}
	}
	return constant.MakeUnknown()
}

func mutation(operator token.Token) (string, string) {
	switch operator {
	case token.EQL:
		return "!=", "cmpop"
	case token.NEQ:
		return "==", "cmpop"
	case token.LSS:
		return ">", "cmpop"
	case token.GTR:
		return "<", "cmpop"
	case token.LEQ:
		return ">=", "cmpop"
	case token.GEQ:
		return "<=", "cmpop"
	case token.LAND:
		return "||", "boolop"
	case token.LOR:
		return "&&", "boolop"
	case token.ADD:
		return "-", "binop"
	case token.SUB:
		return "+", "binop"
	case token.MUL:
		return "/", "binop"
	case token.QUO:
		return "*", "binop"
	}
	return "", ""
}
