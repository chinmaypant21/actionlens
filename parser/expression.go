package main

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

var (
	// Matches ${{ ... }}
	expressionPattern = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

	// 40-character commit SHA.
	commitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// ExtractExpressions find ${{ ... }} expression  in text,
// and the field it came from (e.g. "run", "if", "env.TOKEN", "with.script").
func ExtractExpressions(text string, location string) []ExpressionInfo {
	if text == "" {
		return nil
	}

	matches := expressionPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}

	expressions := make([]ExpressionInfo, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		inside := strings.TrimSpace(match[1])
		expressions = append(expressions, parseExpression(inside, location))
	}

	return expressions
}

// ParseActionReference splits a "uses: actions/checkout@v4" type string
// into owner, repo and ref, and checks whether the ref is a commit SHA.
func ParseActionReference(uses string) *ActionRef {
	if uses == "" {
		return nil
	}

	action := &ActionRef{Raw: uses}

	repoPath := uses
	if at := strings.LastIndex(uses, "@"); at != -1 {
		repoPath = uses[:at]
		action.Ref = uses[at+1:]
		action.IsSHA = commitSHAPattern.MatchString(action.Ref)
	}

	// For "owner/repo/sub/path" only the first two parts are kept.
	parts := strings.Split(repoPath, "/")
	if len(parts) >= 2 {
		action.Owner = parts[0]
		action.Repo = parts[1]
	}

	return action
}

// parseExpression runs actionlint's expression parser on the text inside ${{ }}
// and pulls out the context like github.event.issue.title
// Note: If parsing fails or no context is found, the raw text is kept instead.
func parseExpression(inside, location string) ExpressionInfo {
	info := ExpressionInfo{Location: location}

	// actionlint's lexer expects the closing "}}", so add it back.
	lexer := actionlint.NewExprLexer(inside + " }}")
	tree, err := actionlint.NewExprParser().Parse(lexer)
	if err != nil || tree == nil {
		info.Context = strings.TrimSpace(inside)
		return info
	}

	info.Context = contextPath(tree)
	if info.Context == "" {
		info.Context = strings.TrimSpace(inside)
	}

	return info
}

// contextPath returns the first context path used in an expression.
// For comparisons and logical operators only the left side is checked,
// and for function calls the first argument that has one.
func contextPath(node actionlint.ExprNode) string {
	if node == nil {
		return ""
	}

	switch n := node.(type) {
	case *actionlint.VariableNode: // github
		return n.Name
	case *actionlint.ObjectDerefNode: // github.event.issue.title
		return derefPath(n)
	case *actionlint.IndexAccessNode: // github.event['issue']
		base := contextPath(n.Operand)
		if key, ok := n.Index.(*actionlint.StringNode); ok {
			if base != "" {
				return base + "." + key.Value
			}
			return key.Value
		}
		return base
	case *actionlint.FuncCallNode: // contains(github.event.issue.title, 'bug')
		for _, arg := range n.Args {
			if path := contextPath(arg); path != "" {
				return path
			}
		}
	case *actionlint.CompareOpNode:
		return contextPath(n.Left)
	case *actionlint.LogicalOpNode:
		return contextPath(n.Left)
	case *actionlint.NotOpNode:
		return contextPath(n.Operand)
	}

	return ""
}

// derefPath rebuilds a dotted path like "github.event.issue.title" by walking
// from the last property back to the variable it starts from.
func derefPath(node *actionlint.ObjectDerefNode) string {
	var parts []string
	current := node

	for current != nil {
		parts = append([]string{current.Property}, parts...)
		switch receiver := current.Receiver.(type) {
		case *actionlint.ObjectDerefNode:
			current = receiver
		case *actionlint.VariableNode:
			return receiver.Name + "." + strings.Join(parts, ".")
		case *actionlint.IndexAccessNode:
			if key, ok := receiver.Index.(*actionlint.StringNode); ok {
				parts = append([]string{key.Value}, parts...)
			}
			if variable, ok := receiver.Operand.(*actionlint.VariableNode); ok {
				return variable.Name + "." + strings.Join(parts, ".")
			}
			return strings.Join(parts, ".")
		default:
			return strings.Join(parts, ".")
		}
	}

	return strings.Join(parts, ".")
}
