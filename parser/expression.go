package main

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

var (
	exprRegex = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)
	shaRegex  = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// ExtractExpressions finds all ${{ ... }} expressions in a string and extracts their context and location
func ExtractExpressions(input string, location string) []ExpressionInfo {
	if input == "" {
		return nil
	}

	matches := exprRegex.FindAllStringSubmatch(input, -1)
	if len(matches) == 0 {
		return nil
	}

	results := make([]ExpressionInfo, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		innerExpr := strings.TrimSpace(match[1])
		info := parseSingleExpression(innerExpr, location)
		results = append(results, info)
	}

	return results
}

// parseSingleExpression parses the inner expression text using actionlint's ExprParser
func parseSingleExpression(inner, location string) ExpressionInfo {
	info := ExpressionInfo{
		Location: location,
	}

	lexer := actionlint.NewExprLexer(inner + " }}")
	parser := actionlint.NewExprParser()
	node, err := parser.Parse(lexer)
	if err != nil || node == nil {
		info.Context = strings.TrimSpace(inner)
		return info
	}

	ctx := extractContextFromNode(node)
	if ctx != "" {
		info.Context = ctx
	} else {
		info.Context = strings.TrimSpace(inner)
	}

	return info
}

func extractContextFromNode(node actionlint.ExprNode) string {
	if node == nil {
		return ""
	}

	switch n := node.(type) {
	case *actionlint.VariableNode:
		return n.Name
	case *actionlint.ObjectDerefNode:
		return collectDerefChain(n)
	case *actionlint.IndexAccessNode:
		prefix := extractContextFromNode(n.Operand)
		if strIdx, ok := n.Index.(*actionlint.StringNode); ok {
			if prefix != "" {
				return prefix + "." + strIdx.Value
			}
			return strIdx.Value
		}
		return prefix
	case *actionlint.FuncCallNode:
		for _, arg := range n.Args {
			if ctx := extractContextFromNode(arg); ctx != "" {
				return ctx
			}
		}
	case *actionlint.CompareOpNode:
		return extractContextFromNode(n.Left)
	case *actionlint.LogicalOpNode:
		return extractContextFromNode(n.Left)
	case *actionlint.NotOpNode:
		return extractContextFromNode(n.Operand)
	}

	return ""
}

// collectDerefChain walks an ObjectDerefNode backwards to construct the full context string
func collectDerefChain(node *actionlint.ObjectDerefNode) string {
	var props []string
	curr := node

	for curr != nil {
		props = append([]string{curr.Property}, props...)
		switch recv := curr.Receiver.(type) {
		case *actionlint.ObjectDerefNode:
			curr = recv
		case *actionlint.VariableNode:
			return recv.Name + "." + strings.Join(props, ".")
		case *actionlint.IndexAccessNode:
			if strIdx, ok := recv.Index.(*actionlint.StringNode); ok {
				props = append([]string{strIdx.Value}, props...)
			}
			if varNode, ok := recv.Operand.(*actionlint.VariableNode); ok {
				return varNode.Name + "." + strings.Join(props, ".")
			}
			return strings.Join(props, ".")
		default:
			return strings.Join(props, ".")
		}
	}

	return strings.Join(props, ".")
}

// ParseActionReference parses a "uses:" string into owner, repo, ref and SHA status
func ParseActionReference(raw string) *ActionRef {
	if raw == "" {
		return nil
	}

	ref := &ActionRef{
		Raw: raw,
	}

	atIdx := strings.LastIndex(raw, "@")
	var repoPart, verPart string
	if atIdx != -1 {
		repoPart = raw[:atIdx]
		verPart = raw[atIdx+1:]
		ref.Ref = verPart
		ref.IsSHA = shaRegex.MatchString(verPart)
	} else {
		repoPart = raw
	}

	slashParts := strings.Split(repoPart, "/")
	if len(slashParts) >= 2 {
		ref.Owner = slashParts[0]
		ref.Repo = slashParts[1]
	}

	return ref
}
