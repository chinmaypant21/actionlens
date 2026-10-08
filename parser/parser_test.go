package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseWorkflow_ExpressionInjection(t *testing.T) {
	path := filepath.Join("..", "testdata", "vulnerable", "expression_injection.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading testdata: %v", err)
	}

	ast, err := ParseWorkflow(path, content)
	if err != nil {
		t.Fatalf("ParseWorkflow failed: %v", err)
	}

	if ast.Name != "Vulnerable Issue Processor" {
		t.Errorf("expected name 'Vulnerable Issue Processor', got %q", ast.Name)
	}
	if len(ast.Triggers) != 1 || ast.Triggers[0].Event != "issues" {
		t.Fatalf("expected 1 'issues' trigger, got %+v", ast.Triggers)
	}
	if len(ast.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(ast.Jobs))
	}

	job := ast.Jobs[0]
	if len(job.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(job.Steps))
	}

	step := job.Steps[0]
	if step.ExecType != "run" {
		t.Errorf("expected exec_type 'run', got %q", step.ExecType)
	}
	if len(step.Expressions) != 1 {
		t.Fatalf("expected 1 expression, got %d", len(step.Expressions))
	}

	expr := step.Expressions[0]
	if expr.Location != "run" {
		t.Errorf("expected location 'run', got %q", expr.Location)
	}
	if expr.Context != "github.event.issue.title" {
		t.Errorf("expected context 'github.event.issue.title', got %q", expr.Context)
	}
}

func TestParseWorkflow_ExpressionInjectionRemediated(t *testing.T) {
	path := filepath.Join("..", "testdata", "secure", "expression_injection_remediated.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading testdata: %v", err)
	}

	ast, err := ParseWorkflow(path, content)
	if err != nil {
		t.Fatalf("ParseWorkflow failed: %v", err)
	}

	if ast.Permissions == nil || ast.Permissions.Scopes["issues"] != "read" {
		t.Errorf("expected issues:read permission, got %+v", ast.Permissions)
	}

	step := ast.Jobs[0].Steps[0]
	if len(step.Expressions) != 1 {
		t.Fatalf("expected 1 expression, got %d", len(step.Expressions))
	}
	if step.Expressions[0].Location != "env.issue_title" {
		t.Errorf("expected location 'env.issue_title', got %q", step.Expressions[0].Location)
	}
}

func TestParseWorkflow_UnpinnedAction(t *testing.T) {
	path := filepath.Join("..", "testdata", "vulnerable", "unpinned_action.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading testdata: %v", err)
	}

	ast, err := ParseWorkflow(path, content)
	if err != nil {
		t.Fatalf("ParseWorkflow failed: %v", err)
	}

	steps := ast.Jobs[0].Steps
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}

	if steps[0].Uses == nil || steps[0].Uses.IsSHA {
		t.Errorf("step 0: expected unpinned action (is_sha=false), got %+v", steps[0].Uses)
	}
	if steps[0].Uses.Ref != "v4" {
		t.Errorf("step 0: expected ref 'v4', got %q", steps[0].Uses.Ref)
	}

	if steps[1].Uses == nil || steps[1].Uses.IsSHA {
		t.Errorf("step 1: expected unpinned action (is_sha=false), got %+v", steps[1].Uses)
	}
	if steps[1].Uses.Ref != "main" {
		t.Errorf("step 1: expected ref 'main', got %q", steps[1].Uses.Ref)
	}
}

func TestParseWorkflow_UnpinnedActionPinned(t *testing.T) {
	path := filepath.Join("..", "testdata", "secure", "unpinned_action_pinned.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading testdata: %v", err)
	}

	ast, err := ParseWorkflow(path, content)
	if err != nil {
		t.Fatalf("ParseWorkflow failed: %v", err)
	}

	steps := ast.Jobs[0].Steps
	for i, step := range steps {
		if step.Uses == nil || !step.Uses.IsSHA {
			t.Errorf("step %d: expected pinned action (is_sha=true), got %+v", i, step.Uses)
		}
	}
}

func TestParseWorkflow_ActionInputInjection(t *testing.T) {
	path := filepath.Join("..", "testdata", "vulnerable", "script_injection_with.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading testdata: %v", err)
	}

	ast, err := ParseWorkflow(path, content)
	if err != nil {
		t.Fatalf("ParseWorkflow failed: %v", err)
	}

	step := ast.Jobs[0].Steps[0]
	if step.ExecType != "action" {
		t.Errorf("expected exec_type 'action', got %q", step.ExecType)
	}
	if len(step.Expressions) != 1 {
		t.Fatalf("expected 1 expression, got %d", len(step.Expressions))
	}
	if step.Expressions[0].Location != "with.script" {
		t.Errorf("expected location 'with.script', got %q", step.Expressions[0].Location)
	}
	if step.Expressions[0].Context != "github.event.comment.body" {
		t.Errorf("expected 'github.event.comment.body', got %q", step.Expressions[0].Context)
	}
}

func TestParseWorkflow_PullRequestTargetCheckout(t *testing.T) {
	path := filepath.Join("..", "testdata", "vulnerable", "pull_request_target_checkout.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading testdata: %v", err)
	}

	ast, err := ParseWorkflow(path, content)
	if err != nil {
		t.Fatalf("ParseWorkflow failed: %v", err)
	}

	if ast.Triggers[0].Event != "pull_request_target" {
		t.Errorf("expected event 'pull_request_target', got %q", ast.Triggers[0].Event)
	}

	checkoutStep := ast.Jobs[0].Steps[0]
	if checkoutStep.With["ref"] == "" {
		t.Errorf("expected with.ref to be populated")
	}
	if len(checkoutStep.Expressions) != 1 || checkoutStep.Expressions[0].Context != "github.event.pull_request.head.sha" {
		t.Errorf("expected pull request head sha expression, got %+v", checkoutStep.Expressions)
	}
}
