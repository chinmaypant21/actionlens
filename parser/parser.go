package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rhysd/actionlint"
)

// TODO: the AST does not cover strategy/matrix, containers, services,
// environments or concurrency yet, and expressions are only extracted from
// step fields. Positions could also be tracked more precisely for findings.

// ParseWorkflow parses a workflow file with actionlint and converts it into
// our own WorkflowAST, which is what the Python side reads.
func ParseWorkflow(filePath string, content []byte) (*WorkflowAST, error) {
	workflow, parseErrors := actionlint.Parse(content)
	if len(parseErrors) > 0 {
		var messages []string
		for _, err := range parseErrors {
			messages = append(messages, err.Error())
		}
		return nil, fmt.Errorf("parsing workflow failed: %s", strings.Join(messages, "; "))
	}

	ast := &WorkflowAST{FilePath: filePath}
	if workflow == nil {
		return ast, nil
	}

	if workflow.Name != nil {
		ast.Name = workflow.Name.Value
	}
	ast.Triggers = parseTriggers(workflow.On)
	if workflow.Permissions != nil {
		ast.Permissions = parsePermissions(workflow.Permissions)
	}
	if workflow.Env != nil {
		ast.Env = parseEnv(workflow.Env)
	}

	// actionlint keeps jobs in a map, so sort them by line to get the same order every run.
	jobs := make([]*actionlint.Job, 0, len(workflow.Jobs))
	for _, job := range workflow.Jobs {
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Pos != nil && jobs[j].Pos != nil {
			return jobs[i].Pos.Line < jobs[j].Pos.Line
		}
		return jobs[i].ID.Value < jobs[j].ID.Value
	})

	ast.Jobs = make([]JobAST, 0, len(jobs))
	for _, job := range jobs {
		ast.Jobs = append(ast.Jobs, parseJob(job))
	}

	return ast, nil
}

// parseTriggers reads the "on:" events and their types/branches/tags/paths filters.
func parseTriggers(events []actionlint.Event) []Trigger {
	if len(events) == 0 {
		return nil
	}

	triggers := make([]Trigger, 0, len(events))
	for _, event := range events {
		trigger := Trigger{Event: event.EventName()}

		// Filters are only read for webhook events (push, pull_request, ...).
		if webhook, ok := event.(*actionlint.WebhookEvent); ok {
			trigger.Types = stringValues(webhook.Types)
			if webhook.Branches != nil {
				trigger.Branches = stringValues(webhook.Branches.Values)
			}
			if webhook.Tags != nil {
				trigger.Tags = stringValues(webhook.Tags.Values)
			}
			if webhook.Paths != nil {
				trigger.Paths = stringValues(webhook.Paths.Values)
			}
		}

		triggers = append(triggers, trigger)
	}

	return triggers
}

// parsePermissions reads a permissions: block, which is either a single value
// like "write-all" or a map of scopes like {contents: read}.
func parsePermissions(block *actionlint.Permissions) *PermissionsConfig {
	if block == nil {
		return nil
	}

	permissions := &PermissionsConfig{Pos: toPosition(block.Pos)}
	if block.All != nil {
		permissions.All = block.All.Value
	}
	if len(block.Scopes) > 0 {
		permissions.Scopes = make(map[string]string, len(block.Scopes))
		for scope, level := range block.Scopes {
			if level != nil && level.Value != nil {
				permissions.Scopes[scope] = level.Value.Value
			}
		}
	}

	return permissions
}

// parseEnv turns an env: block into a plain name -> value map.
func parseEnv(env *actionlint.Env) map[string]string {
	if env == nil || len(env.Vars) == 0 {
		return nil
	}

	vars := make(map[string]string, len(env.Vars))
	for name, variable := range env.Vars {
		if variable != nil && variable.Value != nil {
			vars[name] = variable.Value.Value
		}
	}
	return vars
}

func parseJob(j *actionlint.Job) JobAST {
	job := JobAST{Pos: toPosition(j.Pos)}

	if j.ID != nil {
		job.ID = j.ID.Value
	}
	if j.Name != nil {
		job.Name = j.Name.Value
	}
	if j.RunsOn != nil {
		job.RunsOn = parseRunner(j.RunsOn)
	}
	if j.Permissions != nil {
		job.Permissions = parsePermissions(j.Permissions)
	}
	job.Needs = stringValues(j.Needs)
	if j.If != nil {
		job.If = j.If.Value
	}
	if j.Env != nil {
		job.Env = parseEnv(j.Env)
	}

	if len(j.Outputs) > 0 {
		job.Outputs = make(map[string]string, len(j.Outputs))
		for name, output := range j.Outputs {
			if output != nil && output.Value != nil {
				job.Outputs[name] = output.Value.Value
			}
		}
	}

	job.Steps = make([]StepAST, 0, len(j.Steps))
	for _, s := range j.Steps {
		job.Steps = append(job.Steps, parseStep(s))
	}

	return job
}

// parseRunner reads runs-on. its position come either from the first label
// , from the runner group or labels expression
func parseRunner(runsOn *actionlint.Runner) *RunnerConfig {
	runner := &RunnerConfig{}

	switch {
	case len(runsOn.Labels) > 0 && runsOn.Labels[0] != nil && runsOn.Labels[0].Pos != nil:
		runner.Pos = toPosition(runsOn.Labels[0].Pos)
	case runsOn.Group != nil && runsOn.Group.Pos != nil:
		runner.Pos = toPosition(runsOn.Group.Pos)
	case runsOn.LabelsExpr != nil && runsOn.LabelsExpr.Pos != nil:
		runner.Pos = toPosition(runsOn.LabelsExpr.Pos)
	}

	if runsOn.Group != nil {
		runner.Group = runsOn.Group.Value
	}
	runner.Labels = stringValues(runsOn.Labels)
	// e.g. runs-on: ${{ matrix.os }} is kept as the raw expression text
	if runsOn.LabelsExpr != nil {
		runner.Labels = append(runner.Labels, runsOn.LabelsExpr.Value)
	}

	return runner
}

// parseStep reads a step and collects every ${{ }} expression it uses,
// tagged with the field it appears in (if, env.X, run, or with.X).
func parseStep(s *actionlint.Step) StepAST {
	step := StepAST{Pos: toPosition(s.Pos)}

	if s.ID != nil {
		step.ID = s.ID.Value
	}
	if s.Name != nil {
		step.Name = s.Name.Value
	}
	if s.If != nil {
		step.If = s.If.Value
	}
	if s.Env != nil {
		step.Env = parseEnv(s.Env)
	}

	var expressions []ExpressionInfo

	if s.If != nil {
		expressions = append(expressions, ExtractExpressions(s.If.Value, "if")...)
	}
	for name, value := range step.Env {
		expressions = append(expressions, ExtractExpressions(value, "env."+name)...)
	}

	switch exec := s.Exec.(type) {
	case *actionlint.ExecRun:
		step.ExecType = "run"
		if exec.Run != nil {
			step.Run = exec.Run.Value
			expressions = append(expressions, ExtractExpressions(exec.Run.Value, "run")...)
		}
		if exec.Shell != nil {
			step.Shell = exec.Shell.Value
		}
	case *actionlint.ExecAction:
		step.ExecType = "action"
		if exec.Uses != nil {
			step.Uses = ParseActionReference(exec.Uses.Value)
		}
		if len(exec.Inputs) > 0 {
			step.With = make(map[string]string, len(exec.Inputs))
			for name, input := range exec.Inputs {
				if input != nil && input.Value != nil {
					step.With[name] = input.Value.Value
					expressions = append(expressions, ExtractExpressions(input.Value.Value, "with."+name)...)
				}
			}
		}
	}

	if len(expressions) > 0 {
		step.Expressions = expressions
	}

	return step
}

// toPosition copies an actionlint position. A missing position stays 0:0.
func toPosition(pos *actionlint.Pos) SourcePosition {
	if pos == nil {
		return SourcePosition{}
	}
	return SourcePosition{Line: pos.Line, Col: pos.Col}
}

// stringValues collects the values of a list of YAML strings, skipping nil entries.
func stringValues(items []*actionlint.String) []string {
	var values []string
	for _, item := range items {
		if item != nil {
			values = append(values, item.Value)
		}
	}
	return values
}
