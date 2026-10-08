package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rhysd/actionlint"
)

// ParseWorkflow converts a raw workflow YAML byte slice into a normalized WorkflowAST
func ParseWorkflow(filePath string, content []byte) (*WorkflowAST, error) {
	w, errs := actionlint.Parse(content)
	if len(errs) > 0 {
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return nil, fmt.Errorf("parsing workflow failed: %s", strings.Join(msgs, "; "))
	}

	ast := &WorkflowAST{
		FilePath: filePath,
	}

	if w == nil {
		return ast, nil
	}

	if w.Name != nil {
		ast.Name = w.Name.Value
	}

	// Triggers
	ast.Triggers = parseTriggers(w.On)

	// Workflow-level permissions
	if w.Permissions != nil {
		ast.Permissions = parsePermissions(w.Permissions)
	}

	// Workflow-level env
	if w.Env != nil {
		ast.Env = parseEnv(w.Env)
	}

	// Jobs (sorted by source line for deterministic ordering)
	jobList := make([]*actionlint.Job, 0, len(w.Jobs))
	for _, job := range w.Jobs {
		jobList = append(jobList, job)
	}
	sort.Slice(jobList, func(i, j int) bool {
		if jobList[i].Pos != nil && jobList[j].Pos != nil {
			return jobList[i].Pos.Line < jobList[j].Pos.Line
		}
		return jobList[i].ID.Value < jobList[j].ID.Value
	})

	ast.Jobs = make([]JobAST, 0, len(jobList))
	for _, job := range jobList {
		ast.Jobs = append(ast.Jobs, parseJob(job))
	}

	return ast, nil
}

func parseTriggers(events []actionlint.Event) []Trigger {
	if len(events) == 0 {
		return nil
	}

	triggers := make([]Trigger, 0, len(events))
	for _, evt := range events {
		t := Trigger{
			Event: evt.EventName(),
		}

		if we, ok := evt.(*actionlint.WebhookEvent); ok {
			for _, typ := range we.Types {
				if typ != nil {
					t.Types = append(t.Types, typ.Value)
				}
			}
			if we.Branches != nil {
				for _, b := range we.Branches.Values {
					if b != nil {
						t.Branches = append(t.Branches, b.Value)
					}
				}
			}
			if we.Tags != nil {
				for _, tag := range we.Tags.Values {
					if tag != nil {
						t.Tags = append(t.Tags, tag.Value)
					}
				}
			}
			if we.Paths != nil {
				for _, p := range we.Paths.Values {
					if p != nil {
						t.Paths = append(t.Paths, p.Value)
					}
				}
			}
		}

		triggers = append(triggers, t)
	}

	return triggers
}

func parsePermissions(p *actionlint.Permissions) *PermissionsConfig {
	if p == nil {
		return nil
	}

	cfg := &PermissionsConfig{}
	if p.Pos != nil {
		cfg.Pos = SourcePosition{Line: p.Pos.Line, Col: p.Pos.Col}
	}

	if p.All != nil {
		cfg.All = p.All.Value
	}

	if len(p.Scopes) > 0 {
		cfg.Scopes = make(map[string]string, len(p.Scopes))
		for k, v := range p.Scopes {
			if v != nil && v.Value != nil {
				cfg.Scopes[k] = v.Value.Value
			}
		}
	}

	return cfg
}

func parseEnv(e *actionlint.Env) map[string]string {
	if e == nil || len(e.Vars) == 0 {
		return nil
	}

	envMap := make(map[string]string, len(e.Vars))
	for k, v := range e.Vars {
		if v != nil && v.Value != nil {
			envMap[k] = v.Value.Value
		}
	}
	return envMap
}

func parseJob(j *actionlint.Job) JobAST {
	job := JobAST{}

	if j.ID != nil {
		job.ID = j.ID.Value
	}
	if j.Name != nil {
		job.Name = j.Name.Value
	}
	if j.Pos != nil {
		job.Pos = SourcePosition{Line: j.Pos.Line, Col: j.Pos.Col}
	}

	if j.RunsOn != nil {
		rc := &RunnerConfig{}
		if j.RunsOn.Group != nil {
			rc.Group = j.RunsOn.Group.Value
		}
		for _, l := range j.RunsOn.Labels {
			if l != nil {
				rc.Labels = append(rc.Labels, l.Value)
			}
		}
		if j.RunsOn.LabelsExpr != nil {
			rc.Labels = append(rc.Labels, j.RunsOn.LabelsExpr.Value)
		}
		job.RunsOn = rc
	}

	if j.Permissions != nil {
		job.Permissions = parsePermissions(j.Permissions)
	}

	for _, need := range j.Needs {
		if need != nil {
			job.Needs = append(job.Needs, need.Value)
		}
	}

	if j.If != nil {
		job.If = j.If.Value
	}

	if j.Env != nil {
		job.Env = parseEnv(j.Env)
	}

	if len(j.Outputs) > 0 {
		job.Outputs = make(map[string]string, len(j.Outputs))
		for k, v := range j.Outputs {
			if v != nil && v.Value != nil {
				job.Outputs[k] = v.Value.Value
			}
		}
	}

	job.Steps = make([]StepAST, 0, len(j.Steps))
	for _, s := range j.Steps {
		job.Steps = append(job.Steps, parseStep(s))
	}

	return job
}

func parseStep(s *actionlint.Step) StepAST {
	step := StepAST{}

	if s.ID != nil {
		step.ID = s.ID.Value
	}
	if s.Name != nil {
		step.Name = s.Name.Value
	}
	if s.If != nil {
		step.If = s.If.Value
	}
	if s.Pos != nil {
		step.Pos = SourcePosition{Line: s.Pos.Line, Col: s.Pos.Col}
	}

	if s.Env != nil {
		step.Env = parseEnv(s.Env)
	}

	// Expressions can be found in Run, With, Env, or If
	var allExprs []ExpressionInfo

	if s.If != nil {
		allExprs = append(allExprs, ExtractExpressions(s.If.Value, "if")...)
	}

	if step.Env != nil {
		for key, val := range step.Env {
			allExprs = append(allExprs, ExtractExpressions(val, "env."+key)...)
		}
	}

	switch exec := s.Exec.(type) {
	case *actionlint.ExecRun:
		step.ExecType = "run"
		if exec.Run != nil {
			step.Run = exec.Run.Value
			allExprs = append(allExprs, ExtractExpressions(exec.Run.Value, "run")...)
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
			for k, v := range exec.Inputs {
				if v != nil && v.Value != nil {
					step.With[k] = v.Value.Value
					allExprs = append(allExprs, ExtractExpressions(v.Value.Value, "with."+k)...)
				}
			}
		}
	}

	if len(allExprs) > 0 {
		step.Expressions = allExprs
	}

	return step
}
