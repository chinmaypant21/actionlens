package main

// SourcePosition records line and column number of AST elements for SARIF reporting
type SourcePosition struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

// WorkflowAST is the top-level normalized AST for a GitHub Actions workflow
type WorkflowAST struct {
	FilePath    string             `json:"file_path,omitempty"`
	Name        string             `json:"name"`
	Triggers    []Trigger          `json:"triggers"`
	Permissions *PermissionsConfig `json:"permissions,omitempty"`
	Env         map[string]string  `json:"env,omitempty"`
	Jobs        []JobAST           `json:"jobs"`
	Pos         SourcePosition     `json:"pos"`
}

// Trigger represents workflow activation triggers
type Trigger struct {
	Event    string   `json:"event"`
	Types    []string `json:"types,omitempty"`
	Branches []string `json:"branches,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Paths    []string `json:"paths,omitempty"`
}

// PermissionsConfig captures fine-grained or broad permissions
type PermissionsConfig struct {
	All    string            `json:"all,omitempty"`    // "read-all" or "write-all"
	Scopes map[string]string `json:"scopes,omitempty"` // {"contents": "read", ...}
	Pos    SourcePosition    `json:"pos"`
}

// RunnerConfig represents the runs-on environment
type RunnerConfig struct {
	Labels []string       `json:"labels"`
	Group  string         `json:"group,omitempty"`
	Pos    SourcePosition `json:"pos"`
}

// JobAST represents a workflow job
type JobAST struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	RunsOn      *RunnerConfig      `json:"runs_on,omitempty"`
	Permissions *PermissionsConfig `json:"permissions,omitempty"`
	Needs       []string           `json:"needs,omitempty"`
	If          string             `json:"if,omitempty"`
	Env         map[string]string  `json:"env,omitempty"`
	Outputs     map[string]string  `json:"outputs,omitempty"`
	Steps       []StepAST          `json:"steps"`
	Pos         SourcePosition     `json:"pos"`
}

// ExpressionInfo contains the evaluated context and sink location of an interpolated ${{ }} expression
type ExpressionInfo struct {
	Context  string `json:"context"`
	Location string `json:"location,omitempty"`
}

// ActionRef captures action location, tag, and whether pinned to a commit SHA
type ActionRef struct {
	Raw   string `json:"raw"`
	Owner string `json:"owner,omitempty"`
	Repo  string `json:"repo,omitempty"`
	Ref   string `json:"ref,omitempty"`
	IsSHA bool   `json:"is_sha"`
}

// StepAST represents a single step in a job
type StepAST struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	If          string            `json:"if,omitempty"`
	ExecType    string            `json:"exec_type"` // "run" or "action"
	Run         string            `json:"run,omitempty"`
	Shell       string            `json:"shell,omitempty"`
	Uses        *ActionRef        `json:"uses,omitempty"`
	With        map[string]string `json:"with,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Expressions []ExpressionInfo  `json:"expressions,omitempty"`
	Pos         SourcePosition    `json:"pos"`
}
