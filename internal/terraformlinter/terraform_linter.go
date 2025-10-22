// Copyright 2023 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package terraformlinter contains a linter implementation that verifies terraform
// files against our internal style guide and reports on all violations.
package terraformlinter

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/abcxyz/pkg/workerpool"
	"github.com/abcxyz/terraform-linter/internal/terraformlinter/rules"
)

// Top level terraform types to validate.
const (
	tokenTypeResource = "resource"
	tokenTypeModule   = "module"
	tokenTypeVariable = "variable"
	tokenTypeOutput   = "output"
	tokenTypeLocals   = "locals"
	tokenTypeImport   = "import"
	tokenTypeMoved    = "moved"
	tokenTypeData     = "data"
)

// List of valid extensions that can be linted.
var terraformSelectors = []string{".tf", ".tf.json"}

// Enum of positional locations in order.
type tokenPosition int32

const (
	None tokenPosition = iota
	LeadingStart
	LeadingEnd
	ProviderStart
	ProviderCenter
	ProviderEnd
	Ignored
	Trailing
)

// tokenAttr defines an individual attribute within a block of terraform.
type tokenAttr struct {
	tokenPos        tokenPosition
	token           hclsyntax.Token
	trailingNewline bool
}

// keywords to match on.
const (
	attrForEach                = "for_each"
	attrCount                  = "count"
	attrProvider               = "provider"
	attrSource                 = "source"
	attrProviderProject        = "project"
	attrProviderProjectID      = "project_id"
	attrProviderFolder         = "folder"
	attrProviderFolderID       = "folder_id"
	attrProviderOrganization   = "organization"
	attrProviderOrganizationID = "organization_id"
	attrProviderOrgID          = "org_id"
	attrDependsOn              = "depends_on"
	attrLifecycle              = "lifecycle"
)

// mapping of attributes to their expected position.
var positionMap = map[string]tokenPosition{
	attrForEach:                LeadingStart,
	attrCount:                  LeadingStart,
	attrSource:                 LeadingStart,
	attrProvider:               LeadingEnd,
	attrProviderProject:        ProviderEnd,
	attrProviderProjectID:      ProviderEnd,
	attrProviderFolder:         ProviderCenter,
	attrProviderFolderID:       ProviderCenter,
	attrProviderOrganization:   ProviderStart,
	attrProviderOrganizationID: ProviderStart,
	attrProviderOrgID:          ProviderStart,
	attrDependsOn:              Trailing,
	attrLifecycle:              Trailing,
}

type Finding struct {
	rule     *rules.Rule
	token    hclsyntax.Token
	contents []byte
}

// String reports a human-friendly version of the finding in the format:
//
//	<path>:<line>:<column>: <rule-id>: <message>
//	<snippet>
//	^
//
// For example:
//
//	folder/file.tf:37:8: TF001: Things are broken
//	resource "foo" "bar-baz" {
//	                   ^
func (f *Finding) String() string {
	filepath := strings.TrimPrefix(f.token.Range.Filename, "./")
	ruleID := f.rule.ID
	description := f.rule.Description
	line := f.token.Range.Start.Line
	column := f.token.Range.Start.Column

	return fmt.Sprintf("%s:%d:%d: %s: %s\n%s\n%*s\n",
		filepath, line, column, ruleID, description,
		f.contents,
		column, "^")
}

// Config is the input to creating a new linter.
type Config struct {
	ExcludePaths []string
	IgnoreRules  []string
}

// Linter is an instance of a linter type.
type Linter struct {
	excludePaths []string
	ignoreRules  map[string]struct{}

	findings     []*Finding
	findingsLock sync.Mutex
}

// New creates a new instance of a linter with the given config.
func New(c *Config) (*Linter, error) {
	if c == nil {
		c = new(Config)
	}

	ignoreRules := make(map[string]struct{}, len(c.IgnoreRules))
	for _, v := range c.IgnoreRules {
		ignoreRules[v] = struct{}{}
	}

	excludePaths := append([]string{}, c.ExcludePaths...)

	return &Linter{
		excludePaths: excludePaths,
		ignoreRules:  ignoreRules,
	}, nil
}

// AddFinding adds a finding to the linter, skipping any ignored rules. It is
// safe for calling concurrently.
func (l *Linter) AddFinding(r *rules.Rule, lines [][]byte, t hclsyntax.Token) {
	if _, ok := l.ignoreRules[r.ID]; ok {
		return
	}

	l.findingsLock.Lock()
	defer l.findingsLock.Unlock()
	l.findings = append(l.findings, &Finding{
		rule:     r,
		token:    t,
		contents: lines[t.Range.Start.Line-1],
	})
}

// Findings returns a all the findings, sorted by filename and then Rule ID.
func (l *Linter) Findings() []*Finding {
	l.findingsLock.Lock()
	defer l.findingsLock.Unlock()

	slices.SortFunc(l.findings, func(a, b *Finding) int {
		if af, bf := a.token.Range.Filename, b.token.Range.Filename; af != bf {
			return cmp.Compare(af, bf)
		}

		if ai, bi := a.rule.ID, b.rule.ID; ai != bi {
			return cmp.Compare(ai, bi)
		}

		if al, bl := a.token.Range.Start.Line, b.token.Range.Start.Line; al != bl {
			return cmp.Compare(al, bl)
		}

		if ac, bc := a.token.Range.Start.Column, b.token.Range.Start.Column; ac != bc {
			return cmp.Compare(ac, bc)
		}

		return cmp.Compare(a.rule.Description, b.rule.Description)
	})

	return l.findings
}

// Run executes the specified linter for a set of files.
func (l *Linter) Run(ctx context.Context, paths []string) error {
	pool := workerpool.New[*workerpool.Void](nil)

	// Process each provided path in parallel for violations.
	for _, path := range paths {
		if err := pool.Do(ctx, func() (*workerpool.Void, error) {
			if err := l.lint(path); err != nil {
				return nil, fmt.Errorf("error linting file %q: %w", path, err)
			}
			return nil, nil
		}); err != nil {
			return fmt.Errorf("failed to queue work: %w", err)
		}
	}

	// Wait for everything to finish.
	if _, err := pool.Done(ctx); err != nil {
		return fmt.Errorf("failed to lint: %w", err)
	}

	return nil
}

// lint reads a path and determines if it is a file or a directory. When it
// finds a file it reads it and checks it for violations. When it finds a
// directory it calls itself recursively.
func (l *Linter) lint(path string) error {
	if err := filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
		if l.excludedPath(path) {
			return filepath.SkipDir
		}

		if err != nil {
			return err
		}
		for _, sel := range terraformSelectors {
			if strings.HasSuffix(path, sel) {
				content, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("error reading file %q: %w", path, err)
				}
				if err := l.findViolations(content, path); err != nil {
					return fmt.Errorf("error linting file %q: %w", path, err)
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("error walking path %q: %w", path, err)
	}
	return nil
}

// findViolations inspects a set of bytes that represent hcl from a terraform configuration file
// looking for attributes of a resource and ensuring that the ordering matches our style guide.
func (l *Linter) findViolations(content []byte, path string) error {
	tokens, diags := hclsyntax.LexConfig(content, path, hcl.Pos{Byte: 0, Line: 1, Column: 1})
	if diags.HasErrors() {
		// diags.Error is just a string, but the golangci linter gets angry that we aren't using
		// %w in the error message. Attempts to use the nolint tag also get flagged as not needed
		// in newer versions so to appease the linter we wrap the string in an error.
		return fmt.Errorf("error lexing hcl file contents: [%w]", errors.New(diags.Error()))
	}

	lines := bytes.Split(content, []byte("\n"))

	inBlock := false
	depth, start := 0, 0
	// First break apart the terraform into the major blocks of resources / modules
	for idx, token := range tokens {
		if token.Bytes == nil {
			continue
		}
		contents := string(token.Bytes)
		// Each Ident token starts a new object, we are only looking for resource, module, output, variable and moved types
		if !inBlock && token.Type == hclsyntax.TokenIdent &&
			(contents == tokenTypeResource ||
				contents == tokenTypeModule ||
				contents == tokenTypeOutput ||
				contents == tokenTypeVariable ||
				contents == tokenTypeLocals ||
				contents == tokenTypeImport ||
				contents == tokenTypeMoved ||
				contents == tokenTypeData) {
			inBlock = true
			start = idx
			depth = 0
		}

		// If we are in a block, look for the closing braces to find the end
		if inBlock {
			// Before dropping into the block itself, look for names that have a hyphen
			if depth == 0 && token.Type == hclsyntax.TokenQuotedLit {
				if strings.Contains(contents, "-") {
					l.AddFinding(rules.HyphenInName, lines, token)
				}
			}
			if token.Type == hclsyntax.TokenOBrace {
				depth = depth + 1
			}
			if token.Type == hclsyntax.TokenCBrace {
				depth = depth - 1
				// Last brace signals the end of the entire block
				if depth == 0 {
					inBlock = false
					// Validate the block against the rules
					l.validateBlock(lines, tokens[start:idx+1])
				}
			}
		}
	}
	return nil
}

// validateBlock scans a block of terraform looking for violations
// of our style guide.
func (l *Linter) validateBlock(lines [][]byte, tokens hclsyntax.Tokens) {
	var attrs []tokenAttr
	var token hclsyntax.Token
	for len(tokens) > 0 {
		// Pop the first token off
		token, tokens = tokens[0], tokens[1:]
		contents := string(token.Bytes)
		if token.Type == hclsyntax.TokenIdent {
			if contents == tokenTypeModule || contents == tokenTypeResource {
				continue
			}
			var t hclsyntax.Token
			skipping := true
			depth := 0
			// while there are tokens to skip and we haven't exceeded the length of the slice
			for skipping && len(tokens) > 1 {
				t, tokens = tokens[0], tokens[1:]
				if t.Type == hclsyntax.TokenOBrace || t.Type == hclsyntax.TokenOBrack {
					depth = depth + 1
				}
				if t.Type == hclsyntax.TokenCBrace || t.Type == hclsyntax.TokenCBrack {
					depth = depth - 1
				}
				if depth == 0 && (t.Type == hclsyntax.TokenNewline || t.Type == hclsyntax.TokenComment) {
					// Check for an extra newline
					trailingNewline := false
					if len(tokens) > 0 && tokens[0].Type == hclsyntax.TokenNewline {
						trailingNewline = true
					}
					position, ok := positionMap[contents]
					if !ok {
						position = Ignored
					}
					attrs = append(attrs, tokenAttr{
						tokenPos:        position,
						token:           token,
						trailingNewline: trailingNewline,
					})
					skipping = false
				}
				// Reached the end of the file
				if len(tokens) < 2 {
					skipping = false
				}
			}
		}
	}

	l.generateViolations(lines, attrs)
}

func (l *Linter) generateViolations(lines [][]byte, idents []tokenAttr) {
	var lastAttr tokenAttr

	for pos, token := range idents {
		contents := string(token.token.Bytes)
		switch contents {
		// for_each, count and source should be at the top
		case attrForEach, attrCount, attrSource:
			if pos != 0 && lastAttr.tokenPos != LeadingStart {
				l.AddFinding(rules.LeadingMetaBlockAttribute, lines, token.token)
			}
		// provider is at the top but below for_each or count if they exist
		case attrProvider:
			if pos > 0 && lastAttr.tokenPos != LeadingStart {
				l.AddFinding(rules.LeadingMetaBlockAttribute, lines, token.token)
			}
		case attrDependsOn:
			// depends_on somewhere above where it should be
			if pos < len(idents)-1 && idents[len(idents)-1].tokenPos != Trailing {
				l.AddFinding(rules.TrailingMetaBlockAttribute, lines, token.token)
			}
			// depends_on after lifecycle
			if pos == len(idents)-1 && lastAttr.tokenPos == Trailing {
				l.AddFinding(rules.TrailingMetaBlockAttribute, lines, token.token)
			}
		case attrLifecycle:
			// lifecycle should be last
			if pos != len(idents)-1 {
				l.AddFinding(rules.TrailingMetaBlockAttribute, lines, token.token)
			}
		// All provider specific entries follow the same logic. Should be below the metadata segment and above everything else
		// Expect order
		//   organization
		//   folder
		//   project
		case attrProviderOrganization,
			attrProviderOrganizationID,
			attrProviderOrgID:
			if lastAttr.tokenPos > ProviderStart {
				l.AddFinding(rules.ProviderAttributes, lines, token.token)
			}
			if (lastAttr.tokenPos == LeadingStart || lastAttr.tokenPos == LeadingEnd) && !lastAttr.trailingNewline {
				l.AddFinding(rules.MetaBlockNewline, lines, token.token)
			}
		case attrProviderFolder,
			attrProviderFolderID:
			if lastAttr.tokenPos > ProviderCenter {
				l.AddFinding(rules.ProviderAttributes, lines, token.token)
			}
			if (lastAttr.tokenPos == LeadingStart || lastAttr.tokenPos == LeadingEnd) && !lastAttr.trailingNewline {
				l.AddFinding(rules.MetaBlockNewline, lines, token.token)
			}
		case attrProviderProject,
			attrProviderProjectID:
			if lastAttr.tokenPos > ProviderEnd {
				l.AddFinding(rules.ProviderAttributes, lines, token.token)
			}
			if (lastAttr.tokenPos == LeadingStart || lastAttr.tokenPos == LeadingEnd) && !lastAttr.trailingNewline {
				l.AddFinding(rules.MetaBlockNewline, lines, token.token)
			}
		// Check for trailing newlines where required
		default:
			if lastAttr.tokenPos == ProviderEnd && !lastAttr.trailingNewline {
				l.AddFinding(rules.ProviderNewline, lines, token.token)
			}
			if (lastAttr.tokenPos == LeadingStart || lastAttr.tokenPos == LeadingEnd) && !lastAttr.trailingNewline {
				l.AddFinding(rules.MetaBlockNewline, lines, token.token)
			}
		}

		lastAttr = token
	}
}

func (l *Linter) excludedPath(pth string) bool {
	for _, exclude := range l.excludePaths {
		if match, _ := filepath.Match(exclude, pth); match {
			return true
		}
	}
	return false
}
