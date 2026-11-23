// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"bytes"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

const (
	pqcota    = "github.com/randyinthedev-hash/pqcota"
	discovery = "github.com/randyinthedev-hash/pqcota-discovery"
	common    = "github.com/randyinthedev-hash/pqcota-common"
)

var env = "(go1.26.11 " + runtime.GOOS + "/" + runtime.GOARCH + ")"

// release — 릴리스 빌드의 모양: 주 모듈은 통합 리포(devel), 명령은 의존 모듈에 속한다.
func release(cmd string, deps ...*debug.Module) *debug.BuildInfo {
	return &debug.BuildInfo{GoVersion: "go1.26.11", Path: cmd, Main: debug.Module{Path: pqcota, Version: "(devel)"}, Deps: deps}
}

// V1: 빌드 모양마다 한 줄. replace는 원래 require 판만 내지 않고 실제 대체 대상과 판을 적는다.
func TestLine(t *testing.T) {
	nodescan := discovery + "/cmd/pqcota-nodescan"
	for name, c := range map[string]struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		"release": {release(nodescan,
			&debug.Module{Path: common, Version: "v0.18.0", Sum: "h1:a"},
			&debug.Module{Path: discovery, Version: "v0.18.0", Sum: "h1:b"}), true,
			"pqcota-nodescan v0.18.0 " + env},
		"local folder replace": {release(nodescan,
			&debug.Module{Path: discovery, Version: "v0.18.0", Replace: &debug.Module{Path: "../pqcota-discovery"}}), true,
			"pqcota-nodescan v0.18.0 => ../pqcota-discovery (local source; not a release build) " + env},
		"replace with another module and version": {release(nodescan,
			&debug.Module{Path: discovery, Version: "v0.18.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v0.18.1", Sum: "h1:c"}}), true,
			"pqcota-nodescan v0.18.0 => example.com/fork v0.18.1 (not a release build) " + env},
		"built in its own repo (main module, devel)": {&debug.BuildInfo{GoVersion: "go1.26.11", Path: nodescan,
			Main:     debug.Module{Path: discovery, Version: "(devel)"},
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "a1b2c3d4e5f6"}, {Key: "vcs.modified", Value: "true"}}}, true,
			"pqcota-nodescan devel (built from the pqcota-discovery source; not a release build) " + env},
		"no build information": {nil, false, "pqcota-x unknown (no build information)"},
		"no owning module":     {release("example.com/other/cmd/tool"), true, "tool unknown (no build information)"},
	} {
		if got := Line(c.bi, c.ok, "pqcota-x"); got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", name, got, c.want)
		}
	}
	// 커밋은 어느 빌드에서도 내지 않는다(vcs 정보가 있어도).
	devel := &debug.BuildInfo{Path: nodescan, Main: debug.Module{Path: discovery, Version: "(devel)"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "a1b2c3d4e5f6"}}}
	if got := Line(devel, true, ""); strings.Contains(got, "a1b2c3d") {
		t.Errorf("a commit was printed: %q", got)
	}
}

// V1: 모듈 고르기는 경계까지 본다. 단순 접두어면 …/pqcota 와 …/pqcota-discovery 를 혼동한다.
func TestOwnerBoundary(t *testing.T) {
	deps := []*debug.Module{{Path: discovery, Version: "v0.18.0"}, {Path: common, Version: "v0.18.0"}}
	bi := func(cmd string) *debug.BuildInfo {
		return &debug.BuildInfo{Path: cmd, Main: debug.Module{Path: pqcota, Version: "v9.9.9"}, Deps: deps}
	}
	for cmd, want := range map[string]string{
		discovery + "/cmd/pqcota-nodescan": discovery,
		pqcota + "/cmd/pqcota-x":           pqcota,
		discovery:                          discovery, // 모듈 경로와 같음
		pqcota:                             pqcota,
	} {
		m, _ := owner(bi(cmd))
		if m == nil || m.Path != want {
			t.Errorf("%s: owner %v, want %s", cmd, m, want)
		}
	}
	// …/pqcota-discoveryx 는 …/pqcota-discovery 에 속하지 않는다. …/pqcota 에도 속하지 않는다.
	if m, _ := owner(bi(discovery + "x/cmd/x")); m != nil {
		t.Errorf("pqcota-discoveryx was given to %s", m.Path)
	}
}

// V2: 단독 `--version`·`-version`만 출력하고 종료 0. 섞인 호출은 아무것도 하지 않고 돌아간다.
func TestExitIfRequested(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-version"}} {
		var out bytes.Buffer
		code := -1
		exitIfRequested(args, &out, func(c int) { code = c })
		if code != 0 || strings.Count(out.String(), "\n") != 1 || out.Len() < 2 {
			t.Errorf("%v: code %d, output %q", args, code, out.String())
		}
	}
	for _, args := range [][]string{
		{"--version", "web-01"}, {"web-01", "--version"}, {"--output", "json", "--version"},
		{"--version=true"}, {"version"}, {"---version"}, {}, nil,
	} {
		var out bytes.Buffer
		called := false
		exitIfRequested(args, &out, func(int) { called = true })
		if called || out.Len() != 0 {
			t.Errorf("%q: handled a call that was not a lone --version (output %q)", args, out.String())
		}
	}
}
