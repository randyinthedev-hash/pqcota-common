// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package version — 명령의 `--version` 한 줄. 판은 빌드에 심지 않고 **Go 빌드 정보에서 읽는다**
// (계획 2026-11-23-version-flag). 릴리스는 replace 없이 태그의 모듈로 빌드되므로, 명령이 속한 모듈의
// 판이 곧 릴리스 판이다. 주 모듈은 통합 리포이고 그 판은 `(devel)`이라 쓰지 않는다.
//
// 커밋은 어느 빌드에서도 내지 않는다. 릴리스 빌드는 go.mod를 고쳐 빌드하므로 vcs 정보가 있어도 믿을 수
// 없다. 릴리스 커밋은 릴리스 manifest에 있다.
package version

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

// Line — `--version`에 낼 한 줄.
//
//	릴리스                 pqcota-nodescan v0.18.0 (go1.26.11 linux/amd64)
//	로컬 폴더 replace      pqcota-nodescan v0.18.0 => ../pqcota-discovery (local source; not a release build) (…)
//	다른 모듈로 replace    pqcota-nodescan v0.18.0 => example.com/fork v0.18.1 (not a release build) (…)
//	주 모듈 빌드           pqcota-nodescan devel (built from the pqcota-discovery source; not a release build) (…)
//	빌드 정보 없음         pqcota-nodescan unknown (no build information)
//
// replace 빌드는 go.mod의 require 판을 그대로 달지만 코드는 대체 대상의 것이다. 그래서 그 판만 내지 않고
// 실제 대체 대상과 판을 적는다(`go version -m`이 replace를 적는 모양과 같다).
func Line(bi *debug.BuildInfo, ok bool, fallbackName string) string {
	if !ok || bi == nil {
		return fallbackName + " unknown (no build information)"
	}
	name := path.Base(bi.Path)
	if bi.Path == "" {
		name = fallbackName
	}
	m, isMain := owner(bi)
	if m == nil {
		return name + " unknown (no build information)"
	}
	env := fmt.Sprintf("(%s %s/%s)", goVersion(bi), runtime.GOOS, runtime.GOARCH)
	switch {
	case m.Replace != nil && m.Replace.Version == "":
		return fmt.Sprintf("%s %s => %s (local source; not a release build) %s", name, m.Version, m.Replace.Path, env)
	case m.Replace != nil:
		return fmt.Sprintf("%s %s => %s %s (not a release build) %s", name, m.Version, m.Replace.Path, m.Replace.Version, env)
	case isMain && (m.Version == "" || m.Version == "(devel)"):
		return fmt.Sprintf("%s devel (built from the %s source; not a release build) %s", name, path.Base(m.Path), env)
	}
	return fmt.Sprintf("%s %s %s", name, m.Version, env)
}

// owner — 명령(주 패키지 경로)이 속한 모듈. 명령 경로가 모듈 경로와 **같거나 「모듈 경로 + "/"」로 시작하는**
// 모듈만 후보이고, 그중 가장 긴 것이다. 단순 접두어로 보면 …/pqcota 와 …/pqcota-discovery 를 혼동한다.
func owner(bi *debug.BuildInfo) (*debug.Module, bool) {
	var best *debug.Module
	bestMain := false
	consider := func(m *debug.Module, isMain bool) {
		if m == nil || m.Path == "" {
			return
		}
		if bi.Path != m.Path && !strings.HasPrefix(bi.Path, m.Path+"/") {
			return
		}
		if best == nil || len(m.Path) > len(best.Path) {
			best, bestMain = m, isMain
		}
	}
	consider(&bi.Main, true)
	for _, d := range bi.Deps {
		consider(d, false)
	}
	return best, bestMain
}

func goVersion(bi *debug.BuildInfo) string {
	if bi.GoVersion != "" {
		return bi.GoVersion
	}
	return runtime.Version()
}

// Requested — 인자가 **정확히** `--version` 이나 `-version` 하나인가. 다른 인자와 섞인 호출은 아니다:
// `--version`은 파일 이름이나 문자열 값일 수 있으므로(예: `pqcota-cbom-ingest --version web-01`은 그런
// 이름의 파일을 읽는 호출이다), 섞이면 명령의 원래 인자 처리 규칙을 따른다.
func Requested(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "-version")
}

// ExitIfRequested — 단독 `--version`이면 한 줄을 표준 출력에 내고 종료 0. 명령의 main 첫 줄에서 부른다 —
// 키를 읽거나, DB에 붙거나, 파일을 쓰기 전에 끝나야 한다. 아니면 아무것도 하지 않고 돌아간다.
func ExitIfRequested(args []string) {
	exitIfRequested(args, os.Stdout, os.Exit)
}

func exitIfRequested(args []string, w io.Writer, exit func(int)) {
	if !Requested(args) {
		return
	}
	bi, ok := debug.ReadBuildInfo()
	fmt.Fprintln(w, Line(bi, ok, exeName()))
	exit(0)
}

// exeName — 빌드 정보가 없을 때의 명령 이름(실행 파일 이름에서 .exe를 뗀 것).
func exeName() string {
	return strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
}
