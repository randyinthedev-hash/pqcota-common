# pqcota-common — 계약(proto)과 공통 코드의 빌드·테스트
# 전제: go(go.mod의 toolchain 이상). 이 리포는 형제 모듈을 go.mod의 replace로 ../ 에서 읽는다(작업 공간 배치).
#
# gen/ (proto 생성 코드)은 **커밋돼 있다**. proto를 고쳤을 때만 `make generate`로 다시 만들어 함께 커밋한다.

.PHONY: all generate lint breaking tools fmt-check vet build test

all: generate lint breaking fmt-check vet build test

# proto SSOT → Go 코드 생성 (gen/pqcota/{common,discovery,provisioning}/v1/*.pb.go)
# gen/은 커밋돼 있으므로 클론 직후에 돌릴 일은 없고, **proto를 고쳤을 때** 다시 만들어 함께
# 커밋한다. 어긋난 채로 올리면 CI의 generate 드리프트 검사가 막는다(.github/workflows/ci.yml).
# buf가 없으면 무엇을 설치해야 하는지 알려준다 —
# "command not found"만 보이면 원인이 컨트랙트인지 도구인지 알 수 없다.
generate:
	@command -v buf >/dev/null || { \
	  echo "✗ buf 없음 — proto 코드 생성 도구가 필요하다: https://buf.build/docs/installation"; \
	  echo "  설치 후: make tools && make generate"; exit 1; }
	@# buf는 플러그인을 **PATH에서** 찾는다. `make tools`가 방금 깔았어도 $$(go env GOPATH)/bin이
	@# PATH에 없으면 "executable file not found"만 나와, 읽는 사람은 설치가 실패한 줄 안다.
	@# 깔려 있는데 안 보이는 것인지, 아예 없는 것인지를 갈라서 말한다.
	@for p in protoc-gen-go protoc-gen-go-grpc; do \
	  command -v $$p >/dev/null && continue; \
	  if [ -x "$$(go env GOPATH 2>/dev/null)/bin/$$p" ]; then \
	    echo "✗ $$p 이 PATH에 없다 — 설치는 돼 있다($$(go env GOPATH)/bin)."; \
	    echo "  buf는 플러그인을 PATH에서 찾으므로 그 디렉터리를 PATH에 넣어야 한다:"; \
	    echo "    export PATH=\"\$$PATH:\$$(go env GOPATH)/bin\"     # zsh·bash — 셸 설정에 넣어 두면 매번 안 해도 된다"; \
	    echo "    \$$env:Path += \";\$$(go env GOPATH)/bin\"          # Windows PowerShell (정방향 슬래시도 받는다)"; \
	  else \
	    echo "✗ $$p 없음 — 먼저 make tools 를 실행한다."; \
	  fi; exit 1; \
	done
	cd contracts && buf generate

# 계약 lint (STANDARD, 일부 오피니언 규칙 완화 — buf.yaml)
lint:
	@command -v buf >/dev/null || { echo "✗ buf 없음 — https://buf.build/docs/installation"; exit 1; }
	cd contracts && buf lint

# 계약 하위호환 — **이미 릴리스한 계약**을 깨지 않는지 본다(buf.yaml의 `breaking: FILE`).
#
# 기준선은 마지막 릴리스 태그다. 직전 커밋이 아니라 태그인 이유: 릴리스 전에는 계약을 다시
# 짜는 것이 정당하고, 받는 사람이 생긴 뒤부터 못 깨는 것이다. "새 런타임을 코어 무변경으로
# 받는다"는 주장도 **published 계약 기준**이라야 뜻이 있다.
# 태그가 없으면(v0.1.0 이전) 비교 대상이 없다 — 건너뛰되 **왜 건너뛰는지 찍는다**(스킵은 통과가 아니다).
breaking:
	@command -v buf >/dev/null || { echo "✗ buf 없음 — https://buf.build/docs/installation"; exit 1; }
	@if [ -n "$(AGAINST)" ]; then \
	  echo "· 계약 하위호환 기준선: $(AGAINST) (branch)"; \
	  cd contracts && buf breaking --against "../.git#branch=$(AGAINST),subdir=contracts"; \
	  exit $$?; \
	fi; \
	tag=$$(git tag -l 'v*' --sort=-v:refname | head -1); \
	if [ -z "$$tag" ]; then \
	  echo "· 계약 하위호환 검사 건너뜀 — 릴리스 태그가 아직 없다(첫 태그부터 기준선이 생긴다)"; \
	  echo "  작업 중 브랜치를 main과 대조하려면: make breaking AGAINST=main"; \
	else \
	  echo "· 계약 하위호환 기준선: $$tag"; \
	  cd contracts && buf breaking --against "../.git#tag=$$tag,subdir=contracts"; \
	fi

# 전체 빌드 — Go(호스트 + **리눅스 타깃**) + Java 사이드카.
#
# ★ 리눅스 타깃을 따로 빌드하는 이유: collector의 핵심(`/proc`·AF_PACKET·attach)은 `//go:build linux`라
# **macOS에서는 컴파일 대상에서 빠진다.** 호스트 빌드만 하면 Mac 기여자가 그 코드를 깨도 통과한다.
# 교차 컴파일이 공짜(CGO_ENABLED=0)라 늘 함께 확인한다.
build:
	go build ./...
	@echo "→ 리눅스 타깃 교차 확인(리눅스 전용 파일 포함)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./... 2>&1 | head -20; \
	 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./... >/dev/null
	@# Windows 타깃도 함께 본다 — CNG collector가 여기서 자란다. 리눅스 전용 코드가
	@# 빌드 태그 밖으로 새면 **Windows에서만** 깨지므로, 그 코드를 쓰기 전에 게이트를 세운다.
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./... 2>&1 | head -20; \
	 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./... >/dev/null
	@echo "✓ Go 빌드(호스트 + linux/amd64 + windows/amd64) 통과"

# gofmt 게이트 — CONTRIBUTING이 gofmt를 규정하는데 검사가 없어 미포맷이 8건까지 쌓인 적이 있다.
# gen/(생성 코드)은 제외. 실패 시 어떤 파일인지 보여준다.
fmt-check:
	@files=$$(gofmt -l $$(git ls-files '*.go' | grep -v '^gen/') 2>/dev/null); \
	if [ -n "$$files" ]; then \
	  echo "✗ gofmt 필요:"; echo "$$files"; echo "  고치기: gofmt -w <파일>"; exit 1; \
	fi; \
	echo "✓ gofmt 통과"

vet:
	go vet ./...

test:
	go test ./...

# 도구 설치 헬퍼 (buf는 릴리스 바이너리 권장)
# 어디에 깔리는지 함께 알린다 — go install은 알리지 않고 $(go env GOPATH)/bin에 넣는데, 거기가 PATH에
# 없으면 다음 단계인 make generate가 "플러그인 없음"으로 넘어져 원인이 설치처럼 보인다.
#
# **버전을 고정한다.** `@latest`면 언제 깔았느냐로 생성 코드가 달라져, 같은 커밋에서 사람마다
# 다른 gen/이 나온다(gen/이 커밋돼 있어 그 차이가 diff로 드러나고 CI 드리프트 검사에 걸린다).
# PROTOC_GEN_GO는 go.mod의 google.golang.org/protobuf와 **같은 버전**이어야 한다 — 생성 코드가
# 그 런타임을 부른다.
# 데모의 ctl 이미지도 같은 값으로 깐다(demo/Dockerfile).
PROTOC_GEN_GO      := v1.36.11
PROTOC_GEN_GO_GRPC := v1.5.1
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC)
	@echo "✓ 설치 위치: $$(go env GOPATH)/bin"
	@command -v protoc-gen-go >/dev/null \
	  || echo "  ⚠ 이 디렉터리가 PATH에 없다 — make generate 전에 넣어야 한다: export PATH=\"\$$PATH:\$$(go env GOPATH)/bin\""
