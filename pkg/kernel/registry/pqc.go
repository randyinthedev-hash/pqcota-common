package registry

import "strings"

// PQCKind — PQC 알고리즘 종류.
type PQCKind string

const (
	KindKEM       PQCKind = "KEM"
	KindSignature PQCKind = "signature"
)

// PQCMaturity — PQC 알고리즘의 표준화 성숙도. FIPS 라우팅·remediation 분기의 입력.
// 등급(PQC vs 고전)에 "표준이냐 실험이냐" 축을 더한다.
type PQCMaturity string

const (
	MaturityFIPS         PQCMaturity = "fips-standard" // FIPS 203/204/205 최종 표준 (2024.08)
	MaturityDraft        PQCMaturity = "draft"         // 표준화 진행/전신 (Kyber·Dilithium·SPHINCS+·Falcon·HQC)
	MaturityExperimental PQCMaturity = "experimental"  // 연구·대안 (BIKE·FrodoKEM·McEliece·sntrup·MAYO·CROSS)
	MaturityBroken       PQCMaturity = "broken"        // 파훼됨 (Rainbow·GeMSS·SIKE)
)

// PQCAlgorithm — PQC 알고리즘 참조 항목(공개 참조 데이터, 수용 원칙 §2.3). 협상 그룹/알고리즘명에서 매칭한다.
type PQCAlgorithm struct {
	Family   string  // "ML-KEM", "Falcon" 등
	Kind     PQCKind // KEM | signature
	Maturity PQCMaturity
	Standard string   // 표준 문서(예 "FIPS 203"). 표준 아니면 ""
	tokens   []string // 정규화(대문자·구분자 제거) 후 부분문자열 매칭 토큰
}

// FIPSValidatable — FIPS 검증 대상(최종 표준) 여부. 규제 자산 provider 라우팅의 게이트.
func (a PQCAlgorithm) FIPSValidatable() bool { return a.Maturity == MaturityFIPS }

// DefaultPQCAlgorithms — 초기 시드(프로비저닝 설계 §4.2, OpenSSL/OQS·JCA 공통 어휘). 표준→진행→실험→파훼 순.
var DefaultPQCAlgorithms = []PQCAlgorithm{
	// ── FIPS 최종 표준 ──
	{Family: "ML-KEM", Kind: KindKEM, Maturity: MaturityFIPS, Standard: "FIPS 203", tokens: []string{"MLKEM"}},
	{Family: "ML-DSA", Kind: KindSignature, Maturity: MaturityFIPS, Standard: "FIPS 204", tokens: []string{"MLDSA"}},
	{Family: "SLH-DSA", Kind: KindSignature, Maturity: MaturityFIPS, Standard: "FIPS 205", tokens: []string{"SLHDSA"}},
	// ── 표준화 진행/전신 ──
	{Family: "Kyber", Kind: KindKEM, Maturity: MaturityDraft, tokens: []string{"KYBER"}},               // ML-KEM 전신
	{Family: "Dilithium", Kind: KindSignature, Maturity: MaturityDraft, tokens: []string{"DILITHIUM"}}, // ML-DSA 전신
	{Family: "SPHINCS+", Kind: KindSignature, Maturity: MaturityDraft, tokens: []string{"SPHINCS"}},    // SLH-DSA 전신
	{Family: "Falcon", Kind: KindSignature, Maturity: MaturityDraft, tokens: []string{"FALCON"}},       // FN-DSA(FIPS 206 미확정)
	{Family: "HQC", Kind: KindKEM, Maturity: MaturityDraft, tokens: []string{"HQC"}},                   // 2025 NIST 백업 KEM 선정, 표준화 예정
	// ── 연구·대안 (비FIPS) ──
	{Family: "BIKE", Kind: KindKEM, Maturity: MaturityExperimental, tokens: []string{"BIKE"}},
	{Family: "FrodoKEM", Kind: KindKEM, Maturity: MaturityExperimental, tokens: []string{"FRODO"}},
	{Family: "Classic-McEliece", Kind: KindKEM, Maturity: MaturityExperimental, tokens: []string{"MCELIECE"}},
	{Family: "NTRU-Prime", Kind: KindKEM, Maturity: MaturityExperimental, tokens: []string{"SNTRUP"}}, // OpenSSH sntrup761
	{Family: "MAYO", Kind: KindSignature, Maturity: MaturityExperimental, tokens: []string{"MAYO"}},
	{Family: "CROSS", Kind: KindSignature, Maturity: MaturityExperimental, tokens: []string{"CROSS"}},
	// ── 파훼됨 ──
	{Family: "Rainbow", Kind: KindSignature, Maturity: MaturityBroken, tokens: []string{"RAINBOW"}},
	{Family: "GeMSS", Kind: KindSignature, Maturity: MaturityBroken, tokens: []string{"GEMSS"}},
	{Family: "SIKE", Kind: KindKEM, Maturity: MaturityBroken, tokens: []string{"SIKE"}},
}

// MatchPQC — 협상 그룹/알고리즘명에서 PQC 알고리즘을 식별한다.
// 예: "X25519MLKEM768"→ML-KEM(fips-standard), "sntrup761x25519-sha512@openssh.com"→NTRU-Prime(experimental),
// "x25519"→(false, 고전). PQC 토큰이 없으면 ok=false.
func MatchPQC(name string) (PQCAlgorithm, bool) {
	n := normalizeAlgo(name)
	for _, a := range DefaultPQCAlgorithms {
		for _, t := range a.tokens {
			if strings.Contains(n, t) {
				return a, true
			}
		}
	}
	return PQCAlgorithm{}, false
}

// normalizeAlgo — 대문자화 + 구분자(-, _, 공백, .) 제거. "ML-KEM-768" → "MLKEM768".
func normalizeAlgo(s string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(strings.ToUpper(s))
}
