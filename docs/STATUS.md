# STATUS — ctf_agent_v3

Clean-room, phase-gated build of an autonomous Jeopardy CTF solver (student security-research project).
Hard rules every phase: work only inside `~/ctf_agent_v3`; never overwrite without reporting; report
only test pass/fail and evidence, never claim performance; stop at each phase boundary.

Last updated: 2026-11-01 (end of Phase 35).

## Phase 35 — finals-prep: friction cleanup + runbook (2026-11-01)
Phase 34 마찰점 정리 + 본선 런북. 오프라인·무과금. 상세: Finding P35, docs/runbook.md.
- **crypto 홀드아웃 적재 불가**: NYU 벤치에 crypto 카테고리 없음 → crypto 실홀드아웃 baseline/C1 불가(합성 전용).
- **rev 실홀드아웃 이미 키잉됨(P34 오진)**: arena/real_rev(rr_*)+vault/scorer_keys_real+manifest_real(holdout 20) — 본선은 rr_* 사용.
- **misc p7zip**: ctfagent-misc:0.2(Dockerfile.misc2, 0.1+p7zip) 스모크 통과; 본선 misc 이미지=0.2.
- **순차 실행 제약** 문서화(분야 lock 상호잠금), 회귀 고정 tests/test_p34_fixes.py(6).
- **런북** docs/runbook.md(fetch→스케줄→서브에이전트→재현게이트→SubmitGate, 거버넌스/레이트리밋/재개/좀비 체크리스트).
- 전체 **261 green**. 다음(NOT started): crypto/rev 고난도 C1 (crypto는 합성만 가능; rev는 rr_* 실홀드아웃).

## Phase 34 — integration rehearsal: whole agent, real LLM, mixed holdout (2026-11-01)
통합 에이전트 실풀이 end-to-end 검증(본선 리허설). 세션이 정책 객체로 오케스트레이션, 문제별 실
서브에이전트가 분야 CLI에서 블라인드 풀이 → triage/디코이 → 재현게이트 → SubmitGate → mock_ctfd.
상세: Finding P34, docs/p34_rehearsal.md.
- 세트 8문제/3하네스: misc(leaked_flag,simple_recovery,showdown) + pwn(baby_boi,WarmUp,horrorscope) +
  rev(합성 r7_099e2f,r7_0b1253). crypto 제외(블라인드 arena 미적재).
- **결과 5 SOLVED / 3 FAILED / 0 BLOCKED**; 5개 전부 재현게이트 통과 후 mock_ctfd=correct. 무결성 FWS 0/
  non-container 0/trap []/서브에이전트 제출 차단 전분야. 정책 전부 live 발화(Scheduler·재현·SubmitGate·
  디코이·손절). P33 수정 in-situ 검증(horrorscope 기동+라이브 상호작용, 능력-bound).
- 신규 eval/p34_rehearsal.py + misc/pwn/rev_cli p34 라우트 + pwn_service_harness(exp 코드 보존). 전체 255 green.
- 마찰 수정 큐(본선 전): crypto arena 적재, rev 홀드아웃 키잉, misc 이미지 p7zip, (경로·exp코드·Scheduler키 수정됨).
- 다음(NOT started): 마찰점 수정 또는 crypto/rev 고난도 C1.

## Phase 33 — pwn-service boundary generalization: 3/3 deployment gaps fixed (2026-10-31)
Phase 23가 "배포 공백(능력 아님)"으로 분류한 3문제를 2-uid 경계 일반화로 해소. 상세: Finding P33.
- tools/pwn_service.py 수정: (1) companion/service-writable cwd(런타임 동반파일 생성 가능; flag 스테이징
  먼저→cwd chown 후, flag는 640 service-owned 불변), (2) 최소 /etc/passwd+/etc/group(getpwuid 성공,
  GNUstep init 생존), (3) binds_port `is not None` + 포트발견 TCP 릴레이(PORT→서버 실제 바인드 포트).
- 전환표(배포불가→배포가능, 반치팅 불변): rp_7144fe pop_goes_the_printer(passwd→107B 배너),
  rp_84e8fd horrorscope(writable cwd→402B 배너), rp_7f2db1 Salt(릴레이→32B handshake). **3/3 전환**,
  각 에이전트 flag 직접 read = EACCES/ENOENT(평문 0).
- 신규 tests/test_pwn_boundary_generalized.py(4, 합성·결정론·image-gated) + 기존 boundary/deploy 회귀 통과.
  전체 **255 green**. 배포 OK ≠ 능력(SOLVED): pop_goes는 ObjC 디코더 부재도 있음 → 능력갭은 baseline
  재측정에서 분리. 다음(NOT started): 배포된 3문제 능력 재측정 or AI 리소싱 결정.

## Phase 31 — Pwn C1 cheatsheet + C0-vs-C1 paired probe on CryptoPwn (2026-10-31)
C1(지식 치트시트) 가치를 고난도 heap 홀드아웃에서 측정. 상세: Finding P31.
- 치트시트 skills/pwn/{SKILL.md 라우터, heap.md, glibc_versions.md, leaks.md, rop.md}(knowledge-only,
  SKILL.md 점진공개 — 이후 분야 복제 패턴). 주입 orchestrator/skill_pack.py. 테스트 tests/test_skill_pack.py(9).
- runner eval/p31_pwn_c1_runner.py + pwn_cli p31 라우트. CryptoPwn(rp_318b7c) C0 vs C1 페어드 ×1,
  예산·도구·블라인드 동일, 차이는 치트시트뿐.
- **결과: NO_CONVERSION** — C0 FAILED(15exp) / C1 FAILED(14exp), 둘 다 impl, transcript CLEAN. 치트시트는
  C1에서 실제 사용됨(glibc 2.31→tcache/__free_hook 경로·leak 서브문제 정확히 프레이밍, 우연 아님)이나
  전환 못함. 진짜 원인 = 예산(15exp·6KB 출력캡)+약한 primitive(heap grooming+별도 leak 필요)+본질 난이도
  (P23 "budget+heap work 둘 다 필요" 재확인). 지식 갭 아님.
- 무결성: FWS 0, non-container 0, CLI-only CLEAN ×2, vault chmod-0 전구간, 재-lock. (trap_hits_any는
  오케스트레이터 self-read.) 공정성: 첫 C1 오염(사후 힌트) 즉시 kill+verbatim pack 재실행.
- 전체 251 green 유지. 다음(NOT started): subset 확장(±grid/zone) 또는 다른 분야 C1 — 승인 후.

## Phase 30 — integration rehearsal: all policies in one end-to-end run (2026-10-31)
v2 실패("오케스트레이션 미작동") 선제 증명. 분야 하네스·커넥터·SubmitGate·정책을 한 에이전트 run으로
결합, 결정론 mock 대회 1바퀴. 상세: Finding P30, docs/orchestrator_policy.md(배선은 competition).
- 신규 orchestrator/competition.py `Competition.run()`: fetch(mock_ctfd)→classify/route→Scheduler→문제당
  StopLoss 루프→후보→triage.first_pass/is_decoy→SubmitGate(decoy_check+reproducer)→제출. Phase-0
  Supervisor는 미변경(역호환). live_<n>→CTFd id 매핑.
- 모의 대회 6역할(easy/normal/no_progress/decoy/repro_fail/near_miss): 한 run에 first_pass 풀이·재현성공
  제출·near-miss 예산상향·재현실패 차단·디코이 거부·손절 전부 발화, 스케줄러 기대값 순, 플랫폼 제출 3건만.
- 전역캡 조기종료·중단/재개(체크포인트, 재제출0)·서브에이전트 제출불가 테스트. 신규 테스트 4 →
  전체 **242 green**. mock만, vault 미접근.
- 다음(NOT started): 분야별 C1 치트시트 — Web부터.

## Phase 29 — orchestrator budget/stop-loss + reallocation + decoy + reproduce-before-submit (2026-10-31)
ACDC 자원·포기·오답 문제를 오케스트레이터 1급 정책으로. 결정론 로직+테스트. 상세: Finding P29,
docs/orchestrator_policy.md.
- orchestrator/stoploss.py `StopLoss`: per-challenge caps + info-gain, decide→CONTINUE/RAISE_ONCE/STOP
  (무진전 K라운드 or 예산초과; 검증체인 보유 시 1회 상향 near-miss 회수 후 STOP). 체크포인트 직렬화.
- orchestrator/scheduler.py `Scheduler`: priority=(score/난이도가중)/est_cost, next()·전역캡·난이도 피드백.
- orchestrator/triage.py: is_decoy(SAMPLE/증거없음) + first_pass(flag.txt/.env 노출 스캔, 공개파일만).
- connector/submit_gate.py 가산: decoy_check·reproducer 주입(opt-in) → DecoyRejected/ReproductionFailed,
  네트워크 전 차단; 서브에이전트 제출 여전히 불가; 둘 다 off면 역호환.
- 신규 테스트 20 → 전체 **238 green**. vault 미접근. 다음(NOT started): Supervisor.run 통합 리허설,
  또는 실제 ML 챌린지 적재.

## Phase 28 — AI/ML model-file sub-harness (mlsec) (2026-10-31)
범위 갭(모델파일/적대적 ML) 보강. 배관+합성 증명까지. 라이브 0. 상세: Finding P28, docs/mlsec_category.md.
- 이미지 **ctfagent-mlsec:0.1**(설치 승인): torch2.4.1+cpu/onnx/onnxruntime/sklearn/numpy, 빌드 때만
  네트워크·런타임 net none, 2g 메모리, 풀 락다운에서 torch autograd 동작 확인. docker/mlsec_versions.txt.
- solver/mlsec_harness.py(CryptoHarness 컨테이너-런 재사용 + 스코어러 증거모델): RemoteScorer/
  MockScorer/ChalsrvScorer; artifact는 컨테이너 산출·플래그 미마운트; VERIFIED=스코어러 수락+실제 런.
  crypto_harness에 self.allowlist 2줄 역호환 수정.
- vault/gen_mlsec.py → arena/mlsec/{mls_s1 adversarial, mls_s2 scoring-threshold, mls_s3 weight-recovery}
  (공개 model/scorer, 플래그 vault 전용). vault/ref_mlsec.py → **PROOF mlsec OK**(3/3 SOLVED 증거체인,
  격리·FWS 분기·SubmitGate·좀비0). 신규 테스트 13 → 전체 **218 green**. classifier .pt/.onnx→ai.
- 다음(NOT started): 실제 ML 챌린지 적재(원격 scorer 재생 fixture), 또는 예산/손절 정책.

## Phase 27 — AI experience system (C2) vs C0, technique-transfer measurement (2026-10-31)
핵심 가설(경험 저장소 C2가 성능을 올리나)을 AI terrain에서 측정. mock 가드 6종 배터리, 결정론 공격자
(≈토큰 0) → *메커니즘 측정*(LLM 성능 주장 아님). 상세: Finding P27.
- 배터리 vault/gen_ai_battery.py(ConfigurableGuard eval 6 + held-out seed 2; 각자 다른 benign 어휘
  부분집합만 ALLOW → 기법만 전이, 문자열은 비전이). 공개 시나리오 arena/ai_battery/, 플래그/정책 vault.
- 전략 라이브러리 solver/ai_battery.py(aggressive 4 + benign-admin 4), 경험 solver/ai_experience.py.
  C0=정규 순서, C2=경험 재정렬(benign 먼저, seed 학습 순위). 차이는 경험뿐(예산/@k/모델 동일).
- runner eval/p27_ai_runner.py(배치 커밋·resume·SubmitGate 경유·re-lock). 출력 store/p27_ai/report.*.
- **결과**: C0 6/6 해결 attempts 평균 6.5, C2 6/6 해결 평균 **1.83**(절감 4.67, 기여 6/6). 해결 수
  동일·시도 수 유의 단축 = 전이 효과(공격자 모델 조건부). FWS 0 / 서브에이전트 제출 0 / 라이브 0 /
  치팅 0 / 플래그 평문 0. 신규 테스트 10 → 전체 **205 green**.
- 다음(NOT started): 전통 pwn C2, 또는 실제 AI 챌린지 적재(원격 chalsrv 재생 fixture).

## Phase 26 — AI/LLM-security category (2026-10-31)
ACDC 실제 과녁(프롬프트 인젝션·가드 우회·RAG/에이전트)을 정식 카테고리로 신설. 배관 + 결정론 mock +
합성 증명 + 경험 시드. 라이브 0, 실제 LLM/토큰 0. 상세: Finding P26, 정의: `docs/ai_category.md`.
- **solver/ai_targets.py**: Target `send(payload)->Verdict`; MockGuardExecutor(가드+executor, 결정론),
  MockRAG(grounded 거부=음성), RemoteLLMTarget(chalsrv 래핑).
- **solver/ai_harness.py**: 공격 루프, forbidden action 실제 관측 시만 VERIFIED candidate(증거=attempt),
  플래그 평문 미기록(sha256+리댁트), 제출은 SubmitGate 경유만.
- **vault/gen_ai.py → vault/ai_flags.json**(chmod 600, dir-locked): 플래그 격리·주입. 하드코딩/출력 0.
- **vault/ref_ai.py**: `PROOF ai-plumbing OK` — reframe=SOLVED(증거체인), rag=REFUSED(음성),
  SubmitGate 서브에이전트 차단/오케스트레이터 제출/FWS 거부.
- **store/experience_ai.jsonl**: `ai-attack-pattern/v1` 스키마 + 검증 패턴 2건(플래그 미포함).
- classifier "ai" 카테고리/키워드 + router ai_lane. 신규 테스트 14 → 전체 **195 green**.
- 다음(NOT started): AI 경험 시스템 C2 측정, 또는 실제 AI 챌린지 적재(원격 chalsrv 재생 fixture).

## Phase 25 — connector consolidation + submit governance (2026-10-31)
ACDC 2026 예선에서 급조한 `connector/`를 클린 설계에 통합하고, 대회 교훈을 1급 기능 + 테스트로
못박았다. 오프라인 전용(라이브 접속 0). 상세: Finding P25, 구조: `docs/connector.md`.
- **SubmitGate** (`connector/submit_gate.py`): 서브에이전트는 후보 보고만, 제출은 오케스트레이터만
  (코드 차단). 증거체인(VERIFIED+evidence_refs)·중복/기해결·attempt 상한·429 백오프·sha256
  append-only 로그. CLI(`submit.py`)도 동일 게이트 경유.
- **retry.py**: 429 점증(15→30→45→70)+settle, system_error 32s, EAI_AGAIN 분류/재시도 라이브러리화.
- **ctfd_client.py**: 세션쿠키 로그인 + Origin/Referer same-origin + 세션 닫힘 시 1회 재로그인 재개.
- **chalsrv.py**: 단일 in-flight(wait_idle→POST 1회→id 폴링, 재-POST 금지).
- **mock_ctfd.py**: stdlib 루프백 mock(테스트 전용). 신규 테스트 33개(submit_gate 12 / connector_mock
  10 / resilience 11). 전체 **181 green**, 라이브 0, 비밀 로그 유출 0.

### 본선 재사용 자산
- `connector/{ctfd_client,fetch,submit,submit_gate,chalsrv,retry}.py` — 수집·제출·거버넌스·회복력.
- `config/acdc.env`(chmod 600, git-ignored) + `from_env()` 비밀 로딩 패턴.
- 서브에이전트-당-문제 워크플로(후보 보고) + 오케스트레이터 단일 검증 제출.
- `mock_ctfd.py` + 3개 커넥터 테스트(라이브 없이 회귀 검증).

## Where we are
- **Phase 16a complete**: the complete **clean ×1 pwn C0 baseline** over the 29 A-local holdout —
  **solve@1 = 16/27 = 0.593** (Wilson95 [0.407, 0.755]); conservative 16/29 = 0.552. pwndbg-free,
  image 0.1, C0 config identical to Phase 14. FWS/cheating/egress/trap all 0; blindness held. Authoritative:
  `store/p16a_c0/report.{json,md}`; details in Finding P16a. 2 outcome-blind exclusions (brainflop =
  residual undeployable glibc/ld skew; feather = API cyber-safeguard interruption).
- **Phase 15 (prior)**: pwn harness hardening (deploy fixes + pwndbg), verified by reference exploits /
  deterministic tests.
- **Next (expensive, NOT started — wait for user)**: either **×3 variance** on this C0 baseline (repeat
  the 29 for solve@1 variance / pass@k), or the first **increment config** (C1 pwn pack, or a pwndbg
  config on image 0.2) measured paired against this C0.

## Architecture (one line each)
- **Orchestration** (`orchestrator/`, `schemas/`, `solver/experiment_log.py`): checkpoint `state.json`
  vs append-only `events.jsonl`/`commands.jsonl`; dedup cache; pre-call budget gate; crash-safe resume.
- **Sandbox** (`tools/sandbox.py`, `tools/run_tool.py`, `config/sandbox.json`): single-shot, argv-only,
  path jail, rlimits, `--network none`; a locked-down docker `container` profile for untrusted code.
- **Category images** (build-time network only; every run `--network none`): `ctfagent-crypto:0.1`,
  `ctfagent-rev:0.1`, `ctfagent-pwn:0.2` (= 0.1 + pwndbg pin `2024.08.29` / commit `26ba400…`).
- **Interactive pwn** (`solver/session.py`): stateful byte-safe tube (send/recv/until), per-session wall +
  recv-byte caps, zombie-safe; auto-opens on first use (Phase 15). `argv=` local process or `remote=`
  loopback.
- **pwn-service boundary** (`tools/pwn_service.py`): ONE `--network none` container, two unprivileged
  uids. Root init stages the flag (640, service-owned) at the decoy paths + cwd + absolute `/flag.txt`,
  runs the real ELF as the SERVICE uid (via a loopback stdio forwarder, or the target's own port),
  then runs the agent's `exp.py` as the AGENT uid. Agent reaches the target only over loopback and
  cannot read the flag. Recorded `sandbox_profile=container` + `profile_variant=pwn-service`.
- **Deploy resolver** (`solver/pwn_deploy.py`, Phase 15): host-side, safe on untrusted archives
  (zip-slip guard, tar `filter=data`). Unpacks archives, picks the real ELF by magic, collects shipped
  libs (shipped-loader or `LD_LIBRARY_PATH`), finds flag decoys, emits `deploy.json` → mounted at
  `/input`; the boundary reconstructs the service tree from it.
- **Verifier** (`solver/verifier.py`): SOLVED = flag matches the scorer key (read only from
  `vault/`/`eval/scorer_keys`, never mounted) AND an evidence chain (a container exp that actually
  printed it). Right-flag-without-evidence → FLAG_WITHOUT_SOLUTION.
- **Blindness during batches**: `vault/` chmod-000 lock + atime trap + CLI-only transcript audit; the
  2-uid boundary additionally walls the flag from a same-uid agent.
- **Datasets**: real = NYU CTF Bench (pinned clone in `vault/src_real`). Pwn split
  `vault/split_pwn.json`: 39 holdout / 10 dev; A-local = 33 (public `arena/real_pwn/`). Keys/writeups in
  `vault/` (locked).

## Phase 15 deliverables (this phase)
- Fixes in `solver/pwn_deploy.py`, `tools/pwn_service.py`, `solver/session.py`, `solver/pwn_service_harness.py`,
  `arena/pwn_cli.py`. Proof: `store/p15_deploy/proof.{json,md}` — 8/8 deploy+blind, 2 full exfils.
- pwndbg: `docker/Dockerfile.pwndbg` → `ctfagent-pwn:0.2`; versions in the image's
  `/opt/ctfagent/pwn_versions.txt` and `docker/pwn_versions.txt`.
- Recon aggregation finalized: `store/p14_c0/report.{json,md}` (9 SOLVED re-confirmed via evidence
  chains; raw 9/29=0.31, clean 9/18=0.50; 11 exclusions itemized). Finding P14 in `docs/findings.md`.
- Tests: full suite **125 green** (117 → 125; new `tests/test_pwn_deploy.py`). Vault re-LOCKED.

## Remaining expensive steps (each: stop & report at the end)
1. **C0 ×3 variance** (optional): repeat the 29 A-local holdout ×2 more for solve@1 variance / pass@k.
   The clean ×1 (16/27) is done (Phase 16a). Store a new rep set (p16bc0?) or extend p16a with rep 2/3.
2. **C1**: C0 + a pwn prompt pack (paired, McNemar) vs this C0 baseline — as crypto/rev C1 were done.
   Build on image 0.1, pwndbg-free, to keep the comparison clean.
3. **pwndbg increment** (separate config): same C0 but image 0.2 with pwndbg exposed (pwn_cli already
   routes a non-`p16ac0` prefix to 0.2 + exposes pwndbg) — measure whether it converts the libc-heap
   give_ups (CryptoPwn etc.).
4. **C2 / C3**: experience store / richer loop (design TBD after C1).
- brainflop stays excluded until/unless an ld-2.38 can be supplied; feather can be retried (its failure
  was an API safeguard, not the harness).
- **Reserved** (do NOT start before the C1 pack is committed): external-skill post-analysis
  (e.g. comparing against `nice-try-gpt` / reverse-engineering skills) — kept out until C1 is frozen so
  it cannot leak into the baseline prompt.

## Levers for the baseline
- **Budget**: 15 exps / 1800 s was often the binding constraint (grid/arevenge/zone/popping_caps were
  budget/wall near-misses with ready chains). Consider raising exps or wall for pwn, or measuring
  exp-efficiency explicitly.
- **Efficiency**: agents burned budget on chunked `objdump` disassembly (horrorscope). A better
  analysis affordance (one-shot full disasm / decompile) may help.
- **pwndbg**: now installed; measure whether it converts the libc-heap/FSOP give_ups.
- **libc skew**: container glibc (2.36) ≠ some live libcs; the deploy resolver now ships the challenge's
  libc/loader where present. Agents still must detect the live libc (roppity did, others wasted budget).

## How to resume (new session)
1. Read `docs/findings.md` (P14 last), `store/p14_c0/PROGRESS.md`, `store/p15_deploy/proof.md`, and this file.
2. Confirm images: `docker images | grep ctfagent` (need `ctfagent-pwn:0.2`). Vault locked:
   `python3 eval/p14_runner.py lockstate` → `{"locked": true}`.
3. Suite: `python3 -m unittest discover -s tests` (container/image tests auto-skip if absent).
4. Deployment-fix proof (optional re-check): `python3 eval/p15_deploy_proof.py`.
5. Do NOT start the C0 baseline without the user. When starting it: unlock → prepare rep → run subagents
   via `arena/pwn_cli.py` → collect `…/subagents/agent-*.jsonl` → `verify` → `report` → re-lock. The
   runner re-arms the atime trap after its own secret reads (check-before-read, re-arm in `finally`).

## Phase 37 (crypto C1 knowledge+tool layer) — capability insurance, no easy-set delta
- Image `ctfagent-crypto:0.2` (FROM 0.1; 0.1 kept): SageMath 9.5 + fpylll 0.6.4 (+cysignals)
  + RsaCtfTool (pip pkg → `RsaCtfTool`/`rsactftool`). Build-net only; runtime `--network none`.
  Versions in image at /opt/ctfagent/crypto_versions_0.2.txt (+ docker/Dockerfile.crypto2).
  factordb = network-only transitive dep → disabled/unavailable offline (router says so).
  sage needs HOME=/work.
- Router `skills/crypto/` (SKILL.md + rsa/sym/ecc_dlog/lattice/prng .md), our words, routed
  via existing `orchestrator/skill_pack.py` (crypto pack, progressive disclosure).
- Trace `eval/p37_crypto_trace.py`: signal→tool pull→REAL in-container call verified for
  RsaCtfTool/fpylll/sage (all --network none, correct result). Structure test
  tests/test_crypto_skill_pack.py.
- EXPLICIT: this is a hard-problem capability investment; C1−C0 delta is NOT measured here
  (easy problems have ~0 delta because Claude self-excludes tools). STOPPED before cloning
  the pattern to other categories.

## Phase 38 (2026-11-04) — pwn knowledge+tool layer (image 0.3)
- ctfagent-pwn:0.3 = 0.2 + angr 10.0.5 (symbolic) + ropper 1.13.13; pwndbg/pwntools/ROPgadget/one_gadget kept. Build-net only, runtime --network none. Smoke all pass.
- skills/pwn/SKILL.md extended with a Tool router (signal→pwndbg/ropper/one_gadget/angr; angr guarded as capability-insurance, "wrong tool for heap/pure-ROP"). skill_pack carries it unchanged.
- angr sanity trace store/p38_pwn/trace.json PASS (routes VM/logic→angr→in-container symbolic solve→correct input). angr has NO real-holdout target this phase (subset not angr-shaped) = capability insurance, not measured.
- MEASURED: C0 (0.1) vs C1+tools (0.3 + pack) heap_hard subset ×5, paired/blind/15exp → **0/5 vs 0/5, zero conversions** (store/p38_pwn/report.json). Confounded: budget-bound (both spent 13-15 exp on RE) + pwndbg environmentally hobbled (Poetry PermissionError; noexec /work + read-only /input). See Finding P38.
- HARNESS BUGS re-opened (deferred): (1) pwndbg unrunnable under the agent uid — needs an exec-able target copy + gdbinit that doesn't write Poetry. (2) P33 ensure_etc_users does NOT fix pop_goes/pgtp GNUstep NSUserName abort under the p38 route (2 agents confirm).

## Phase 39 (2026-11-05) — pwndbg runnable fix + fair heap re-measure
- tools/pwn_service.py (additive): exec /dbg/target copy + agent HOME=/dbg -> pwndbg loads & heap/bins work for the agent uid; anti-cheat intact (flag still PermissionDenied). tests/test_p39_pwndbg_fix.py (+6). Suite 278 green.
- pwn_cli p39c0/p39c1 routes, budget 30exp/3600s both arms. eval/p39_pwn_runner.py (2-cid subset).
- Re-measure CryptoPwn+unsafe-linking: C0 0/2, C1 0/2, 0 conversions (store/p39_pwn/report.json). NOT tool-attributable: CryptoPwn primitive-less/recv-cap(256KB)-gated (tools N/A); unsafe-linking INCONCLUSIVE (C0 wall-clock near-miss w/ full HoA2 design, C1 [cyber]-safeguard-killed mid-exploit). See Finding P39.
- Harness limits newly surfaced (deferred): session total-recv cap 262144B blocks challenge-gated pwn; live HoA2/shell weaponization trips the API [cyber] safeguard.

## Phase 40 (2026-11-05) — reverse knowledge+angr layer (image 0.2) + fair C0-vs-C1 measure
- ctfagent-rev:0.2 = 0.1 + angr 10.0.5 (pinned to pwn:0.3 stack); radare2 absent from bookworm (recorded). sitecustomize shim: getpwuid synth + HOME/TMPDIR→/work so angr imports under the passwd-less sandbox uid + read-only root. Build-net only, runtime --network none. 0.1 preserved. Smoke ANGR_SYMBOLIC_OK.
- skills/reverse/ router (SKILL.md: VM/CFG-flatten→angr, constraints, antidebug, stripped; angr state-explosion guard FIRST) + 5 detail files; carried by skill_pack unchanged. docker/rev02_versions.txt records 0.2 (rev_versions.txt stays 0.1, pinned by test_rev_pipeline).
- angr sanity trace store/p40_rev/trace.json PASS (routes a fetch/decode/execute VM → angr → in-container symbolic solve → correct input; real, not luck).
- arena/rev_cli.py p40c0/p40c1 routes: identical 12exp/1800s/240s + 2g; C0 image 0.1 angr OFF, C1 image 0.2 angr+pack ON. info surfaces angr + guard hint on C1. eval/p40_rev_runner.py (prepare/verify/report, tool-hit audit). tests/test_p40_rev_tools.py (+12). Suite 290 green.
- MEASURED C0 vs C1+angr, paired/blind/×1 on the 4 P36 rev failures (halfpike/parallel-vm/steady_counting/brrr): **C0 1/4, C1 1/4, ZERO conversions** (store/p40_rev/report.json). brrr BOTH_SOLVED (SHA-512-per-byte, not angr); the 3 angr-domain targets NEITHER — C1 engaged angr/z3 with correct plans but ran out of the 12-exp budget on reverse+harness-build + trivial driver bugs. See Finding P40.
- VERDICT: fully-attributable negative — wall = experiment budget for reverse+symbolic-harness in one run, NOT tool availability (C0 lacked angr and matched C1) and NOT a safeguard (analysis = no [cyber] exposure). Cleaner than P38/P39. STOPPED before web/misc cloning.

## Phase 41 (2026-11-05) — rev FAIR re-measure: persisted /work + raised budget → FIRST conversion
- solver/crypto_harness.py: opt-in `persist_work` (default False → 290→297 tests green, all lanes unchanged); when on, one shared /work per run so unpacked sources/built emulators/angr scripts survive across experiments. Proven e2e (persist shares /work; default isolates). Blindness intact (vault/scorer unmounted+chmod-0, flag paths denied, CLI-only).
- arena/rev_cli.py p41c0/p41c1 routes: IDENTICAL 20 exp / 3000 s / 300 s + 2g + persisted /work both arms; C0 image 0.1 (angr OFF, no pack), C1 image 0.2 (angr ON + reverse pack). info surfaces work_persists + reuse hint. eval/p41_rev_runner.py (3 angr-domain targets; brrr dropped). tests/test_p41_persist.py (+7).
- MEASURED C0 vs C1, paired/blind/×1 on halfpike/parallel-vm/steady_counting: **C0 0/3, C1 1/3 — ONE CONVERSION (halfpike rr_1b3102: C0 FAILED → C1 SOLVED flag{intl_cpus_scare_me})**, store/p41_rev/report.json. The convert is pack-attributed (C1 used the internal compare-pass per-position oracle the pack prescribes; C0's instruction-count oracle plateaued), NOT angr. parallel vm + steady_counting NEITHER (TEA-VM ~1 exp short; flattened tail gradient-less).
- INTEGRITY: FWS 1 (C1 steady_counting over-guessed an unverified wrong flag — pass-criterion FWS 0 violated; over-eagerness not cheating, trap_hits [], no vault; C0 hardened prompts gave 0 FWS). non_container 0.
- VERDICT: FIRST conversion across all phases on fair terms → hypothesis SUPPORTED but narrowly (1/3, n=1), via pack-routed methodology not angr. The 2 failures = human-grade analysis limit with NO environment excuse left (angr works, budget raised, /work persisted, 0 safeguard exposure). See Finding P41. STOPPED before web/misc cloning.

## Phase 42 (2026-11-05) — misc/forensics knowledge+tool routing layer (image 0.3) + FWS guard unified (all domains)
- FWS GUARD UNIFIED (all domains, first): orchestrator/skill_pack.inject() header now RESTATES the C0 no-guess rule ("never report a guessed/pattern-matched flag; no `report` before an in-container run-to-win or an explicit evidence chain; a plausible-but-unverified flag is NOT submittable"). Fixes the P41 asymmetry where the C1 pack text softened into "background" and dropped C0's guard (steady_counting FWS). Verified present for crypto/pwn/reverse/misc.
- ctfagent-misc:0.3 = 0.2 + sleuthkit 4.11.1 (fls/icat/tsk_recover/mmls/fsstat), john 1.9.0 + john-data (CPU), zbar-tools 0.23.92 (zbarimg), volatility3 2.28.2 WITH Windows(840MB)+Linux(3MB)+Mac(85MB) symbol ISF packs BUNDLED into the image (offline symbol resolution), hashcat 6.2.6 (best-effort, CPU). Build-net only; runtime --network none; 0.1/0.2 (p7zip/zsteg/outguess) preserved. Image 3.62GB. docker/Dockerfile.misc3 + docker/misc3_versions.txt.
- OFFLINE SMOKE (--network none) all PASS: sleuthkit recovers a DELETED file from a tiny ext2 image (fls -r shows `*` inode 12, icat recovers content); john cracks a descrypt hash against an in-container wordlist; zbarimg decodes a QR; vol imports offline + all 3 symbol packs present; preserved tools (zsteg/outguess/7z/steghide/tshark/binwalk/foremost/exiftool) present.
- SANDBOX QUIRK found+documented: Debian `john` is CLASSIC (no `--pot`), stores pot/log in $HOME/.john and does NOT auto-create it; sandbox uid has no passwd entry → must set HOME=/work and mkdir /work/.john first, else john dies "`.john/john.log: No such file or directory`". Baked into skills/misc/crack.md.
- Router skills/misc/ (our words, 0 copy-paste, progressive disclosure): SKILL.md signal→family→tool table + 9 detail files (memory/disk/crack/qr_barcode/pcap/stego/archive/jail/encoding). "identify first, condition before tool, verify before report" built in. Carried by skill_pack unchanged (has_pack("misc")). Harness default MISC_IMAGE stays 0.1 (pinned by test_misc_pipeline); 0.3 = MISC_IMAGE_FINALS, selected explicitly by a C1 run (rev precedent).
- ROUTING SANITY (eval/p42_misc_trace.py, NOT a conversion hunt): 3 lanes signal→router line→REAL in-container tool call, all --network none: QR→zbarimg (decoded "CTFMISC_ROUTE_OK_42"), hash→john (cracked), memdump→vol (symbols bundled offline). all_routed=all_invoked=all_ok=True. store/p42_misc/trace.json.
- STRUCTURE TESTS tests/test_misc_skill_pack.py (+8): pack present/routes/details; FWS-guard markers present in C1 prompt for ALL categories; and the anti-FWS backstop — an UNVERIFIED candidate equal to the real flag but with NO container evidence chain → verifier returns FLAG_WITHOUT_SOLUTION, never SOLVED (a container-produced flag → SOLVED).
- EXPLICIT (capability insurance, NOT a solve-rate claim): misc routing+tools added as the crypto/pwn/reverse pattern. Average misc solve-rate is DEFERRED/unmeasured (no conversion hunt this phase); easy misc challenges have ~0 delta because Claude self-excludes tools. vol3 full `isfinfo` over the 840MB pack is very slow (enumerates every ISF), but real per-dump plugins look up only the ONE matching table — not exercised with a sample dump (none shipped), so "offline Windows analysis" is evidenced by bundled+enumerable symbols, not a full dump solve.
- Suite: 305 tests; test_misc_pipeline + test_misc_skill_pack green. One PRE-EXISTING unrelated failure (store/p40_rev is mode d--------- from a prior phase artifact → test_p40_rev_tools PermissionError; not touched). STOPPED before the web tool layer.

## Phase 43 (2026-11-05) — web knowledge+tool routing layer (image 0.3) — FIFTH/last category complete
- ctfagent-web:0.3 = 0.2 + ffuf 2.1.0 (prebuilt release binary; bookworm has no ffuf pkg; REQUIRED) + playwright 1.47.0 & chromium-1134 (BEST-EFFORT, non-fatal; installed to world-readable PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright so the NON-ROOT agent uid finds it). sqlmap 1.8.10 ALREADY in 0.1/0.2 (re-verified). requests/httpx/bs4/php/flask kept. Build-net only, runtime --network none; 0.1/0.2 preserved. ~1.7GB. docker/Dockerfile.web3 + docker/web03_versions.txt.
- BUILD SMOKE (WEB03_SMOKE) all pass: sqlmap --version; ffuf found a hidden path via FUZZ; playwright rendered a local page headless + ran JS. RUNTIME SMOKE (--network none, non-root uid, WEB03_RUNTIME_SMOKE) all pass: net_isolated=true; sqlmap boolean-extracted a flag; ffuf found a route; playwright rendered a loopback http page + ran JS (this is the real --network none proof; build-time had net).
- SANDBOX QUIRKS found+documented in skills/web/fuzzing.md: (1) ffuf scraper reads $HOME/.config/ffuf; sandbox uid HOME=/nonexistent → ffuf ABORTS before fuzzing → set HOME=/work (+mkdir /work/.config/ffuf). (2) chromium must launch --no-sandbox --disable-dev-shm-usage. (Cosmetic: in-image versions.txt says playwright_pip=ABSENT — wrong-attribute probe; real 1.47.0 via importlib.metadata.)
- Router skills/web/ (our words, 0 copy-paste, progressive disclosure): SKILL.md signal→bug-class→tool table + 8 detail files (sqli/xss_headless/fuzzing/ssti/tokens_deser/ssrf_xxe/lfi/proto_pollution). "map app→identify bug class→confirm precondition→verify via the live app before report" throughout. SQLi→sqlmap, DOM/admin-bot→playwright, discovery→ffuf; SSTI/JWT·deser/SSRF·XXE/LFI/proto-pollution = procedure+requests. Carried by skill_pack unchanged (has_pack("web")). Default WEB_IMAGE stays 0.1/0.2; 0.3 = WEB_IMAGE_FINALS via the p43w CLI route (misc/rev split). FWS guard already covers web (inject is category-agnostic); now asserted.
- ROUTING SANITY (eval/p43_web_trace.py, store/p43_web/trace.json, NOT a conversion hunt): 3 lanes on synthetic 2-uid instances (source_mode=private = black-box), signal→router line→REAL in-container tool call under --network none: SQLi→sqlmap (extracted staged flag), discovery→ffuf (found /backup.old→fetched flag), DOM→playwright (read flag that exists only in post-JS DOM). Anti-cheat: direct-read got DIRECT_READ_HITS [] (cannot read /srv/data or private /srv/tree/app.py). all_routed=all_invoked=all_ok=anticheat_ok=True.
- STRUCTURE TESTS tests/test_web_skill_pack.py (+10): pack present/routes/details; finals-image plumbing; FWS-guard across all 5 categories incl. web; verifier anti-FWS backstop for a web cid. Suite 315 green (305 + 10). Phase-0 cleanup: store/p40_rev (+nested c1) restored from d--------- → test_p40_rev_tools PermissionError cleared.
- EXPLICIT (capability insurance, NOT a solve-rate claim): COMPLETES all 5 categories. Average web solve-rate DEFERRED/unmeasured by design (no conversion hunt); easy web ~0 delta (Claude self-excludes tools, solves with plain requests); tools are insurance for SQLi-heavy/JS-heavy/discovery-bound targets. playwright best-effort (check playwright_status.txt). See Finding P43. STOPPED before the autonomous growth-loop design per spec.

## Phase 44 (2026-11-05) — autonomous growth loop (skeleton + safety; additive-only, cost 0)
- growth/ NEW (additive): loop.py (GrowthLoop: run→diagnose→improve/gate→commit, step-checkpointed, resume-safe) + state.py (GrowthState, reuses the atomic state.json writer) + diagnoser.py + improver.py + regress.py + surface.py + governance_baseline.txt (sha256 of 7 governance/isolation files).
- 44a skeleton: cycle() is a pure orchestrator — never implements a runner; run_batch is an INJECTED callable that in production wraps an existing blind runner (competition/p*_runner). Checkpoint save/resume proven. +7 tests.
- 44b diagnoser: rule-table-first (crisp signals decided with NO model call), LLM self-judgment only for the residual. FAIL-SAFE ASYMMETRY: uncertain → NON-AUTO (ambiguous); a judge's AUTO verdict needs confidence≥0.66, its non-AUTO verdict accepted at any confidence. FWS tagged + excluded from experience-promotion successes. Buckets: AUTO{knowledge_gap,experience_gap,budget,approach} / HUMAN_GATE{tool_gap,harness_bug,fws,ambiguous} / SKIP{human_grade} / LOG_ONCE{cyber_blocked}. +14 tests.
- 44c improver+regress: SEQUENTIAL one-change-at-a-time apply→gate→commit/rollback; atomic hash-verified rollback (Surface snapshot/restore, sha256 byte-identity, no residue); DUAL adoption condition = (a) dev-target fail→solved flip AND (b) holdout no strict drop; variance-conservative (any drop → rollback; never adopt on a holdout gain alone). Blind: improver reads dev only; regressor touches holdout via an injected unlock→grade→relock grader. +8 tests. Demo store/p44_growth/demo_cycle.json = 1 adopt · 1 rollback.
- 44d autonomous validation (deterministic fakes, cost 0): mid-improve power-loss RECOVERY (per-improvement durable snapshots+ledger → resume at the exact point, no batch re-run, no double-apply); convergence fires (net-0-adoption×k → stop_reason); HUMAN_GATE/SKIP accumulate in growth/requests.md across cycles with 0 auto-applied + cyber dedup per cid; final drift proof (7 governance hashes match). +4 tests. Demo store/p44_growth/autocycles.json = 3 chained cycles → converged, 1 adopt / 3 drift-blocked rollbacks.
- Suite 348 green (was 315; +33 growth tests). p40_rev lock already fixed in P43 (confirmed green). Governance/verifier/FWS/isolation/split UNMODIFIED (sha256 verified). EXPLICIT: this is skeleton+safety only — the FIRST real blind-runner autonomous growth run is a SEPARATE later milestone, NOT done here. No performance claim.
