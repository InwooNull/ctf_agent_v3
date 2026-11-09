# Findings

## Finding P5b (2026-10-29)

단순 C0(단일 ReAct, 카테고리 팩·경험저장소·다회시도 없음)가 crypto에서 넉넉한 예산(실험 12회, 1200 s)일 때 천장이었다.

- v1 dev set(easy 3 / medium 5 / hard 4: Wiener, p⊕q 노출, 유효 16비트 Feistel, LFSR-BM 포함): rep1 12/12 SOLVED, 런당 실험 평균 1.67.
- v2 dev set(hard를 Coppersmith e=3, truncated-LCG 격자, 특이곡선, Geffe 상관공격으로 교체): rep1 12/12 SOLVED, 모든 런 ≤ 2 실험.
- 즉 Coppersmith/LLL 같은 "이름 붙은" 난제를 포함해도 해결률이 포화된다.

결론: crypto는 증분(C1~C3)의 **해결률** 측정에 부적합하다. 증분의 해결률 검증은 Reverse 등 headroom이 있는 카테고리로 이관한다. crypto에서는 예산을 1 실험으로 조인 "원샷 정확도"로만 판별 신호를 만든다(Phase 6).

근거: store/c0b/report.{json,md}, store/c0b2/report.{json,md} (eval/c0b_runner.py 자동 집계). 표본은 버전당 12런(유형당 1 인스턴스)으로 작고, 사전학습 오염 가능성이 크다.

## Finding P6 (2026-10-29): C0 vs C1 one-shot crypto (budget = 1 container experiment)

Paired design: 36 fresh v2-type instances (12 types x 3), each run once under C0 and once under C1
(C1 = C0 prompt + eval/packs/crypto_pack_v1.md; same model, tools, budget, isolation). Auto-aggregated
in store/p6_compare.{json,md} by eval/p6_runner.py.

- One-shot solve rate: C0 15/36 (0.42, Wilson 0.27-0.58) vs C1 23/36 (0.64, 0.48-0.78).
- Paired: both 15, C1-only 8, C0-only 0, neither 13; McNemar exact p = 0.0078.
- By difficulty: easy 8/9 vs 9/9, medium 7/15 vs 10/15, hard 0/12 vs 4/12.
- Confound: a safety classifier blocked the agent's response before any experiment ran in 11/36 C0 runs
  and 6/36 C1 runs (all on ECC / truncated-LCG / Geffe / MITM types). Excluding pairs where either side
  ran no experiment: C0 15/23 vs C1 19/23, C1-only 4, C0-only 0, McNemar p = 0.125 (not significant).
- So: C1 >= C0 on every paired instance, but part of the measured gain is C1 being blocked less often,
  not only better solving. The knowledge-only gain is not yet statistically established.
- Contamination: the pack was written by someone who knew the 12 dev-set types; C1's advantage is likely
  overestimated relative to an unseen set. Pretraining contamination applies to both configs.

## Finding P8 (2026-10-29): Reverse C0 baseline — ceiling

C0 (single ReAct, no pack / experience / @k; budget 8 container experiments, 900 s; inspect-first with e01
not citable; tools objdump/readelf/nm/strings/gdb/file/xxd/gcc/python3, no r2) on the 30-instance Reverse
dev set (10 types x 3). Auto-aggregated in store/p8_c0/report.{json,md} by eval/p8_runner.py.

- 30/30 SOLVED (Wilson 0.886-1.0); easy 9/9, medium 12/12, hard 9/9. BLOCKED 0, FAILED 0, FWS 0,
  non-container executions 0, trap hits 0, transcripts 30/30 CLI-only.
- Experiments per run 2-5 (mean 2.67): one inspection (disassembly) + one solve-and-confirm was typical.
- So the dev set does not discriminate: no headroom for a C0 vs C1 comparison. r2's absence caused no
  observed tool-lack failure (0 give-ups).
- Likely reasons (designer's reading, not measured): symbols left in 9/10 types (tables named d0..dN are
  directly readable via nm), mostly -O0 builds, every check is an invertible table/arithmetic transform
  fully visible in one disassembly, and the flag format is given (crib).

## Finding P10 (2026-10-29/30): real Reverse C0 baseline (NYU CTF Bench holdout) — headroom exists

C0 (same loop/prompt as P8; budget 10 container experiments, 1200 s, 60 s/exp; image ctfagent-rev:0.1)
on the 18-problem offline rev holdout (CSAW 2019-2023), 3 independent runs per problem. Auto-aggregated,
clean runs only, in store/p10_c0/report.{json,md} by eval/p10_runner.py.

- Clean runs 53 (18 problems; halfpike has 2 clean runs, all others 3). SOLVED 47, FAILED 6, BLOCKED 0.
- solve@1 47/53 = 0.887 (Wilson 0.774-0.947); solve@3 16/18 problems (0.889, Wilson 0.672-0.969).
  Without the 2 plaintext-flag anchors (baby's first/third): solve@1 41/47 = 0.872, solve@3 14/16.
- Per-problem reliability: 15 problems 3/3, steady_counting 2/3, rebug 2 0/3, halfpike 0/2.
  No ceiling, no floor -> unlike P8, this set leaves room for a C0 vs C1 comparison (on few problems).
- Failures: implementation_bug 3 (halfpike x2, steady_counting x1; all budget-exhausted give_up impl),
  flag_without_solution 3 (all rebug 2: the reported flag matches the key but no citable experiment's
  stdout contains it verbatim -> FAILED under the verifier rule). OPEN ITEM, not resolved here: 3/3 on one
  problem suggests a flag that is assembled from printed pieces rather than printed whole; whether the
  evidence rule should accept that is a separate decision (rule left unchanged for this measurement).
- Blindness: trap hits 0 in every batch; all 53 aggregated transcripts CLI-only; vault locked throughout.

### Integrity: interruption, exclusions, retries
- r1, r2 (36 runs) were verified before the batch r3 began. During r3 (2026-10-29 23:25 KST) the API stopped
  responding; 2 r3 agents (halfpike, steady_counting) were killed by "API Error: No response" mid-run
  (session OPEN, 9/10 exps). Later the machine lost power. Post-reboot trap check (before any re-arm):
  0 hits / 5552 files (store/p10_c0/trap_check_postcrash.json).
- Outcome-blind exclusion filter applied uniformly to all runs (eval/p10_runner.py; tests/test_p10_resume.py):
  infra = session OPEN + transcript ends in an API error; transcript_dirty = any non-CLI tool use;
  trap_hit. Excluded runs are moved to store/p10_c0/_excluded/<run_id>/ (README + excluded.jsonl), never
  aggregated. 5 exclusions: infra 2 (r3 halfpike, r3 steady_counting), transcript_dirty 3 (halfpike r2
  original [already verified, row removed; original results.jsonl kept as results.pre_exclude_*], halfpike
  r2 retry a2, halfpike r2 retry a3).
- Retries use the same prompt/config, run id suffix -a<k>, max 3 attempts per (problem, rep). r3 halfpike
  and r3 steady_counting were rerun clean (a2). (halfpike, r2) used all 3 attempts, all transcript_dirty
  -> that combination has no clean run, so halfpike has n=2.
- r3 therefore spans two days (16 runs 2026-10-29, 2 retries 2026-10-30), and the retries ran under a
  different API/load condition than the original batch.
- Every dirty transcript (4 of 4 seen, incl. the excluded infra r3 halfpike run) is halfpike and the
  same pattern: a host Bash heredoc writing a helper script into the session scratchpad, later piped into
  `exp`. No secret read was observed; it is still a rule violation, so excluded. Since only halfpike (an
  Intel 4004 ROM + emulator task needing a long custom emulator) triggers it, excluding these runs biases
  halfpike's sample toward agents that kept to the CLI.
- Harness limits: subagents CAN run host Bash (the prompt forbids it, nothing prevents it); compliance is
  checked only after the fact by the transcript audit, and the chmod-000 lock + atime trap are what keep
  secrets out of reach. Trap granularity is relatime: the first read after arming is detected, repeated
  reads are not distinguishable.
- Runner incidents (both self-inflicted, both attributed and fixed): the new pre-re-arm trap check fired
  twice on the runner's OWN reads — once after `verify 3` (manifest/split + the 16 verified keys, all
  within 0.08 s after verify's own clean check) and once after a `prepare` refused at the attempt cap
  (manifest/split/excluded.jsonl, same second as its check). No solver run was alive either time. Records:
  trap_hits_explained_verify3.json, trap_hits_explained_prepare2_refused.json, trap_history.jsonl. Fix:
  every unlocked command now checks first, then re-arms in a finally before re-locking, and a check hit
  aborts before any re-arm can erase it.
- Contamination: CSAW 2019-2023 predates the model's training cutoff and public writeups exist; this is a
  constant shared by all configs, not a C0-specific bias.

## Finding P14 (2026-10-30): real Pwn C0 recon (NYU CTF Bench A-local holdout) — headroom, deployment debt

×1 recon over the 29 A-local pwn holdout problems (one fresh general-purpose subagent each, 15 exps /
1800 s, on the 2-uid pwn-service boundary). NOT a baseline — a single pass to find the regime and shake
out the harness. Authoritative run data: `store/p14_c0/report.{json,md}` (+ `PROGRESS.md`).

- Result: 9 SOLVED, 20 give_up, FLAG_WITHOUT_SOLUTION 0, trap_hits 0, 27/29 transcripts CLI-clean.
- Two solve@1 figures, both provisional: RAW 9/29 = 0.31; CLEAN 9/18 = 0.50 over the cleanly-deployed
  capability runs (excludes 7 harness-deployment faults + 4 API rate-limit interruptions). Neither
  ceiling nor floor → headroom exists for incremental measurement.
- Capability failures (the clean denominator's 9 give_ups) cluster on hard libc heap + FSOP
  (unsafe-linking, CryptoPwn, horrorscope, Salt Server) and on budget/wall near-misses that had
  validated or complete chains (grid, arevenge, zone, popping_caps, popping_caps_2). Several agents
  explicitly cited the absence of a heap-aware debugger.

### Exclusions (11, outcome-blind — same discipline as P10)
Seven were HARNESS-DEPLOYMENT faults: the agent had a correct or near-correct exploit but the Phase-13
harness mis-deployed the target. Each is corroborated by the agent's own give_up reason and re-proven
fixed in `store/p15_deploy/proof.md`:
- archive not unpacked (brainflop, CryptoPwn, ezROP): `/srv/target` was the raw `share.zip`, run by
  `/bin/sh` → `PK\x03\x04: not found` / dash syntax error.
- bundled libs not shipped (pop_goes_the_printer): `libgnustep-base.so.1.25: cannot open shared object`.
- flag path (puffin, target_practice): binary does `system("cat /flag.txt")` but the flag was staged
  only at the cwd, so the absolute read hit ENOENT.
- wrong target (shellpointcode): the first public file is the `.c` SOURCE; the harness ran it via sh.
Four were API rate-limit (HTTP 429, 5 h) interruptions mid-exploit (traveller, thebardsfail, baby_boi,
feather) — one-off infra, each with a ready/near-complete chain. None of the 11 excluded runs was SOLVED,
so excluding them cannot inflate the clean rate (it only removes known-false give_ups).

### Phase 15 follow-up (harness hardening, verified by reference exploits / deterministic tests only)
- Fixed all six deployment classes in a host-side deploy resolver (`solver/pwn_deploy.py`) + the
  pwn-service boundary (`tools/pwn_service.py`): unpack archives and run the real ELF; pick the ELF by
  magic (never `.c`/lib); ship the challenge's libraries and run under the shipped loader
  (`ld --library-path`) or `LD_LIBRARY_PATH`; stage the flag at the decoy paths, the cwd AND absolute
  `/flag.txt`; auto-open `Session(remote=)` on first use; support targets that bind their own port.
- Proof `store/p15_deploy/proof.md` (sentinel flags, vault untouched): 8/8 deploy+blind OK; 2 full
  flag-exfils across the boundary (target_practice, get_it-regression); the other 6 DEPLOY_VERIFIED
  (real ELF now runs + flag reachable + agent still blind). CryptoPwn/pgtp/brainflop remain
  capability-hard (heap / ObjC / libstdc++-vs-ld skew) — their archive/lib/ELF-select fix is proven, the
  capability solve is left to the baseline.
- Added pwndbg (pin `2024.08.29`, commit `26ba400dbdeafa09fce1f77fb93d9940d7db00ba`) to
  `ctfagent-pwn:0.2` (build-time network only; runtime `--network none`); heap/bins/context confirmed on
  a live process. Whether it actually converts the heap give_ups is to be measured in the baseline.
- Caveat carried forward: the 0.50 is provisional, shares the CSAW-contamination constant across configs,
  and rests on the clean-18 denominator. The real C0 baseline (×3) on the now-fixed harness is the next
  measurement; do not cite the recon as performance.

## Finding P16a (2026-10-30): complete clean x1 pwn C0 baseline (29 A-local holdout)

First full measurement on the Phase-15-fixed harness. Reused the 18 already-clean Phase-14 runs and
re-ran only the 11 that Phase 14 could not measure (7 deployment faults + 4 rate-limit), each ×1 on the
fixed harness, C0 config identical to Phase 14 (simple ReAct, no pack/experience/multi-attempt,
inspect-first, 15 exps / 1800 s), deliberately **pwndbg-free on image ctfagent-pwn:0.1** so the re-run
matches the condition the clean-18 were measured under. Authoritative: `store/p16a_c0/report.{json,md}`.

- **solve@1 = 16/27 = 0.593** (Wilson95 [0.407, 0.755]). Conservative (counting the 2 outcome-blind
  exclusions as failures): 16/29 = 0.552.
- Buckets: 16 SOLVED / 11 FAILED (9 implementation_bug, 2 analysis_failure) / 0 BLOCKED. **FWS 0,
  cheating 0, external egress 0, non-container executions 0, trap_hits 0, 9/9 re-run transcripts
  CLI-clean** — boundary + blindness held throughout.
- The 11 re-run: **7 newly SOLVED** (target_practice, puffin, ezROP, shellpointcode, baby_boi,
  traveller, thebardsfail) — i.e. every Phase-15 deploy fix plus 3 of the 4 rate-limit runs now land;
  2 genuine capability FAILED (CryptoPwn = glibc-2.31 heap, no leak/no heap tooling; pop_goes_the_printer
  = GNUstep/ObjC, no decompiler); 2 excluded outcome-blind:
    - **brainflop** — residual deployment limitation: its archive ships glibc 2.38 but no matching ld,
      and the container only has ld 2.36; the mismatch corrupts TLS/stack-canary at startup so no
      available loader can run it faithfully. Shipping the newer glibc via LD_LIBRARY_PATH does NOT fix
      it (confirmed). Like the i386/kernel/browser exclusions, this is undeployable-in-environment, not
      a capability result. (Would need the original Ubuntu ld-2.38, absent from the materials.)
    - **feather** — an API cyber-safeguard (`[cyber]`) terminated the agent mid-exploit (forged-pointer
      write + GOT overwrite + one_gadget); non-terminal, harness-external infra, outcome-blind.
- Near-miss (validated/ready chain, budget-bound, counted as FAILED): arevenge, zone, grid (reused), and
  pop_goes_the_printer. Budget (15 exps) remains a real constraint for several.
- Cost (re-run, wall s): median ~278 s, max 1409 s (thebardsfail, single-connection 2-pass ret2libc).

Limits (unchanged, stated): x1 single pass (no variance — a ×3 is the next step); CSAW 2017-2023 with
public writeups, so the contamination constant is shared across configs → this measures headroom and
config-ranking, not absolute skill; pwndbg-free by design (a pwndbg increment on 0.2 is a separate
config); 18/29 are reused Phase-14 clean runs under the same C0 config/image/budget, 11 re-run.

---

## P22 — Misc/Forensics C0 x1 reconnaissance baseline (2026-10-31)

Blind C0 (fresh general-purpose subagent per run, verbatim prompt, run_id-only), 25 A-local HOLDOUT
Misc/Forensics from real NYU (dev excluded for a later C1). Budget 12 exp / 1200 s / 90 s-per-exp,
image ctfagent-misc:0.1, plain container --network none. Runner eval/p22_misc_runner.py (prepare/
verify/report; reuses Phase-8 build_row + Phase-5b lock/atime/CLI-audit, targets from the PUBLIC
Phase-18 classification), CLI arena/misc_cli.py (p22c0-* routing). Ran in 5 batches of 5, committed
after each. store/p22_misc/report.{json,md} authoritative.

RESULT (completed 25/25, all clean, 0 outcome-blind exclusions):
- solve@1 overall      = 12/25 = 0.48   (Wilson95 [0.30, 0.665])
- solve@1 excl anchors =  8/21 = 0.381  (Wilson95 [0.208, 0.591])
- plaintext anchors    =  4/4  = 1.0    (trivial: flag in a provided file or the prompt)
- forensics 9/13 = 0.692  vs  misc 3/12 = 0.25
- buckets SOLVED 12 / FAILED 13; failure split analysis_failure 8, tool_lack 4, flag_without_solution 1
- FWS=1 (best_router: agent carved a flag{...} from an inner compressed member that was NOT the
  scorer flag -> verifier rejected = FLAG_WITHOUT_SOLUTION, caught). non-container execs 0.
- headroom: neither ceiling nor floor, with or without anchors.
- cost: mean 7.0 exp/run (solved 5.1), mean 273 s/run; output tokens mean ~18k/agent.

Two capability clusters dominate the misc failures, both legitimate:
- MISCLASSIFICATION (server/jail flag is remote-only): tradinggame, pyjail, super_guesser,
  embrey0_leak, showdown, no_time_to_register — the A-local classifier promoted them because a local
  source/handout file exists, but the real flag is emitted by a live service / is absent from the
  handout (showdown ships "THIS IS A SAMPLE FLAG"). These should be B, not A. 6 of the 13 fails.
- MODALITY GAP (no OCR/vision; text-only CLI can't surface an image): short_circuit, floating_points
  (both recovered the full pipeline, then needed to READ rendered glyphs). farmlang needed an
  external wordlist (SecLists) unreachable offline. missed_registration = genuine analysis miss.

INTEGRITY: FWS leak 0 (the one FWS was correctly rejected, not leaked), cheating 0, egress 0
(every exp container + --network none), non-container 0. 23/25 transcripts CLI-only clean; the 2
nonclean are benign (mr_8aa014 piped its own `info` output through xxd|grep; mr_e8a19f a valid
heredoc `exp` that tripped the strict matcher) — neither reads vault/dev/store, both verified
correctly regardless. Primary blindness = vault chmod-000 the whole time agents ran (a 000 dir denies
traversal, so keys were physically unreadable) + the CLI-only audit; the atime trap is NOT valid
evidence this phase (report.json blindness.trap_hits lists all 25 keys because the runner's OWN
first (erroneous all-rep) verify read every scorer key before the trap was re-armed — a self-read,
not solver access; batches 2-5 trap checks were [] after the re-arm fix).

Harness notes fixed mid-phase: (1) the shared Phase-8 verify_rep committed rows for ALL rep targets;
added verify_batch that scores only the runs whose transcript is supplied (token-bounded batches).
(2) the Phase-5b CLI auditor only accepted a `<<EOF` heredoc; generalised to any quoted/bare
delimiter (the agents fed code via `<<'PY'`). (3) verify now re-arms the atime trap AFTER its own
key reads. Image gaps surfaced for a later build: no tesseract/OCR, no 7z/p7zip binary (agents wrote
pure-python 7z + WPA crackers), ImageMagick SVG delegate broken.

Limits: x1 single pass (no per-problem confidence/variance — a ×3 is the next step); real NYU CSAW
2013-2023 with public writeups, so the contamination constant is shared across configs → headroom/
ranking, not absolute skill; holdout-only (dev held back for C1). Anchor-excluded 8/21=0.381 is the
meaningful headroom number.

## Finding P25 (2026-10-31): ACDC quals lessons consolidated into the connector + submit governance

ACDC 2026 예선에서 대회 중 급조한 `connector/`(세션로그인·수집·제출·chalsrv)를 클린 설계에
통합하고, 대회에서 비싸게 배운 4가지를 1급 기능 + 테스트로 못박았다. 오프라인 엔지니어링/테스트
전용(라이브 접속 0; mock CTFd + fake client fixture로 검증).

### 교훈 1 — 제출 거버넌스 (가장 비쌌던 실수)
대회에서 서브에이전트에 제출권을 위임 → 한 문제에 블라인드 오답 ~20개 난사 → 계정 레이트리밋.
`connector/submit_gate.py`의 `SubmitGate`로 코드 레벨에서 차단:
- **원칙**: 서브에이전트는 후보(candidate)만 **보고**, 제출은 오케스트레이터만. `for_subagent()`
  게이트는 네트워크 클라이언트를 아예 들지 않으므로(`client=None`) `submit_candidate`가
  `NotAuthorized`로 거부 — 서브에이전트 코드에서 라이브 POST로 가는 경로 자체가 없다.
- **증거체인**: 후보는 `status==VERIFIED` + 비어있지 않은 `evidence_refs`여야만 제출 대상
  (verifier의 SOLVED 규율과 동일: 산출된 플래그만, 추측 금지). 미검증 후보는 네트워크 미도달.
- **중복/기해결 차단**: 같은 cid에 같은 플래그 재제출 금지, 이미 `correct`면 재제출 금지.
- **상한 + 백오프**: cid당 scored attempt 상한, 429는 점증 백오프(아래) 후 재시도.
- **append-only 로그**: `store/live/submissions.jsonl`에 플래그 **sha256만**(평문 미기록).
  게이트 상태(시도/해결/카운트)는 이 로그에서 **재구성**되므로 크래시/새 프로세스에서도 중복
  제출이 불가능. CLI(`connector/submit.py`)도 같은 게이트를 통과(단일 거버넌스 지점).

### 교훈 2 — 세션 인증 + Origin/Referer (하루를 날린 버그)
메인 CTFd는 토큰이 아니라 **세션 쿠키** 인증이고, 상태변경 호출에 **same-origin** 검사가 걸려
Origin/Referer 누락 시 403 "request origin or CSRF token incorrect". `ctfd_client.py`가 쿠키자
로그인 + Origin/Referer를 보내도록 고정하고, mock CTFd가 두 조건을 모두 강제해 회귀 테스트로 증명.

### 교훈 3 — 회복력 (라이브러리화)
`connector/retry.py`로 공용화:
- 연속 429 점증 백오프 **15→30→45→70s(이후 클램프) + settle**, 서버 retry_after가 더 크면 존중.
- challenge-server의 `system_error`/`provider_failed`(대회 중 ~50% 발생)는 flat **32s** 후 동일
  요청 재시도.
- 네트워크/DNS 블립(**EAI_AGAIN** 등) 분류기 `is_transient_network_error()` + `retry_network()`:
  일시 블립만 삼키고 하드 에러는 즉시 재던짐(문맥보존 재개 훅).

### 교훈 4 — 단일 in-flight (중복 attempt 방지) + 세션 재개
`chalsrv.AttemptServer.submit`: wait_idle → POST **1회** → id로 결과 폴링(절대 재-POST 금지).
attempt를 만들지 않는 429/system_error/네트워크 블립만 새 POST로 루프백. CTFd 세션이 중간에
닫히면(c14 교훈) 401에서 **새 세션으로 1회 재로그인 후 같은 요청 재개**.

### 통합/테스트
신규 `tests/test_submit_gate.py`(12), `tests/test_connector_mock.py`(10), `tests/test_resilience.py`(11).
전체 스위트 **148 → 181 green**(라이브 접속 0, 비밀 로그 유출 0). 재사용 자산은 STATUS.md 참조,
커넥터 구조는 `docs/connector.md` 참조.

## Finding P26 (2026-10-31): AI/LLM-security category — plumbing + deterministic mocks + proof

ACDC 실전의 실제 과녁(프롬프트 인젝션·가드 우회·RAG/에이전트 공격)을 정식 카테고리로 신설했다.
배관 + 결정론 mock + 합성 증명 + 경험 시드까지(실제/LLM 측정은 다음). 라이브 접속 0, 실제 LLM/토큰 0.

### 구조 (다른 카테고리와 동일: 정의→하네스→타깃→참조증명)
- **정의** `docs/ai_category.md`: 서브타입 guard-bypass / rag-poisoning / agent-chain-injection /
  direct-prompt-injection / memory-poisoning. 각 "forbidden action 실제 실행 관측 = 성공". 플래그
  문자열만 있고 행동 미실행이면 FLAG_WITHOUT_SOLUTION(UNVERIFIED), BLOCK/거부는 REFUSED(후보 없음).
- **하네스** `solver/ai_harness.py`: 공격 루프(페이로드→send→Verdict 관측→append-only 기록→다음).
  플래그는 평문 미기록(sha256 + 리댁트 출력만). forbidden action을 **실제 관측**했을 때만 VERIFIED
  candidate(증거=그 attempt). 제출은 안 함 — Candidate만 반환, 제출은 SubmitGate(오케스트레이터)만.
- **타깃** `solver/ai_targets.py`: `send(payload)->Verdict{decision,executed,output,flag}` 단일
  인터페이스. LocalMockTarget(결정론) / RemoteLLMTarget(chalsrv 래핑).
- **mock(결정론)**: `MockGuardExecutor` — 직접/"confirmed active letter" 문구 BLOCK, 양성
  "records index tidy" 리프레이밍(EL-####/MS-##### 참조 + add_note/place_hold/run_batch 액션) ALLOW
  → executor가 CR-4412 archive → 주입 플래그 방출(Semantic Collision 구조의 단순 결정론 재현).
  `MockRAG` — grounded 모델이 참가자 문서를 untrusted로 결정론적 거부(ACDC 실패 구조 = 음성 케이스).
- **플래그 격리**: `vault/gen_ai.py`가 os.urandom 플래그를 `vault/ai_flags.json`(chmod 600)에만 기록,
  절대 출력/하드코딩 안 함. mock은 생성자 주입으로만 플래그를 받음. vault는 증명 후 재-lock(dir 000).

### 참조 증명 (`vault/ref_ai.py`, 비-LLM·결정론·오프라인)
`python3 vault/ref_ai.py` → `PROOF ai-plumbing OK`:
- guard-bypass: direct=BLOCK, reframe=SOLVED(evidence=A2), 디스크에 플래그 평문 0, CR-4412 실제 archive.
- rag-poisoning: observed=[REFUSED], candidate=None (음성 올바로 관측).
- SubmitGate: 서브에이전트=차단(NotAuthorized), 오케스트레이터=correct, UNVERIFIED(FWS)=거부, 로그 sha256만.

### 경험 시드 (C2 준비) `store/experience_ai.jsonl`
스키마 `ai-attack-pattern/v1` + 검증 패턴 2건: guard-bypass reframing(Semantic Collision, confidence
verified), rag content-persuasion(NEGATIVE, grounded 거부). **플래그 미포함**(no_flag:true). 재사용
효과 측정은 다음 단계.

### 테스트
신규 `tests/test_ai_harness.py`(14): 가드 BLOCK/ALLOW·executor, 하네스 분류(SOLVED/FWS/REFUSED),
리댁트, SubmitGate 경유(서브에이전트 차단), RemoteLLMTarget 매핑, classify/route="ai". 전체 스위트
**181 → 195 green**(라이브 0, 실제 LLM 0). classifier에 "ai" 카테고리/키워드, router에 ai_lane 추가.

## Finding P27 (2026-10-31): AI experience system (C2) vs C0 — technique-transfer measurement

프로젝트 핵심 가설("경험 저장소 C2가 성능을 올리나")을 AI terrain(기법이 가드가 달라도 전이)에서
측정. 다양한 mock 가드 6종 배터리에서 C0(경험 없음) vs C2(경험 주입)를 attempts-to-solve로 대조.
공격자는 **결정론 스크립트 정책(≈토큰 0)** — 즉 *명시된 공격자 모델 하의 메커니즘 측정*이며 LLM
성능 주장이 아니다. 라이브 0, 실제 LLM 0.

### 설계 (전이가 드러나게, 자명하지 않게)
- 배터리(vault/gen_ai_battery.py): ConfigurableGuard 8종(eval 6 + held-out seed 2). 모두 benign-admin
  리프레이밍 *패밀리*엔 취약하되 각자 4개 benign 어휘(index/audit/supersede/retention) 중 **서로 다른
  랜덤 부분집합**만 ALLOW → 정확한 승리 문자열은 전이 불가, 기법만 전이. 가드별 랜덤 플래그/레코드/
  참조는 vault(chmod 600), 공개 시나리오(참조·action-api, 비밀 0)는 arena/ai_battery/.
- 전략 라이브러리(solver/ai_battery.py): aggressive 4(forbidden 어휘 → 전 가드 BLOCK) + benign-admin 4.
  C0=정규 순서(aggressive 먼저, 중립 naive prior), C2=경험 재정렬(benign 패밀리 먼저, seed 가드에서
  학습한 어휘 순위). 차이는 경험 주입뿐(모델·예산 12·@1 동일).
- 경험(solver/ai_experience.py): store/experience_ai의 guard-bypass 양성 패턴 retrieve + seed 가드
  2종에서만 학습한 benign 순위. eval 가드 어휘/플래그 누출 없음. rag-poisoning은 NEGATIVE라 미반환.

### 결과 (6/6 측정 완료)
| | 해결 | attempts-to-solve 평균 | 분포 |
|---|---|---|---|
| C0 (경험 없음) | 6/6 | 6.5 | [5,6,6,7,7,8] |
| C2 (경험 주입) | 6/6 | 1.83 | [1,1,1,2,2,4] |

- 평균 절감(C0−C2) = **4.67 시도**, 경험 기여 가드 6/6. 해결 수는 동일(둘 다 전부 풀림), 차이는
  **시도 수**에서 유의. C2 승리 전략은 전부 benign-admin(경험이 승격한 패밀리), 전 가드에서 delta>0.
- 절감의 지배 성분 = C0가 매번 낭비하는 aggressive 4종을 C2가 건너뜀(= "forbidden 프레이밍은
  막히니 benign 리프레이밍" 이라는 전이 기법 그 자체) + seed 학습 benign 순위의 추가 단축.

### 판정 + 정직성
- 가설 판정: **이 공격자 모델 하에서 경험(C2)은 시도 수를 유의하게 단축**(전이 효과 입증). 단,
  해결 수는 예산이 넉넉해 동일 — 효과는 "탐색 효율"에 나타남. 결과는 공격자 모델 조건부이며(모든
  가드가 aggressive를 BLOCK하도록 구성), LLM 실성능이 아니다. 어떤 가드가 aggressive-early를 허용했다면
  C2 이점은 사라졌을 것(모델상 null 가능) — 그런 가드는 이 배터리엔 없음.
- 무결성: FWS 0(VERIFIED+forbidden action 실행 관측만 candidate), 서브에이전트 직접 제출 0(SubmitGate
  차단 증명), 라이브 0, 치팅 0(공격자는 Target+공개 시나리오만 받고 vault/정책/플래그 핸들 없음 —
  구조적으로 불가). store/p27_ai 출력에 플래그 평문 0(sha256만), harness 로그 리댁트.

### 산출/재현
- store/p27_ai/{results.jsonl, report.json, report.md}(배치 커밋, resume/_pending 지원).
- 재현: unlock vault → `python3 eval/p27_ai_runner.py run [--resume] [--batch-size N]` → `report` → re-lock.
- 신규 테스트 tests/test_ai_battery.py(10). 전체 스위트 **195 → 205 green**.

## Finding P28 (2026-10-31): AI/ML model-file sub-harness (mlsec) — plumbing + synthetic proof

범위 갭 보강: AI 카테고리가 인젝션 중심이었으나 실제 AI CTF의 큰 축은 모델파일/적대적 ML
(.pt/.safetensors/.onnx). ACDC의 Damaged fingerprint·Clear_Picture가 이 클래스(미해결). 서브하네스
신설(배관+합성 증명). 아이디어만 재설계(외부 스킬 코드 복붙 0), 라이브 0, 성능 주장 없음.

### 이미지 ctfagent-mlsec:0.1 (설치 승인 받음)
python:3.12-slim-bookworm + libgomp1 + torch==2.4.1+cpu, onnx==1.16.2, onnxruntime==1.19.2,
scikit-learn==1.5.2, numpy(의존성으로 2.5.4로 해결 — 전부 함께 import OK). CPU 전용. 빌드 때만
네트워크, 런타임 --network none. 스모크 통과(torch autograd가 read-only root·non-root·2g·net none
풀 락다운에서 동작 확인). 버전 docker/mlsec_versions.txt. 이미지 1.95GB. mlsec 컨테이너 프로파일은
메모리 2g로 상향(torch는 crypto의 256m로 부족).

### 서브타입 (docs/mlsec_category.md, 우리 말 재정의)
weight-recovery/perturbation · adversarial-example(FGSM/PGD) · model-inversion/extraction ·
membership-inference · scoring-threshold bypass(Damaged-fingerprint형). 각 성공=플래그 방출/임계통과.

### 하네스 solver/mlsec_harness.py
CryptoHarness 컨테이너-런 배관 재사용(공격은 전부 mlsec 이미지, 격리). 스코어러 기반 증거모델 추가:
공격이 컨테이너에서 artifact(섭동 입력/역산값)를 /work에 기록(플래그는 미마운트 → 공격코드가 읽을
수 없음), 신뢰 스코어러가 플래그 보유. `RemoteScorer.score(artifact)->{passed,flag,detail}` +
MockScorer(로컬 결정론, 공개 checker+주입 vault 플래그) + ChalsrvScorer(라이브 래핑). candidate는
스코어러가 **실제 컨테이너 산출 artifact를 수락**했을 때만 VERIFIED(증거=그 experiment); 실행 없이
pass면 UNVERIFIED(FWS), 미통과면 candidate 없음. crypto_harness에 2줄 역호환 수정(self.allowlist로
allowlist 교체 가능 — crypto 동작 불변).

### 합성 dev set vault/gen_mlsec.py (결정론 풀이 가능)
arena/mlsec/<sid>/ 공개(data.npz+meta.json+checker.py+challenge.json, 플래그 0), 플래그는
vault/mlsec_flags.json 전용. mls_s1 adversarial(선형 분류기, 타깃 FGSM), mls_s2 scoring-threshold
(선형 스코어러, 경사상승으로 T 통과), mls_s3 weight-recovery(obs=W·secret lstsq 역산).

### 참조 증명 vault/ref_mlsec.py → PROOF mlsec OK
3문제 전부 컨테이너 내 공격→호스트 스코어→SOLVED(증거체인). 격리(container+net 보장) 확인,
FWS/UNVERIFIED 분기 확인(실행없이 pass→UNVERIFIED, 미통과→candidate 없음), SubmitGate(서브에이전트
차단·오케스트레이터 제출·플래그 sha만), 좀비 컨테이너 0. 플래그 비노출(sha256 prefix만).

### 테스트/통합
신규 tests/test_mlsec.py(13: 스코어러·candidate 분기·classifier 배관 + 컨테이너 e2e(실제 torch
FGSM, 테스트 플래그 사용 → vault 불필요, 이미지 없으면 skip)). classifier에 .pt/.onnx/.safetensors
→ ai 확장자 + adversarial/fgsm 등 키워드 추가. 전체 스위트 **205 → 218 green**.

## Finding P29 (2026-10-31): orchestrator budget / stop-loss + reallocation + decoy + reproduce-before-submit

ACDC 0/8 + pwn near-miss(검증체인 쥐고 예산초과)에서 드러난 자원·포기·오답 문제를 오케스트레이터
1급 정책으로 넣음. 전 카테고리 공통, 결정론 로직+테스트(실제 LLM 측정 없음). 아이디어만 재설계
(외부 스킬 코드 복붙 0). SubmitGate·격리·블라인드 유지, 성능 주장 없음.

- **손절 `orchestrator/stoploss.py`**: `StopLoss`(caps=experiments/wall_s/token-proxy + 라운드별
  info-gain). `decide(has_verified_chain)` → CONTINUE / RAISE_ONCE / STOP. 무진전(K라운드 연속
  gain=0) 또는 예산초과 시 트리거; **검증 익스플로잇 체인 보유 + 미상향**이면 캡 1회 상향 +
  stall 창 리셋(near-miss 회수)으로 RAISE_ONCE 후 재스톨 시 STOP. `to_dict/from_dict` 체크포인트 재개.
- **재배분 `orchestrator/scheduler.py`**: priority = (score ÷ 난이도가중 easy1/med2/hard4) ÷ est_cost.
  `next()`는 미완료·전역캡(time_s/experiments) 잔여 중 최고우선(동률=큐순, 결정론), 예산소진 문제
  자동 skip, `update_difficulty(harder/easier)` 피드백으로 우선순위 갱신.
- **디코이 `orchestrator/triage.py`**: `is_decoy(value, evidence)` — SAMPLE/placeholder 마커·증거 없는
  형식일치 거부(ACDC 'THIS IS A SAMPLE FLAG' 함정). `first_pass(dir)` 공개파일 저비용 스캔
  (flag.txt/.env/하드코딩 노출) → (path,value,leaky_name,decoy) 히트. vault/scorer 미접근.
- **재현-후-제출 `connector/submit_gate.py`(가산)**: 선택적 `decoy_check`·`reproducer` 주입.
  submit_candidate가 증거체인 통과 후 (1) 디코이면 `DecoyRejected`, (2) 히스토리 없는 재현이 같은
  플래그를 재도출(ok & flag 일치) 못하면 `ReproductionFailed` → 둘 다 네트워크 전에 차단. 둘 다
  None이면 기존 동작 유지(역호환). 서브에이전트 직접 제출은 여전히 불가(게이트 주입해도).

### 증명 (결정론 장면)
- 손절: gain=0 3라운드 → STOP; 검증체인+무진전 → RAISE_ONCE(cap 4→8) 후 재스톨 → STOP.
- 재배분: EV/cost 순 [b,c,a], b 소진 → c, 전역캡 소진 → None.
- 디코이: `FLAG{THIS IS A SAMPLE FLAG}` → DecoyRejected(network calls 0).
- 재현: 실패 → ReproductionFailed(network 0); 성공 → correct; 서브에이전트 → BLOCKED.

### 테스트
신규 `tests/test_orchestrator_policy.py`(20). 전체 스위트 **218 → 238 green**. vault 미접근(순수
오케스트레이터 로직 + SubmitGate 가산 수정). SubmitGate 기존 테스트 전부 통과(게이트 opt-in 기본 off).

## Finding P30 (2026-10-31): integration rehearsal — all policies wired into one end-to-end run

v2의 핵심 실패("오케스트레이션이 함께 돌지 않음")를 v3에서 선제 증명. 분야 하네스·커넥터·SubmitGate·
정책(StopLoss/Scheduler/triage/reproducer)을 하나의 에이전트 run으로 결합해 결정론 mock 대회를 한 바퀴
돌렸다. 라이브 0, LLM 0, 성능 주장 없음.

### 배선
신규 통합 오케스트레이터 `orchestrator/competition.py`의 `run()`에 네 정책을 함께 연결:
fetch(connector.mock_ctfd+CTFdClient) → classify/route → Scheduler(flags-per-hour) → 문제당 StopLoss
라운드 루프 → 후보 → triage.first_pass/is_decoy → SubmitGate(decoy_check+reproducer, 재현-후-제출) →
제출. Phase-0 `Supervisor`(단일큐 mock 엔진)는 **의도적으로 미변경**(238 테스트 역호환 보존) — 통합
run은 competition이 담당. 제출 cid는 live_<n>→CTFd 정수 id로 매핑(게이트 dedup/log은 그 id로 키).

### end-to-end 모의 대회 (역할별 6문제, 결정론 scripted 솔버)
한 번의 run 로그(각 정책 발화):
- live_1 crypto/crypto_lane pri100 → **first_pass**가 flag.txt 노출 플래그 즉시 풀이→제출 correct.
- live_2 web/web_lane pri80 → 정상 라운드→후보→**재현 성공**→제출 correct.
- live_6 pwn/pwn_lane pri60 → 무진전+검증체인 보유 → **stop-loss near-miss 예산 1회 상향** → round4 풀이.
- live_5 ai/ai_lane pri50 → 후보 정답이나 **재현실패(ReproductionFailed)** → 제출 차단 → stop-loss.
- live_4 misc/generic pri30 → first_pass+scripted 후보가 SAMPLE FLAG → **디코이 거부(DecoyRejected)** → 미제출.
- live_3 rev/rev_lane pri25 → 무진전 3라운드 → **stop-loss 손절**.
스케줄러가 기대값(점수/난이도÷cost) 순으로 처리(priority 100→80→60→50→30→25). 플랫폼에 도달한 제출은
실제 3건(id 1,2,6)뿐 — 디코이·재현실패는 네트워크 이전 차단, 디코이 값은 서버에 전송 0.

### 추가 증명
- 전역 예산 상한: global experiments cap 소진 시 큐 조기 종료(remaining 남김) — 테스트.
- 중단/재개: max_challenges=2로 중단→state.json 체크포인트→새 Competition이 나머지 완주, SubmitGate
  로그 재생으로 live_1/live_2 **재제출 0**(idempotent) — 테스트.
- 서브에이전트 직접 제출 파이프라인 내에서도 여전히 불가(NotAuthorized) — 테스트.

### 테스트
신규 `tests/test_competition.py`(4). 전체 스위트 **238 → 242 green**. mock만, 라이브 0, vault 미접근.

## Finding P31 (2026-10-31): Pwn C1 cheatsheet + C0-vs-C1 paired probe on a hard-heap holdout

C1(분야 지식 치트시트) 가치를 고난도 홀드아웃에서 측정. 치트시트를 확립하고(skills/pwn/, SKILL.md
점진공개 포맷 — 이후 분야 복제용) CryptoPwn(rp_318b7c, 16a가 능력한계로 FAILED한 glibc-2.31 heap)에서
C0 vs C1 페어드 ×1. 예산·@k·도구·이미지·블라인드·boundary 동일, **차이는 치트시트 주입뿐**. 라이브 0,
성능 주장 없음.

### 치트시트 (knowledge-only, 우리 말)
skills/pwn/{SKILL.md(얇은 라우터), heap.md, glibc_versions.md, leaks.md, rop.md}. tcache poisoning
(+safe-linking 2.32), fastbin dup, unsorted-bin leak, House of Force/Apple, FSOP/_IO_FILE, tcache key,
glibc 2.23→2.35 차이, 누출 전략, ROP/SROP/ret2csu/pivot. 주입 메커니즘 orchestrator/skill_pack.py
(inject=C0프롬프트+pack; 복제 가능 패턴). 구조 테스트 tests/test_skill_pack.py(9). 플래그/익스플로잇 0.

### 측정 (runner eval/p31_pwn_c1_runner.py, pwn_cli p31 라우트; p8/c0b 블라인드 머신러리 재사용)
| arm | lever | 결과 | n_exp | kind | transcript |
|---|---|---|---|---|---|
| C0 | 치트시트 없음 | FAILED | 15/15 | implementation_bug | CLEAN |
| C1 | pwn 치트시트 주입 | FAILED | 14/15 | implementation_bug | CLEAN |
**verdict = NO_CONVERSION** (16a baseline도 FAILED → 재확인).

### 치트시트가 실제 쓰였나 (우연 아님 확인)
C1 trace(자기보고 + CLEAN transcript): glibc_versions.md(2.31→hooks 존재·pre-safe-linking이라 fd 위조에
heap-leak 불요)와 heap.md(tcache poisoning 타깃=__free_hook)가 **의도된 RCE 경로를 정확히 프레이밍**,
leaks.md가 decode OOB-read를 leak 서브문제로 매칭. 즉 지식은 engage되어 방향을 올바로 잡아줌 — 우연 아님.
단, 특정 encode-grow 오버플로 발견엔 도움 안 됨(디스어셈 독해 필요).

### 전환 실패의 진짜 원인 (지식 아님)
- C0: arbitrary-fd-read 누출 1차primitive를 라이브에서 **실제 트리거**(e15), base64 헬퍼 버그+예산소진으로 1실험 부족.
- C1: encode-core heap 오버플로 발견했으나 기록값이 순차 16-bit 인덱스(<0x1fff)뿐 → tcache fd에 8바이트
  포인터 심기 불가, heap grooming+별도 leak 필요. 예산 대부분을 정적 리버싱(6KB 출력캡)에 소모.
- 두 arm이 **서로 다른 버그**(fd-read vs heap-overflow)를 택함 = 접근 변동성 큼(P23 "variance is large" 일치).
- 결론: 이 heap_hard 실패는 **지식 갭이 아니라 예산+도구(실험 15회·출력 6KB캡)+본질적 난이도**가 binding.
  P23 기록("CryptoPwn needs BOTH budget AND heap work; neither lever alone converts")과 일치. 치트시트는
  방향 설정엔 유효하나 C0 예산에선 전환 레버가 아님.

### 무결성
FWS 0, non-container 0, 두 transcript 모두 CLI-only CLEAN(solver가 비밀 미접근), vault 전 구간 chmod-0.
report.json의 trap_hits_any는 오케스트레이터 self-read(내 manifest 조회 + verifier의 scorer-key 읽기 +
이전 페이즈 gen_*.py)로 solver 접근 아님(P14 self-read 주의와 동일; CLEAN transcript가 권위 신호). vault 재-lock.
공정성 사건: 첫 C1 시도에 pack을 압축·C0가 찾은 버그를 가리키는 NOTE를 사후 추가하는 오염을 범해 즉시
kill(실작업 전)하고 c1 run 리셋 후 **verbatim 사전저작 pack**으로 재실행.

### 판정 + 다음
N=1·변동성 큼 → "치트시트가 고난도 heap을 전환" 신호는 **없음**(NO_CONVERSION). 단 지식은 경로를 올바로
프레이밍함(죽은 레버 아님). 이 전환엔 예산/도구 레버가 필요. subset 확장(±grid/zone 등)·다른 분야 C1은
승인 후. 신규 테스트 9(skill_pack) → 전체 **251 green** 유지(라이브 측정은 테스트 수와 무관).

## Finding P33 (2026-10-31): pwn-service boundary generalization — 3/3 deployment gaps fixed

Phase 23가 "능력 아님, 배포 공백"으로 분류한 pwn 실패 3개를 2-uid 경계 일반화로 해소. 반치팅
(에이전트 flag 직접 read 불가) 불변 유지. 오프라인·결정론·비-LLM 검증(합성 회귀 + 실문제 배포가능 프로브).

### 수정 (tools/pwn_service.py BOUNDARY_INIT, 경계 일반화)
1. **companion/service-writable cwd**: 서비스 run_cwd(+manifest `service_writable`)를 service-uid
   소유·쓰기가능으로. 바이너리가 기동 시 cookies.txt/oracle.txt 등 런타임 동반파일을 생성 가능.
   **순서 주의**: flag 스테이징(root가 root-owned 디렉토리에 기록)을 먼저, cwd chown은 그 후
   (root엔 CAP_DAC_OVERRIDE 없어 service-owned 디렉토리에 flag 생성 불가 → 먼저 스테이징). flag는
   여전히 640 service-owned(디렉토리 소유 변경이 파일을 바꾸지 않음) → 에이전트 접근 불가 불변.
2. **최소 /etc/passwd + /etc/group**: root init이 drop 전에 root/service/agent uid 엔트리를 추가
   (민감정보 0, 누락분만). getpwuid()가 성공해 GNUstep/NSUserName류 init이 죽지 않음. env USER/HOME은
   getpwuid를 만족 못함 — 실제 passwd 엔트리 필요.
3. **forking/own-port 서버**: `if binds_port:` → `if binds_port is not None:` (0="binds, port unknown"이
   falsy로 stdio 포워더에 오라우팅되던 버그). own-port 서버는 직접 실행 + **포트 발견 TCP 릴레이**
   (/proc/net/tcp의 LISTEN 포트 파싱 → 서버가 실제 바인드한 포트 P 발견 → P≠PORT면 service-uid 릴레이
   PORT→P). 서버가 하드코딩 포트를 바인드하고 $PORT를 무시해도 에이전트는 항상 127.0.0.1:PORT로 도달,
   배너/handshake가 바이트 그대로 중계됨(서버는 연결당 fork 유지 = 단일 in-flight 불변).

### 전환표 (배포불가 → 배포가능; P23 분류 기준)
| cid | 문제 | P23 상태 | P33 결과 | 증거 | 반치팅 |
|---|---|---|---|---|---|
| rp_7144fe | Pop Goes the Printer (GNUstep) | 배포불가(passwd 없어 init abort) | **배포가능** | 서비스 기동 + 107B 배너 수신 | flag read DENIED(EACCES) |
| rp_84e8fd | horrorscope (companion) | 배포불가(cookies/oracle 부재 SIGSEGV) | **배포가능** | 서비스 기동 + 402B 배너 (writable cwd로 런타임 동반파일 생성) | DENIED |
| rp_7f2db1 | Salt Server (forking own-port) | 배포불가(32B handshake 미중계) | **배포가능** | 릴레이로 **32B handshake 수신** | DENIED |

**3/3 전환, 반치팅 전원 불변**(각 문제 에이전트 uid가 staged flag 직접 open → 전부 EACCES/ENOENT, 평문 0).

### 배포 OK vs 능력 분리 (정직)
"배포가능"은 서비스가 기동하고 에이전트가 연결·배너를 받는다는 뜻(= 측정 가능해짐). 실제 SOLVED(능력)은
별개: 참조 익스플로잇이 존재해야 하고, pop_goes_the_printer는 P16a가 "ObjC 디코더 부재"(도구/능력)도
지적함. 즉 **배포갭은 닫혔고, 능력갭은 baseline 재측정에서 분리 측정**(다음 단계). 성능 주장 없음.

### 테스트
신규 tests/test_pwn_boundary_generalized.py(4: companion·passwd·forking + 반치팅), 각 합성 미니서비스로
결정론 검증(이미지 없으면 skip), vault-free. 기존 test_pwn_boundary/test_pwn_deploy 회귀 통과(경계
불변). 실문제 3개 배포가능 프로브는 vault 언락 하 결정론 수행 후 재-lock. FWS/치팅/egress 0.

## Finding P34 (2026-11-01): integration rehearsal — whole agent, real LLM, mixed holdout

통합 에이전트가 "실제 LLM 풀이"로 혼합 홀드아웃을 end-to-end 처리하는지 검증(본선 리허설 + 전 부품
실작동 증명). 세션이 오케스트레이터로 정책 객체(Scheduler/StopLoss/triage/SubmitGate)를 돌리고,
문제별 실 서브에이전트가 분야 CLI에서 블라인드로 풀이 → 후보 → triage/디코이 → 재현게이트 →
SubmitGate → mock_ctfd. 플랫폼=mock_ctfd(라이브 0). 소표본 sanity, 성능 주장 없음. 상세: docs/p34_rehearsal.md.

### 세트 (8문제, 3 하네스; crypto 불가)
misc(plain): leaked_flag, simple_recovery, showdown(디코이) · pwn(2-uid): baby_boi, WarmUp,
horrorscope(P33 배포) · rev(합성 r7_* 세트): r7_099e2f, r7_0b1253. crypto는 블라인드 arena 미적재로 제외.

### 결과 (3버킷) — store/p34_rehearsal/report.json
- **5 SOLVED / 3 FAILED / 0 BLOCKED**. misc 1/2, pwn 2/1, rev 2/0.
- 5개 SOLVED 전부 **깨끗한 재현(히스토리 없는 승리 실험 재실행)** 통과 후 SubmitGate→mock_ctfd=**correct**.
- FAILED: showdown/leaked_flag(원격-오분류, 올바른 give_up), horrorscope(배포됨+라이브 상호작용, glibc-2.34
  무기화 한계 = 능력-bound, 배포 아님).
- 무결성: **FWS 0, non-container 0, trap_hits [] (블라인드 유지), 서브에이전트 직접제출 3분야 전부 차단**.
  nonclean 2건(mr_73bb9c FAILED, r7_099e2f SOLVED+trap-clean) = 양성(P22류).

### 정책 live 발화
Scheduler 기대값 순 처리; **재현게이트**(실제 false-negative를 런 중 포착·수정 후 5/5 재현·제출);
SubmitGate→mock_ctfd(5/5 correct); 서브에이전트 제출 차단(전 분야); triage 디코이(showdown 샘플 —
에이전트가 올바로 미보고 → 후보 없음, 스크린 준비됨); StopLoss=give_up/exhaust 손절.
P33 경계 수정 **in-situ 검증**(horrorscope 기동+라이브 상호작용).

### 마찰점 (본선 전 수정 큐; docs/p34_rehearsal.md)
1. crypto 블라인드 arena 미적재 → 적재 필요. 2. rev 홀드아웃(rr_*) 미키잉 → 합성 r7_*로 대체(라벨됨),
실홀드아웃 키잉 필요. 3. 재현게이트 경로(harness/ 중첩) **수정됨**. 4. pwn 경계가 exp 코드 미보존 →
**수정됨**(exp_code/<name>.py). 5. misc 이미지 7z 바이너리 부재 → p7zip 추가 권장. 6. Scheduler 키
cid/id **수정됨**. 7. 분야별 lock이 형제 디렉토리를 상호 잠금 → 분야 순차 실행. 8. competition.py는 LLM
스폰 불가 → 통합 실풀이 run은 세션-오케스트레이션(정책 객체 재사용).

### 산출/테스트
신규 eval/p34_rehearsal.py(오케스트레이션+3버킷+정책로그), misc_cli/pwn_cli/rev_cli에 p34 라우트,
pwn_service_harness 수정(exp 코드 보존). store/p34_rehearsal/{misc,pwn,rev}/{results,submit_report}.json +
report.json. 전체 스위트 **255 green 유지**(회귀 0). vault 재-lock.

## Finding P35 (2026-11-01): finals-prep — friction cleanup + runbook

Phase 34 마찰점 큐를 정리하고 본선 런북을 작성. 오프라인·무과금. 두 개는 조사로 재평가됨(아래).

### 적재 현실 (조사 결과 — 중요)
- **crypto 블라인드 arena: 적재 불가.** NYU 벤치에 crypto 카테고리가 없음(카테고리=forensics/misc/
  pwn/rev/web). 실제 crypto 홀드아웃 소스가 없어 적재 불가 — crypto는 합성 전용(eval/make_dev_*).
  즉 crypto 실홀드아웃 baseline/C1은 현 자료로 불가(정직 보고; 날조 금지).
- **rev 실홀드아웃: 이미 키잉됨(P34 오진).** eval/real_loader.py가 arena/real_rev(rr_*) +
  vault/scorer_keys_real + manifest_real.json(holdout 20/dev 9)으로 이미 적재·키잉함. P34가 합성
  r7_*/scorer_keys_rev를 잘못 사용. 본선/C1 rev는 rr_* + scorer_keys_real 사용해야 함(구조 위반 0, 재적재 불요).

### 수정 (엔지니어링)
- **misc p7zip**: ctfagent-misc:0.2(docker/Dockerfile.misc2 = 0.1 위에 p7zip-full 레이어).
  7z/7za가 --network none·non-root에서 동작 스모크 통과(p7zip-full=16.02+really26.02). 0.1은
  기존 결과 재현용 보존; 본선 misc 이미지=0.2. 버전 docker/misc_versions_0.2.txt.
- **회귀 고정**: tests/test_p34_fixes.py(6) — 재현게이트 _winning_code 경로(misc work/ + pwn exp_code/),
  pwn exp 코드 보존, Scheduler cid→id 매핑, rev 실홀드아웃 존재.
- **순차 실행 제약**: 분야별 vault lock이 형제 블라인드 디렉토리를 상호 잠금 → 분야 동시 블라인드 불가,
  순차 실행 필수. docs/runbook.md §6에 명문화.

### 런북 docs/runbook.md
본선 실행 단계(acdc.env→fetch→분류/스케줄→문제별 서브에이전트 스폰→triage/디코이→재현게이트→
SubmitGate→제출), competition.py=정책 레이어·실풀이는 세션 구동 명시, 제출 거버넌스·레이트리밋·
재시도/재개·좀비정리 체크리스트, "약점 발견→수정" 절차, 홀드아웃 세트 목록(crypto 부재 명시).

### 테스트
전체 스위트 **255 → 261 green**(신규 6). 라이브 접속 0, 블라인드/반치팅 불변, vault 재-lock.

## Finding P37 — Crypto knowledge+tool routing layer (capability insurance, no delta claim)
Built a C1 crypto layer: specialist-tool image `ctfagent-crypto:0.2` (FROM 0.1, kept) + a
signal→technique→tool router (`skills/crypto/`) wired through the existing `skill_pack`
injection, same progressive-disclosure pattern as pwn.
- **Why no delta is measured here**: measurement showed Claude excludes tools on EASY
  problems (C1−C0 ≈ 0), so tool/knowledge value shows up only on HARD problems Claude
  can't do bare-handed. This layer is deliberately a **capability investment for hard
  crypto**, NOT an easy-set booster — we do not claim or measure a solve-rate delta.
- **Image 0.2 (5.91 GB)**: + SageMath 9.5 (Coppersmith/ECC/DLOG/lattice), fpylll 0.6.4
  (LLL/BKZ; needed `cysignals`), RsaCtfTool (pip-installed package → `RsaCtfTool` command;
  many OFFLINE RSA attacks). Build-time network only; runtime always `--network none`.
- **Offline caveat**: `factordb` is present only as a RsaCtfTool transitive dep and is
  NETWORK-ONLY (queries factordb.com) → unusable under `--network none`; the router marks
  it unavailable and routes elsewhere. sage needs a writable `HOME` → set `HOME=/work`.
- **Routing trace** (`eval/p37_crypto_trace.py`, store/p37_crypto): all 3 signals route to
  the right tool AND the tool really runs in-container `--network none` with the correct
  result — close-primes→RsaCtfTool(fermat) factored n; low-density subset-sum→fpylll(LLL)
  recovered the subset; stereotyped message→sage `small_roots` recovered the unknown.
- Knowledge authored in our own words (no external skill/code copy). Structure test
  `tests/test_crypto_skill_pack.py`. Isolation/blind/SubmitGate unchanged.

## Finding P38 — pwn knowledge+tool layer (image 0.3: pwndbg+angr+ropper) does NOT convert the heap_hard holdout subset (C0 0/5 vs C1+tools 0/5), with material environment caveats
Paired ×1, blind, image 0.1 (C0) vs 0.3 + verbatim skills/pwn pack (C1+tools), identical
budget 15 exp / 1800 s, same pwn-service 2-uid boundary, --network none. Subset =
CryptoPwn (2.31 heap), unsafe-linking (2.35 safe-linking), horrorscope (2.34 UAF),
Salt Server (forking own-port), pop_goes_the_printer (GNUstep/ObjC). Result: C0 0/5,
C1 0/5 — NEITHER on all five (store/p38_pwn/report.json). Integrity: FWS 0, cheating 0,
egress 0, non-container 0, trap_hits [], 10/10 transcripts CLI-clean.

Why no conversion (per-target, from the agents' own give-up analyses):
- **Budget was the recurring binding constraint, not knowledge.** On the two genuine
  heap targets (CryptoPwn, unsafe-linking) BOTH C0 and C1 fully reversed the binary,
  found the intended bug, and (unsafe-linking) verified a heap/safe-linking leak live +
  designed a complete House-of-Apple-2 chain — then ran out of the 15-exp / 1800-s
  budget before the multi-stage single-shot exploit could be built and fired. C1's
  knowledge arguably oriented it better (CryptoPwn C1 named the exact 2.31 __free_hook
  chain; unsafe-linking C1 designed an unlimited-leak via the logo FILE to beat the
  one-read counter) but the wall was identical. Matches P23/P31: "needs BOTH budget AND
  heap work; neither lever alone converts."
- **pwndbg — the measured tool — was effectively UNUSABLE in both heap targets where it
  mattered.** (a) unsafe-linking: pwndbg's gdbinit auto-update threw PermissionError on
  /root/.local/bin/poetry → agent fell back to plain gdb. (b) horrorscope: /work is
  noexec and /input/target is read-only for the agent uid, so the agent could not run
  the target under gdb to observe the live heap/tcache. So the C1+pwndbg condition could
  not deliver pwndbg's core value (live heap introspection) within budget. This is a
  HARNESS limitation, not evidence that heap introspection is useless — it means a fair
  pwndbg test needs: an exec-able target copy for the agent, and a pwndbg that loads
  without the Poetry write. (Fix deferred — changing it mid-measurement would break C0/C1
  comparability.)
- **Two targets are not heap-tooling problems at all** (symmetric across C0/C1, so no
  tool could convert): Salt Server = bespoke SHA-512/Curve25519 crypto protocol needing a
  faithful reimplementation (both agents correctly declined angr/pwndbg as wrong-tool);
  pop_goes = the live GNUstep service aborts pre-main on NSUserName ("Unable to determine
  current user name") — a DEPLOYMENT fault (no passwd entry / empty USER env for the
  service uid). NB: Phase 33 claimed to fix pop_goes via ensure_etc_users; two independent
  agents (C0+C1) show it still aborts here, so the P33 fix is NOT effective for the real
  pgtp under the p38 route — re-open as a harness bug.

angr: the subset is heap/ROP/ObjC/crypto — NOT angr-shaped. No agent used angr on a real
target (correctly; the tool router says angr is the wrong tool for heap/pure-ROP). angr's
capability-insurance value is shown only by the synthetic sanity trace
store/p38_pwn/trace.json (routes VM/logic signal → angr → symbolic solve in-container →
correct input), not by this subset.

VERDICT (honest, per the user's framing): on this heap_hard subset, knowledge+tools did
NOT convert — but the result is CONFOUNDED by (i) a hard 15-exp budget that both
conditions spent on reversing before any exploit, and (ii) sandbox friction that disabled
pwndbg exactly where it was needed. So this is NOT a clean "tools don't help high-difficulty
pwn" conclusion; it is "at THIS budget and with pwndbg environmentally hobbled, the tool
layer added orientation but no conversion." A cleaner re-test would raise budget AND fix the
pwndbg exec/Poetry friction. Capability-insurance (angr for VM/logic, pwndbg for heap when
runnable) remains justified; the easy-set delta is not measured (ceiling), as in crypto P37.

## Finding P39 — pwndbg made runnable for the agent + heap budget raised to 30/3600; fair heap re-measure = 0 conversions but NOT tool-attributable (walls moved to recv-cap / wall-clock / a [cyber] safeguard)
Phase 38's heap_hard 0/5 was confounded (budget spent on RE; pwndbg unloadable). Phase 39 fixed
both and re-measured the 2 genuine heap targets (CryptoPwn 2.31, unsafe-linking 2.35) at 30 exp /
3600 s, C0 (image 0.1) vs C1 (image 0.3 + verbatim pack + WORKING pwndbg).

HARNESS FIX (tools/pwn_service.py, additive; tests/test_p39_pwndbg_fix.py, +6, full suite 278 green):
- Boundary now stages an exec-able copy of the PUBLIC target at /dbg/target (+ /dbg/libs) on a
  `--tmpfs /dbg:rw,exec` mount, so the agent can run the binary under gdb/pwndbg (/work is a noexec
  bind, /input is read-only). The FLAG is never written to /dbg -> anti-cheat invariant preserved
  (proven: agent reads /dbg/target but every flag path stays PermissionDenied; trap_hits []).
- Agent HOME set to /dbg so pwndbg's gdbinit find_poetry() no longer does Path("~/.local/bin/poetry")
  .exists() against /root (0700) and raises PermissionError. Verified: pwndbg loads (165 cmds),
  heap/tcachebins work for the agent uid.

RESULT (store/p39_pwn/report.json): C0 0/2, C1 0/2, zero conversions, FWS 0, cheating 0, egress 0,
trap_hits []. BUT the result is NOT a clean "tools don't help", because at the raised budget with
tools runnable the binding wall MOVED off "budget/tooling" to problem/harness-specific limits:
- CryptoPwn: C0 hit the session total-recv cap (262144 B) traversing the 256-round Challenge gate
  (the ONLY path to the sole corruption primitive); C1 independently concluded Decode is logically
  unreachable and found NO exploitable primitive at all -> pwndbg/angr/ropper had nothing to act on.
  Both FAILED. This is a genuine NEITHER, but the wall is the recv-cap / challenge-gate, not heap tooling.
- unsafe-linking: C0 built THREE gdb-verified primitives (heap+safe-link leak, arbitrary free via a
  dangling ctrl chunk, libc leak via the logo FILE vtable) and designed the full House-of-Apple-2
  chain, but died on WALL-CLOCK (a 2^24 Python brute-force + gdb calibration ate ~3300 s of 3600 s).
  C1 (working pwndbg) was TERMINATED mid-exploit by the Anthropic API [cyber] safeguard while firing
  the HoA2 system() chain (req_011Cgi8QxadrxpNhpoi8BzPF) -> outcome-blind infra kill, excluded (same
  class as P16a 'feather'). So the decisive comparison is INCONCLUSIVE in both arms.

VERDICT: the pwndbg-unrunnable confound is now FIXED (pwndbg runs for the agent, anti-cheat intact),
but the hypothesis "tools+routing convert high-difficulty heap" remains UNRESOLVED on this subset:
0 conversions, yet neither failure is attributable to lacking tools — the walls were a 256KB recv
cap, a 3600s wall-clock vs a 2^24 brute-force, and an infra safeguard. Cleaner future attempts:
(1) raise/stream past the session recv-cap so CryptoPwn's challenge-gate is traversable (or pick heap
targets without a megabyte-scale gate); (2) give the agent a faster solver path / more wall-clock so
unsafe-linking's brute-force doesn't eat the budget; (3) the [cyber] safeguard on live HoA2/shellcraft
is an environment limit on measuring weaponization end-to-end, not a capability signal.

## Finding P40 (2026-11-05) — Reverse C0 vs C1+angr: 0 conversions, wall = experiment budget (not tools, not safeguards)

Reverse is the FAIR ground the pwn phases (P38/P39) lacked: pure analysis (no weaponization
→ no [cyber] safeguard exposure, confirmed 0 terminations), angr's real home (VM/CFG/logic),
and a genuine holdout of hard failures. Built ctfagent-rev:0.2 (= rev:0.1 + angr 10.0.5, pinned
to the pwn:0.3 stack; radare2 still absent from bookworm, recorded) with a sitecustomize shim so
angr imports cleanly under the passwd-less sandbox uid + read-only root (HOME/TMPDIR→/work,
synthetic getpwuid). Authored skills/reverse/ (SKILL.md router + vm/cfg_flatten/constraints/
antidebug/stripped, angr state-explosion guard first). angr sanity trace PASS: recovered the
accepted input of a genuine fetch/decode/execute VM end-to-end in-container
(store/p40_rev/trace.json) — the conversion mechanism is real symbolic execution, not luck.

MEASURED: C0 (rev:0.1, no angr, no pack) vs C1+tools (rev:0.2, angr + reverse router pack),
paired/blind/×1, 12 exp / 1800 s / 240 s-per-exp and 2g memory IDENTICAL on both arms, on the 4
Phase-36 rev failures (halfpike 4004-emulator, parallel-vm concurrent-bytecode-VM,
steady_counting OLLVM-flattened, brrr SHA-512-per-byte). Result: **C0 1/4, C1 1/4, ZERO
conversions** (store/p40_rev/report.json). FWS 0, trap_hits [], non-container 0. (One non-clean
C0 transcript = that agent spawned its own background non-CLI command; FAILED regardless.)

- brrr: BOTH_SOLVED (flag{such_pr1m1t1v3_t3chn0l0gy}). NOT angr-shaped — 44 independent per-byte
  SHA-512 digests; both arms recovered it by gdb byte-brute. Tools/pack made no difference.
- parallel vm / steady_counting / halfpike: NEITHER. These ARE angr's domain, and the C1 agents
  DID engage the symbolic kit (tool_use: angr on steady_counting, z3 on parallel vm) with correct
  plans — but every one ran into the 12-experiment budget consumed by reversing + building the
  symbolic/emulator harness + a trivial driver bug (parallel vm: one STORE-vs-LOAD opcode bug;
  steady_counting: Veritesting lift crash then an `sm.found` typo; halfpike: budget spent reading
  the 23KB 4004 source). Each reported being 1–2 experiments short of a solve.

VERDICT: 0 conversions, but NOT "tools are useless." angr is proven working and correctly reached
for on the right targets; the binding wall is the per-challenge EXPERIMENT BUDGET for doing BOTH
the reverse AND the symbolic-harness build in one blind run — not tool availability (C0 lacked
angr and still matched C1), and not a safeguard (reverse is analysis; no [cyber] exposure). This
is a cleaner, fully-attributable negative than P38/P39: the fix is budget/harness-build ergonomics
(raise exp budget for VM/CFG, and/or persist /work across experiments so the emulator is built
once and reused), not a capability gap. On this 4-target subset the angr+router lever did not
convert a C0 failure.

## Finding P41 (2026-11-05) — Reverse C0 vs C1, FAIR re-measure (persisted /work + 20-exp budget): FIRST CONVERSION

Phase 40 left reverse's negative attributed to experiment-budget-for-harness-build, not tools.
P41 removed that excuse: (1) opt-in persisted /work (solver/crypto_harness.persist_work, default
off → 297 tests green; one shared /work per run so unpacked sources / built emulators / angr
scripts survive between experiments), (2) budget raised to 20 exp / 3000 s / 300 s-per-exp,
IDENTICAL on C0 and C1. Re-measured the 3 angr-domain targets (brrr dropped — P40 both-solved by
gdb-brute). C0 (rev:0.1, no angr, no pack) vs C1+tools (rev:0.2, angr + reverse router pack),
paired/blind/×1.

RESULT (store/p41_rev/report.json): **C0 0/3, C1 1/3 — ONE CONVERSION (halfpike).**
- halfpike (rr_1b3102, 4004 emulator): **C1_CONVERTED** — C0 FAILED, C1 SOLVED flag{intl_cpus_scare_me}.
  BOTH arms built a Python 4004 emulator in persisted /work with equal budget; the DIFFERENTIATOR
  was the oracle. C1 used the program's INTERNAL compare-pass signal as a per-position oracle (what
  the pack's VM/emulator section prescribes) and resolved all 24 chars; C0 used an instruction-count
  oracle that PLATEAUED on positions 12-14 and ran out (its guess flag{intel_cpu_scare_me} rejected).
  Conversion is KNOWLEDGE-PACK-attributed, NOT angr (C1 tools_used=[]; emulator, not symbolic). n=1.
- parallel vm (rr_df0262, concurrent bytecode VM + TEA): NEITHER. Both fully reversed the ISA; C1
  left a working emulator + z3 solver in persisted /work, cut off "as solve2.py was about to run";
  C0 found the conditional-jump opcode only on exp 20. ~1 experiment short even at 20/3000.
- steady_counting (rr_96228d, OLLVM-flattened): NEITHER + integrity ding. A Collatz opaque-predicate
  count oracle recovers the prefix (both got flag{ins_coun...), but the 17-char tail is validated as
  a BLOCK (fn 0x400770) with NO per-char gradient. C0 gave up cleanly; C1 reported an UNVERIFIED
  wrong flag → flag_without_solution (FWS). Over-eager guess, NOT cheating (trap_hits [], no vault).

Integrity: FWS 1 (C1 steady_counting — pass-criterion "FWS 0" VIOLATED, over-eagerness not cheating;
C0 prompts hardened to "never guess / confirm run-to-win" produced 0 FWS). trap_hits [], non-container
0. 4 non-clean transcripts = agents ran own background (non-CLI) commands for long emulator/angr runs;
every verdict is still scorer-verified against the locked key.

VERDICT: the FIRST conversion across all phases, on fair same-budget/same-persisted-/work terms →
the hypothesis "knowledge+tools+budget+ergonomics convert high-difficulty reverse" is SUPPORTED but
NARROWLY (1/3, n=1), and via PACK-ROUTED METHODOLOGY (the right per-position oracle), not angr (angr
timed out on the flattened target; z3 wasn't run in time on the VM). The two that still failed show
the hardest reverse — long VM-inversion chains and gradient-less block constraints — sits at the
human-grade analysis limit with NO environment excuse left (angr works, budget raised, /work
persisted, 0 [cyber] safeguard exposures). /work persistence worked (emulators built once + reused)
but agents still spent the budget on the reversing+solver-debugging itself, not setup.

## Finding P42 (2026-11-05) — Misc/forensics knowledge+tool routing added (image 0.3); FWS guard unified across all domains; capability insurance, solve-rate deferred

Replicated the crypto/pwn/reverse "knowledge pack + specialist tools" pattern for misc/forensics,
and fixed a cross-cutting integrity gap surfaced in P41. No conversion hunt and NO solve-rate claim —
the goal was (1) routing works end-to-end with real in-container tool calls, (2) isolation/anti-cheat
intact, (3) the C1 prompt stops guessing flags.

FWS GUARD UNIFIED (all domains). P41 showed a C1 (pack-injected) reverse agent report an unverified
WRONG flag (steady_counting) after the knowledge pack text softened the prompt into "background",
dropping the C0 hard guard. Fix is central: orchestrator/skill_pack.inject() now restates the guard in
the injected header for EVERY category — "never report a guessed/pattern-matched flag; no `report`
before an in-container run-to-win (or an explicit evidence chain); a plausible-but-unverified flag is
NOT submittable; give up cleanly instead." So C1 == C0 on the no-guess rule. Verified present for
crypto/pwn/reverse/misc (tests/test_misc_skill_pack.TestFwsGuardUnification). Backstop re-locked: even
a candidate equal to the real flag with no container evidence chain → verifier FLAG_WITHOUT_SOLUTION,
never SOLVED (TestUnverifiedCandidateBlocked).

IMAGE ctfagent-misc:0.3 (FROM 0.2; build-net only, runtime --network none; 0.1/0.2 preserved; 3.62GB):
+ sleuthkit 4.11.1 (fls/icat/tsk_recover/mmls/fsstat — disk/deleted-file forensics)
+ john 1.9.0 + john-data (CPU hash cracking; no GPU so john primary)
+ zbar-tools 0.23.92 (zbarimg CLI; pyzbar/libzbar already in 0.2)
+ volatility3 2.28.2 WITH Windows(840MB)+Linux(3MB)+Mac(85MB) symbol ISF packs BUNDLED → symbol
  resolution works fully offline (the one capability that normally needs network)
+ hashcat 6.2.6 (best-effort/recorded; CPU-only here so router routes rule/mask→hashcat but prefers
  john/other for large keyspaces)

OFFLINE SMOKE (--network none) all PASS, including a genuine forensics demonstration: sleuthkit
recovered a DELETED file from a tiny ext2 image (fls -r marks inode 12 `*`; icat printed its content).
john cracked a descrypt hash; zbarimg decoded a QR; vol imported offline with all packs present.

SANDBOX QUIRK found + documented in skills/misc/crack.md: Debian `john` is CLASSIC (not jumbo) — no
`--pot` flag, stores pot/log under $HOME/.john, does NOT auto-create it. The sandbox uid has no passwd
entry, so john must be run with HOME=/work and a pre-made /work/.john, else it dies with
"`.john/john.log: No such file or directory`". (vol3 isfinfo over the 840MB pack is pathologically
slow — enumerates every ISF — but real plugins look up only the one matching table by banner/hash.)

ROUTER skills/misc/ (our words, 0 copy-paste, progressive disclosure): SKILL.md signal→family→tool
table + 9 detail files (memory/disk/crack/qr_barcode/pcap/stego/archive/jail/encoding), "identify
first → confirm precondition → verify before report" discipline throughout. Carried by skill_pack
unchanged. Default MISC_IMAGE stays 0.1 (pinned by test_misc_pipeline); 0.3 is MISC_IMAGE_FINALS,
selected explicitly by a C1 run (same split rev used for 0.1 vs 0.2).

ROUTING SANITY (eval/p42_misc_trace.py, store/p42_misc/trace.json): 3 lanes signal→router line→REAL
in-container tool invocation under --network none — QR→zbarimg (decoded), hash→john (cracked),
memdump→vol (symbols bundled offline). all_routed=all_invoked=all_ok=True. This is NOT evidence of a
solve-rate; it is evidence the lever is wired and the tools run in isolation.

VERDICT: capability insurance delivered and wired, isolation/anti-cheat intact, and the C1 over-guess
hole from P41 closed centrally. Average misc solve-rate is DEFERRED (unmeasured by design this phase).
"Offline Windows memory analysis" is evidenced by bundled+offline-enumerable symbol tables, not a full
dump-plugin solve (no sample dump shipped). Pre-existing unrelated suite failure noted: store/p40_rev
is mode d--------- (a prior phase's locked artifact) → test_p40_rev_tools PermissionError; left
untouched. STOPPED before the web tool layer per spec.

## Finding P43 (2026-11-05) — Web knowledge+tool routing added (image 0.3: +ffuf, +playwright/chromium best-effort; sqlmap already present); capability insurance, solve-rate deferred — 5 categories now complete

Replicated the crypto/pwn/reverse/misc "knowledge pack + specialist tools" pattern for the FIFTH and
last category, web. No conversion hunt and NO solve-rate claim — the goal was (1) routing works
end-to-end with real in-container tool calls on the 2-uid web-service boundary, (2) isolation/anti-cheat
intact (the agent uid cannot read the service-owned staged flag/source; --network none, loopback-only
target), (3) the C1 prompt carries the same no-guess guard as C0.

IMAGE ctfagent-web:0.3 (FROM 0.2; build-net only, runtime --network none; 0.1/0.2 preserved; ~1.7GB):
+ sqlmap 1.8.10 — ALREADY in 0.1/0.2 via pip; re-verified, no change (SQLi automation)
+ ffuf 2.1.0 — official prebuilt linux-amd64 release binary (bookworm has no ffuf package). REQUIRED
  layer; build aborts if it does not run. (content/parameter discovery)
+ playwright 1.47.0 + chromium-1134 — BEST-EFFORT layer, NON-FATAL on failure (heavy download); the
  layer records /opt/ctfagent/playwright_status.txt and the build continues even if chromium is absent.
  Installed to a FIXED world-readable PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright so the NON-ROOT agent
  uid finds it at runtime (a root-HOME install is invisible to the agent uid — caught in the first
  runtime smoke and fixed). (DOM-XSS / JS-rendered / admin-bot)
kept: requests/httpx/beautifulsoup4, php-cli/flask from 0.1/0.2. wfuzz NOT added (ffuf covers fuzzing).

BUILD-TIME SMOKE (WEB03_SMOKE, all pass): sqlmap --version; ffuf found a hidden path via FUZZ on a
loopback http.server; playwright rendered a local page headless AND ran its JS.
RUNTIME SMOKE (--network none, non-root uid, WEB03_RUNTIME_SMOKE, all pass): net_isolated=true; sqlmap
boolean-extracted a flag from a loopback sqlite-backed app; ffuf found a hidden route; playwright
rendered a loopback http page + ran its JS. This is the real --network none proof (build-time had net).

SANDBOX QUIRKS found + documented in skills/web/fuzzing.md: (1) ffuf's scraper reads $HOME/.config/ffuf;
the sandbox uid has HOME=/nonexistent so ffuf ABORTS before fuzzing — set HOME=/work (+ mkdir
/work/.config/ffuf). (2) chromium must launch with --no-sandbox --disable-dev-shm-usage under the
non-root cap-dropped uid. (Cosmetic: the in-image versions.txt says playwright_pip=ABSENT because the
probe used a nonexistent attribute; real version is 1.47.0 via importlib.metadata — import works.)

ROUTER skills/web/ (our words, 0 copy-paste, progressive disclosure): SKILL.md signal→bug-class→tool
table + 8 detail files (sqli/xss_headless/fuzzing/ssti/tokens_deser/ssrf_xxe/lfi/proto_pollution),
"map the app → identify the bug class → confirm precondition → verify by making the live app disclose
the flag before report" discipline throughout. SQLi→sqlmap, DOM/admin-bot→playwright, discovery→ffuf;
SSTI/JWT·deserialization/SSRF·XXE/LFI/prototype-pollution are knowledge-procedure + requests (no
dedicated CLI). Carried by skill_pack unchanged (has_pack("web")). Default WEB_IMAGE stays 0.1 (0.2 for
the p36 holdout runner); 0.3 is WEB_IMAGE_FINALS, selected explicitly by a C1 run via the p43w CLI
route (same split misc/rev used). The FWS guard header already covers web (skill_pack.inject is
category-agnostic); now asserted for web too.

ROUTING SANITY (eval/p43_web_trace.py → store/p43_web/trace.json, NOT a conversion hunt): 3 lanes on
distinct synthetic 2-uid instances (source_mode=private = genuinely black-box), signal→router line→REAL
in-container tool call under --network none, plus an anti-cheat probe. SQLi→sqlmap (boolean-extracted
the staged flag), discovery→ffuf (found the unlinked /backup.old then fetched the flag), DOM→playwright
(rendered the JS page and read the flag that exists only in the post-JS DOM). Anti-cheat: a direct-read
experiment got DIRECT_READ_HITS [] (cannot read /srv/data or the private /srv/tree/app.py).
all_routed=all_invoked=all_ok=anticheat_ok=True. This is evidence the lever is wired and the tools run
in isolation — NOT a solve-rate.

STRUCTURE TESTS tests/test_web_skill_pack.py (+10): pack present/routes/details; finals-image plumbing
(WEB_IMAGE_FINALS distinct; ffuf/playwright are finals-only extras); FWS-guard carries into the web C1
prompt and across all 5 categories; the verifier anti-FWS backstop holds for a web cid (guessed flag
w/o container evidence → FLAG_WITHOUT_SOLUTION; app-disclosed flag → SOLVED).

EXPLICIT (capability insurance, NOT a solve-rate claim): web routing+tools added as the
crypto/pwn/reverse/misc pattern; this COMPLETES all 5 categories. Average web solve-rate is
DEFERRED/unmeasured by design this phase (no conversion hunt). Easy web challenges have ~0 delta
because Claude self-excludes the tools and solves with plain requests; the tools are insurance for
SQLi-heavy / JS-heavy / discovery-bound targets. playwright is best-effort — a run must check
playwright_status.txt before relying on the headless lane. STOPPED before the autonomous growth loop
design per spec.

## Finding P51 (2026-11-06) — 블라인드 오염면: 미잠금 동일-CID 과거 run 디렉터리 (vault lock이 못 막는 구조적 누출) + 표준 pre-spawn 가드

구조적 사실 (다음 사이클이 반드시 알아야 함): **vault chmod-0 lock은 `STATIC_SECRETS` 트리만 가린다.** 블라인드
dev를 돌릴 때, 같은 challenge id의 **이전 단계 run 디렉터리**(예: `store/p45_misc/p45ms-<cid>-*`,
`store/p48-<cid>-*`, `store/p18_misc/runs/*-<cid>`)는 그 트리 밖에 있어 lock으로 가려지지 않는다. 새로 스폰된
블라인드 solver가 `cat store/p45_misc/p45ms-<자기cid>-*/harness/*` 로 **자기 문제의 과거 풀이 트랜스크립트**를
읽을 수 있다 → 블라인드 독립성 파괴. 플래그 값 자체는 solver run 디렉터리에 안 쓰이지만(= evidence는 exp-id만),
독립 solve 측정으로서는 과거 트랜스크립트 열람이 곧 오염이다. 추가로 `store/p45_misc/runs_46c.json` 류의 집계
파일에는 **평문 후보 플래그값**(`flag{<40hex>}`)이 남아 있어 위생 문제다.

측정 맥락: p51 cycle-1 (misc 0.5, 11개 블라인드 dev `mr_*`, mr_de0abb는 비블라인드로 제외). 시크릿 트리
자체는 정상 — repair가 무장한 trap_files=17783은 p51 정의(16개 `STATIC_SECRETS`) 트리의 **완전한 walk**였고
(부분 arm 아님; p45의 12386 대비 vault 증가로 정합), ~26000 예상치와의 차이는 스코프 차이였다(미잠금 기타
`store/pXX` 28개 ≈ 10140 파일, 17783+10140≈27923). 즉 vault/키 블라인드는 멀쩡했고, 누출면은 **vault 밖**이었다.

수정 (일회성 아님 — **표준 pre-spawn 가드**): `eval/c0b_runner.py`에 재사용 함수 추가(공유 모듈이라 모든
러너가 상속).
- `prior_cid_run_dirs(cids, cycle_root)`: cycle_root 밖에서 이름에 cid를 포함하는 가장 얕은 run 디렉터리 열거.
- `guard_prespawn(cids, cycle_root, extra_hygiene=())`: (a) 위 과거 run 디렉터리, (b) 그 형제 store 디렉터리에
  직접 놓인 **평문 real-flag 파일**(`flag{<16+hex>}` 자동 탐지 — runs_46c.json 등이 하드코딩 없이 잡힘),
  (c) 명시적 extra_hygiene 를 전부 `chmod 0`. 원래 mode를 `cycle_root/prespawn_guard.json`에 기록(복원용).
  **순수 강화(chmod 0)만** 수행 — vault를 약화하지 않으므로 repair()의 chmod-up(분류기가 막는)과 달리
  auto-mode에서 허용됨. 멱등(재실행이 기록된 true mode를 0으로 덮지 않음).
- `unguard_prespawn(cycle_root)`: 기록된 원 mode로 복원.
- `eval/p51_cycle.py`: `prepare()`가 lock 직후 `guard_prespawn(dev, ROOT)`를 **자동 호출**; 수동용
  `guard`/`unguard` 서브커맨드 추가.

적용 결과 (p51c1): 46개 경로 잠금 = 과거 run 디렉터리 41 (p18_misc/runs 6 + p45_misc 35) + 평문-플래그 파일 5
(runs_46c.json, runs.json, requests46c.md, residuals46c_to_judge.json, key_audit_mr_de0abb.json).
검증: 잠금 후 solver-가시 트리에서 **11개 CID 관련 비정상 평문 플래그 누출 = 0**. 11개 중 평문 플래그가
solver에게 보이는 유일한 경우는 각자의 **챌린지 파일 자체**(`arena/real_misc/mr_0a806e|mr_39ddd1/networking.pcap`)
뿐 — 추출 대상이므로 의도된 것. 러너 의존성 없음: p51은 `store/p18_misc/classification.json`(= CID 디렉터리
아님, readable 유지)과 자기 ROOT만 읽음; 과거 run 디렉터리는 grading/diagnose에서 안 읽음.

열린 관찰 (범위 밖, 미조치):
- solver-가시 트리에 **다른 단계/카테고리** 챌린지의 평문 플래그가 178개 파일에 존재(m17_*, w19_*, rr_*,
  mls_*, mr_de0abb 등). 교차-CID라 이번 11개엔 오염 아님(다른 문제 플래그는 report해도 FWS). 그러나 "블라인드"는
  결국 per-CID 가드 + FWS evidence 요구에만 의존함을 뜻함. 장기적으론 run 디렉터리에 평문 플래그를 안 남기는
  하네스 위생이 바람직.
- `arena/real_misc/mr_0a806e/networking.pcap.process` 는 challenge.json의 published `files`에 포함된 정식
  아티팩트(원본 코퍼스 배포 형태). 파생 파일이 추출을 쉽게 만들 여지가 있으나 챌린지 설계 이슈라 가드와 무관.

## Finding P52 (2026-11-06) — Cycle 2: user-approved harness fixes (misc:0.6 crypto + /work persist + crack-class timeout/pids) convert 0/6 cycle-1 failures; fixes correct but expose DEEPER stacked blockers

User-approved the Phase-51 needs-queue HUMAN-GATE harness fixes and asked for a re-measure. Applied WITHOUT
touching governance (7/7 hashes == baseline): (1) image ctfagent-misc:0.6 = 0.5 + pycryptodome 3.21 (AES/RSA);
(2) /work persisted across a run's experiments via crypto/rev's existing opt-in, env-gated MISC_PERSIST_WORK=1
per route (default OFF so existing tests unchanged — an unconditional flip broke 2 misc tests, fixed to the
opt-in pattern); (3) crack-class per-exp timeout 90->300s (MISC_BUDGET) + pids 128->512 (runtime deep-copy of
sandbox.json, file unedited). e2e on 0.6 GREEN: --network none / read-only root / non-root / cap-drop ALL /
no-new-privs intact, /work persists across exps, in-sandbox AES decrypt works, pids=512. Full suite 379 OK.

RE-MEASURE (6 cycle-1 dev failures × K=2 = 12 blind runs, misc:0.6, max_experiments still 12 — the budget lever
stayed gate-rolled-back): **0 conversions.** total_solved delta = 0 (dev stays 5/11). Key-independent: all 12
runs give_up/budget_exhausted with NO candidate. Holdout no strict drop (2/3 -> 2/3; mr_1f8f74 excluded as
non-blind). vault stayed chmod-0 the ENTIRE cycle (no unlock occurred — strongest blind guarantee).

WHY 0 (the honest signal): the fixes were correct and USED, and each removed the cycle-1 proximate blocker — but
exposed a deeper one. mr_42745d: pycryptodome ran real AES attempts, but the key is not derivable from the
artifacts. mr_f0bf90: 300s let a FULL rockyou complete, but the passphrase is custom (not in rockyou).
mr_8c08a5/mr_a5950f/mr_ec419b: reached the FINAL step (reconstructed PPTX / decrypted flag.png / known cascade
path) but ran out at exactly 12 experiments. mr_60057e: NEW tool gap — flag is drawn in a Haiku HVIF vector icon
with no AGG renderer in-container.

KEY re-opened item: with the crypto lib present, the binding constraint for several challenges is now genuinely
experiment COUNT (not per-exp time) — multiple runs died one step from the flag at 12 exp. This is NEW evidence
for the max_experiments budget lever that cycle 1 rolled back on mr_42745d's (then crypto-specific) grounds; a
fresh 12->20 gate on these is now justified. Logged to needs-queue with a new HVIF-renderer tool gap and misc
skill recipes (PPTX <a:t> run-concat; always render a small flag.png to ASCII; multi-line base64 concat).

OPERATIONAL: the auto-mode classifier now consistently blocks an AGENT-issued vault unlock ([Security Weaken]),
including the verifier grade's unlock and the key-audit. Per user instruction these are handed to the user to run
in-terminal (eval/p52_cycle2.py grade ; eval/p52_key_audit.py) rather than worked around. mr_30b660 remains a
reproducible evidenced-candidate-vs-key MISMATCH (key-audit pending user run; CSAW_CTF{...} vs flag{...} format).

## Finding P53 (2026-11-06) — First AUTO-adoption test: budget lever (cap 12->20) gated and ROLLED BACK (auto_applied=0); gate empirically corrected the re-diagnosis

Re-gated the max_experiments budget lever that cycle 2 re-opened. Re-diagnosis (46b + judgment + fail-safe) on
the 4 cycle-2 failures picked TARGETS {mr_8c08a5, mr_a5950f} (reached final step, looked budget-bound); EXCLUDED
mr_ec419b (approach/OCR) and mr_42745d (dead-end: AES key not derivable). Lever = misc hard-band cap 12->20 (NOT
global, cost-bounded). before @cap12 reused from p52c2 (identical harness); after @cap20 fresh K=2.

RESULT: both targets 0/2 -> 0/2 (NO flip), holdout 2->2 no-drop -> **ROLLBACK, auto_applied=0**, hash-verified
(misc_cli.py==S0). The 20-exp runs REVEALED the true blockers, neither of which is budget: mr_8c08a5's flag is a
MaxiCode 2-D barcode (image0.gif) with no in-image decoder (TOOL gap); mr_a5950f's flag.png uses a per-block XOR
keystream (only block0=[0x50,0x3f]) whose generator was uncracked (APPROACH/crypto). For mr_a5950f the 46b
diagnoser's mechanical "approach" bucket was CORRECT and the P53 semantic override to "budget" was WRONG — the
gate caught the misclassification before any standing change. Lesson: "reached the final step" is insufficient
for budget-bucket; the last step must be a working method needing only repetition.

Significance: the first autonomous-growth AUTO-adoption test produced auto_applied=0 — the gate (dev-target flip
AND holdout no-drop, atomic hash-verified rollback) correctly declined a non-converting lever, protecting cost
(no +8 exp/run) and the baseline. Governance 7/7 == baseline; vault re-locked 0o0; solver blindness held (no
unlock during solving). needs-queue reclassified mr_8c08a5->tool(MaxiCode decoder), mr_a5950f->approach(keystream).
