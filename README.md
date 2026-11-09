# ctf_agent_v3 — Phase 0 + Phase 1 + Phase 2 + Phase 3

Jeopardy CTF 자율 풀이 에이전트를 처음부터(clean-room) 만드는 프로젝트의 **Phase 0**입니다.
이 단계에서는 LLM과 CTF 도구 없이 오케스트레이션 골격이 결정론적으로 동작하는지만 확인합니다.

## 범위 (Phase 0)
- 포함: 규칙 기반 분류와 라우팅, mock 솔버, 체크포인트/resume, 이벤트·명령 로그, dedup 캐시, 호출 전 예산 검사
- 제외: 실제 솔버와 도구 실행, LLM 및 외부 API, 경험 저장소, 병렬 실행(concurrency=1 고정)
- 의존성: Python 3 표준 라이브러리만 사용
- 성능은 주장하지 않으며, 테스트 통과 여부만 다룹니다.

## 구조
```
config/settings.json         seed, budget(time_s/max_rounds/max_attempts), concurrency, paths
schemas/records.py           Hypothesis / Experiment / Candidate / Checkpoint
orchestrator/supervisor.py   상태기계(dispatch → experiment → done), 예산 게이트, state.json, resume
orchestrator/classifier.py   확장자·키워드 → category
orchestrator/router.py       category → lane
solver/mock_solver.py        시나리오를 결정론적으로 재생하는 가짜 솔버
solver/experiment_log.py     events.jsonl / commands.jsonl, dedup 키, 캐시
tests/                       lifecycle / dedup / budget
```

## 런타임 산출물 (`store/runs/<run_id>/`)
- `state.json`: resume용 스냅샷입니다. Checkpoint(현재 문제, 활성 가설, 소비 예산, next_action, safe_point)와 큐, 결과를 담고, 원자적으로 교체 저장합니다.
- `events.jsonl`: append-only 이벤트 로그입니다.
- `commands.jsonl`: 실제로 실행한 실험만 기록합니다. dedup 캐시는 resume 시 이 파일로부터 재구성합니다.

## 데이터 계약 요약
- 실험 결과는 `execution_status`(ok/error/timeout/aborted), `observation`, `hypothesis_judgment`(support/refute/inconclusive/deferred)로 분리합니다. 실행이 ok가 아니면 판정을 강제로 inconclusive(aborted이면 deferred)로 바꾸므로, 도구 실패가 가설 반박으로 이어지지 않습니다.
- dedup 키는 `sha256(tool, version, argv[], input_file_hashes, env, timeout, cwd)`입니다. `nondeterministic=True`인 실험과 timeout/aborted 결과는 캐시하지 않습니다. 캐시 hit는 시도 예산을 소비하지 않으며, 판정은 가설별로 다시 내립니다.
- 예산은 모든 dispatch와 실험을 시작하기 전에 검사합니다. 소진되면 `status=aborted`로 바꾸고 `next_action.blocked_by`를 남긴 체크포인트를 저장한 뒤 멈춥니다.

## Phase 1 — 공통 도구 실행 계층 (`tools/`)
실제 명령을 안전하게 실행하는 단발 실행 계층입니다. LLM·실제 CTF 솔버·비신뢰 바이너리·인터랙티브·병렬은 포함하지 않습니다.

```
config/tools.json    도구 allowlist (id→bin/version_cmd/smoke_cmd/deterministic/categories/sandbox_profile)
tools/sandbox.py     격리 백엔드 탐지, netns/rlimit 프로파일, 상태 분류
tools/run_tool.py    run_tool(spec): 검증 → 격리 → 실행 → 결과 스키마, 재현 레코드
tools/probe.py       격리 수단 probe + 도구 존재/버전/스모크 판정
```

### 실제로 강제되는 격리 (이 호스트 기준, probe로 확인)
| 항목 | 수단 | 보장 여부 |
|---|---|---|
| 아웃바운드 네트워크 차단 | `unshare --user --map-root-user --net` (user+net namespace) | **보장** (netns 사용 가능) |
| CPU 시간 상한 | `RLIMIT_CPU` (soft<hard → SIGXCPU) → `aborted` | 보장 |
| 메모리 상한 | `RLIMIT_AS` → 할당 실패(MemoryError) → `error` | 보장(할당 차단) |
| 출력 파일 크기 상한 | `RLIMIT_FSIZE` → 쓰기 거부 → `error` | 보장(쓰기 차단) |
| 월타임 타임아웃 | subprocess timeout + `killpg` → `timeout` | 보장 |
| 셸 주입 차단 | argv 리스트만, 셸 미경유. 메타문자는 리터럴 인자 | 보장 |
| 경로 jail | cwd·argv 경로가 jail 밖이면 실행 전 거부 | **인터페이스 한정** |

- 경로 jail은 "우리가 도구에 넘기는 인자"를 막습니다. 악성 바이너리가 스스로 여는 경로까지 막는 완전한 FS 격리는 mount namespace/docker가 필요하며 이번 단계에서 연결하지 않았습니다. 따라서 allowlist에는 안전한 읽기 전용 유틸리티만 둡니다.
- `docker`는 이 호스트에 있고 더 강한 백엔드이지만, 이번 단계는 stdlib+unshare 경로만 구현하고 probe는 docker 가용성만 보고합니다.
- 네트워크 차단이 미보장인 호스트에서는 `network_guaranteed=False`로 정직하게 표시하고, 비신뢰 실행은 허용하지 않습니다.

### run_tool 결과 스키마
`tool_id, execution_id, execution_status(ok|error|timeout|aborted), return_code, stdout_ref, stderr_ref, stdout_truncated, stderr_truncated, duration, resource_usage, tool_version, reproducibility_level(full|conditional|external_dependent), sandbox_profile, network_guaranteed, created_files[]`.
run_tool은 실행 상태와 관측만 반환하며 가설 판정은 하지 않습니다. 출력이 상한을 넘으면 artifact 파일로 저장하고 truncated=true로 표시합니다.

### Phase 0 반영 수정
1. dedup 캐시는 `ok` 결과만(그리고 nondeterministic이 아닐 때만) 캐시합니다. error/timeout/aborted는 캐시하지 않고 항상 재실행합니다.
2. `events.jsonl`의 각 이벤트에 단조 seq를 부여하고 `state.json`에 `last_committed_seq`를 저장합니다. resume 시 그 이후의 이벤트·명령 꼬리를 잘라내어(reconcile) 크래시로 생긴 중복을 제거합니다.

## Phase 2 — Docker 격리 백엔드 (`container` 프로파일)
Phase 3(임의 파이썬 코드 실행) 전에, 강한 FS+네트워크+리소스 격리를 Docker로 확보합니다. 이미 설치된 docker CLI를 subprocess로 호출하며, docker 파이썬 SDK는 설치하지 않습니다. 이미지 자동 pull을 하지 않고 로컬에 있는 최소 이미지만 사용합니다.

- `config/sandbox.json` — container 프로파일 파라미터(이미지, 네트워크, 리소스 상한, 마운트 경로, user).
- `tools/sandbox.py` — `container` 백엔드 추가(`readonly-utils`=netns/rlimit와 함께 선택 가능). `build_container_argv`, `classify_container_status`, `container_backend_ready`.
- `tools/run_tool.py` — `sandbox_profile`로 `readonly-utils` | `container` 선택. `trust: "untrusted"` 도구는 **검증된 container 백엔드에서만** 실행 허용, 아니면 `ToolError`.
- `tools/probe.py` — docker 가용성 + 로컬 가용 이미지 탐지(`probe_container`).

사용 이미지: `python:3.12-slim-bookworm`(로컬에 이미 존재, pull 불필요).

### docker run 잠금 설정
`--network none`, `--read-only`(루트 FS 읽기전용), 작업 dir만 rw bind(출력이 호스트 jail에 남음), 입력은 `:ro` 마운트, `--user`(비root, 호스트 UID), `--cap-drop ALL`, `--security-opt no-new-privileges`, `--memory/--memory-swap/--cpus/--pids-limit/--ulimit fsize`, `--rm`, 월타임 timeout 후 `docker kill`. 명시한 작업/입력 dir 외에는 어떤 호스트 경로도 마운트하지 않습니다.

### 우회 차단 실측 (컨테이너 안에서 시도, test_sandbox_container.py)
| # | 시도 | 결과 |
|---|---|---|
| 1 | `connect(1.1.1.1:53)` / `gethostbyname` | 실패 — `--network none`, `NET_OK` 없음 |
| 2 | 호스트 전용 `.host_secret_marker`를 `/**` glob으로 탐색 | 안 보임. `/etc/passwd`는 컨테이너(Debian) 것이며 호스트 사용자명 미노출 |
| 3 | `/root_escape` 쓰기 | 거부 — read-only 루트. 작업 dir 쓰기는 허용되고 호스트에 영속 |
| 4 | 메모리 과할당 / CPU 무한루프 / fork 폭탄 | 각각 중단(aborted/OOM), 월타임 timeout, pids-limit로 fork 차단 |
| 5 | `id` | 비root (uid≠0) |
| 6 | 실행 후 `docker ps -a` | 컨테이너 없음(`--rm`) |

### 정책
- 위 1~6을 통과했으므로, 비신뢰 코드(임의 파이썬/바이너리)는 **container 프로파일에서만** 실행 허용으로 표시합니다(`trust: "untrusted"`). container 백엔드가 준비 안 된 호스트에서는 비신뢰 실행을 거부합니다.
- `readonly-utils`(netns/rlimit)는 안전 allowlist 유틸 전용으로 유지합니다.

## Phase 3 — Crypto 풀이 배관 (스크립트 드라이버, LLM 없음)
실제 Crypto 풀이 배관을 만들되, 이번 단계의 추론은 LLM이 아니라 하드코딩된 스크립트 드라이버로 결정론적으로 증명합니다(Claude 직접 풀이는 Phase 4). 모든 풀이 코드는 **container(비신뢰 프로파일, `--network none`) 안에서만** 실행하며 호스트에서 직접 실행하지 않습니다.

```
docker/Dockerfile.crypto       FROM python:3.12-slim-bookworm + pip(pycryptodome,gmpy2,sympy,z3-solver) → ctfagent-crypto:0.1
eval/datasets/dev/ch1_encoding base64(hex(base64(flag))) 다중 인코딩
eval/datasets/dev/ch2_smallrsa 작은 소수 RSA (n,e,c; sympy.factorint로 분해)
eval/scorer_keys/<id>.json     정답 플래그 — 채점기만 읽는 위치(풀이/드라이버가 접근 불가)
solver/crypto_harness.py       추론자 진입점: run_experiment/record_hypothesis/report_candidate/get_state/check_budget
solver/verifier.py             SOLVED = (채점기 일치) AND (증거체인), 채점 경로 분리
solver/scripted_driver.py      각 문제 올바른 풀이 단계를 하드코딩해 harness로 실행
```

### 이미지 빌드 (한 번)
```bash
docker build -f docker/Dockerfile.crypto -t ctfagent-crypto:0.1 .
```
base 이미지는 로컬에 있어 pull하지 않고, pip만 무료 PyPI 네트워크를 씁니다. gmpy2는 wheel 우선, 실패 시 GMP/MPFR/MPC 런타임 폴백.

#### 메모리 포렌식 (vol3) — `ctfagent-misc:0.7` (CM8, 오프라인 실작동)
```bash
docker build -f docker/Dockerfile.misc7 -t ctfagent-misc:0.7 docker/   # warm 스캔 ~10분(1회)
```
- **Windows/Mac**: ISF 심볼 팩(windows.zip 801M / mac.zip 81M)이 이미지에 사전탑재돼 있고,
  **심볼 식별자 인덱스를 빌드타임에 베이크**(`warm_vol_cache.py`, ~592s 1회)해 두므로 런타임
  첫 조회가 **캐시 히트**다. 해석기가 `/work`에 베이크 캐시를 시딩하고 `HOME=/work
  XDG_CACHE_HOME=/work`로 vol3를 돌린다 → 콜드 스캔(801M, 수 분) 없이 **실제 구조**를 뽑는다.
  (검증: 실제 512M WinXP 덤프에 `windows.pslist`가 ~4.5s에 실제 프로세스 트리 반환.)
- **Linux**: 범용 심볼 사전탑재 불가(커널별). 챌린지가 커널 심볼(vmlinux+DWARF / System.map)을
  제공하면 벤더링된 `dwarf2json` + `vol-linux-isf` 헬퍼가 **오프라인으로 ISF를 즉석 생성** 후
  `vol -s`로 해석한다. 심볼이 없으면 `strings` 폴백 + `##NEED##`(→ `needs.jsonl`, tool_gap).
- 격리 불변: 솔브는 `--network none`·ro-root·non-root·cap-drop ALL·`/work`만 rw. 빌드타임만
  네트워크 허용(캐시 베이크는 네트워크 미사용 — 번들 팩 로컬 스캔). 회귀: `tests/test_cm8_vol3_e2e.py`.

### SOLVED 판정 (verifier)
- **SOLVED**: (a) 보고된 후보 플래그가 채점기 기대값과 일치 **AND** (b) 증거체인 — 그 플래그를 실제로 출력한 **container** 실험(status ok, profile=container)이 기록돼 있음.
- **FLAG_WITHOUT_SOLUTION**: (a)만 있고 (b) 없음 — 증거 없는 추측.
- **UNVERIFIED**: 둘 다 없음.
- 채점기(`verifier._expected_flag`)만 `scorer_keys`를 읽습니다. harness/driver/풀이 코드는 읽지 않고, scorer_keys는 container에 마운트되지 않습니다(입력은 `/input` ro의 문제 파일뿐).

### 로그 (store/runs/<id>/)
Phase 0 규약 재사용: `events.jsonl`, `commands.jsonl`, 추가로 `experiments.jsonl`(stdout_ref/profile/status), `candidates.jsonl`, `state.json`. dedup과 예산 검사는 container 실행 경로에서도 동작합니다.

### 실행 격리 하드닝 (Phase 4.5)
container 안 파이썬은 **`python3 -I`(isolated)** 로 실행합니다. 스크립트가 있는 `/work`가 `sys.path`에 올라가지 않으므로, 풀이 스크립트나 챌린지 입력이 `inspect.py`/`os.py` 같은 이름이어도 stdlib를 가로채지 못합니다(Phase 4에서 발견한 import 탈취 footgun 수정). 입력은 `/input`(ro)에 마운트되며 `sys.path`에 포함되지 않습니다. 회귀 테스트: `tests/test_exec_isolation.py`.

## CM9 — 컨테스트 모드 pwn/rev/crypto 라우팅 (`orchestrator/contest_solvers.py`)

CM5(web)·CM6/7(파일분석)에 이어, 컨테스트 디스패치가 pwn/rev/crypto를 **각자의 기존
하네스**로 라우팅한다(새 솔빙 엔진 없음, 얇은 배관만). 증거/VERIFIED 규율·자동제출 금지
동일. 거버넌스 7파일·벤치(`--network none`) 불변.

- **트리아지 확장** (`contest_files.sniff`/`triage_dir`): 암호 아티팩트(PEM 매직·`.pem/.sage/.key`
  확장자·`params.json`/cipher·RSA 마커) → `crypto`; 바이너리(ELF/PE) → `rev`(툴 라벨 `angr`,
  `strings`는 하네스 내부 최후 폴백일 뿐 라우팅 아님). 큰 더미 파일이 섞여도 암호 신호가
  '가장 큰 파일' 휴리스틱을 이긴다.
- **rev** → `RevHarness`(`ctfagent-rev:0.2`)의 **angr 심볼릭 실행**: 프로그램 stdout에 플래그가
  실린 도달가능 상태를 탐색. 바이너리에 리터럴 플래그 문자열이 없어도(즉 `strings` 미검출)
  실제로 푼다. 증거=하네스 실행출력(SRC_EXEC).
- **crypto** → `CryptoHarness`(`ctfagent-crypto:0.1`)의 **sympy 소인수분해** 경로로 교과서 RSA 해독.
- **pwn(원격)** → `solver/session.py` 튜브를 **CM2 EgressBroker 경유**로 타깃에 연결(`broker=`
  핸드셰이크, pwntools 없는 호스트에서도 동작하는 소켓 튜브). **무기화하지 않는 상호작용만**
  수행 — 서비스가 자발적으로 흘리는 플래그는 증거(SRC_TARGET) 기반 solve. 플래그가 버그 뒤에
  있으면 익스 개발이 **[cyber] 게이트**: `cyber_gate.jsonl`에 `logged_not_bypassed`로 기록하고
  **우회하지 않음** → StopLoss가 정직하게 STOP. 브로커가 egress를 거부하면 `BrokerRefused` 역시
  같은 게이트로 기록된다.
- **pwn(로컬 바이너리)** → `PwnHarness`(`ctfagent-pwn`, `--network none`) 격리 경로에서 벤인
  상호작용만. 동일한 [cyber] 게이트 적용.

디스패치: 네트워크 챌린지는 `contest_run.DEFAULT_REGISTRY`(web/pwn), 파일 아티팩트는
`FILE_SOLVERS`(rev/crypto/pwn)로 분기하고 그 외 패밀리는 CM6/7 분석기(`file_solver`) 유지.
회귀: `tests/test_cm9_category_solvers.py`(트리아지·라우팅·[cyber]게이트는 docker 없이, 세 실솔브
e2e는 이미지 있을 때).

## 실행
```bash
cd ~/ctf_agent_v3
python3 -m unittest discover -s tests -v   # container/pwn/rev/crypto e2e는 docker·이미지 미가용 시 자동 skip

# 격리/도구/컨테이너 probe 결과 직접 확인
python3 -m tools.probe
```

코드에서 직접 사용할 때:
```python
from orchestrator.supervisor import Supervisor
sup = Supervisor("run-001").start([challenge_dict, ...])   # challenge_dict["scenario"]는 mock 솔버 입력
sup.run(stop_after_steps=3)                              # "interrupted"
Supervisor.resume("run-001").run()                       # "completed" | "aborted"
```
