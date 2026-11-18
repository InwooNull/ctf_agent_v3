# ctf_agent_v3

**Jeopardy CTF를 격리 샌드박스 안에서 자동으로 풀어내는 자율 에이전트.**
web · pwn · rev · crypto · misc·forensics · AI — 파일·URL·CTFd 주소를 넣으면 종류를 판별하고, **실제로 플래그를 출력했을 때만** 후보로 보고합니다(추측 금지).

[설치](#설치) · [사용](#사용) · [저장소 범위](#저장소-범위) · [핵심 설계](#핵심-설계) · [ARCHITECTURE](ARCHITECTURE.md) · [RESULTS](RESULTS.md) · [CLAUDE.md](CLAUDE.md)

```
입력:  challenge.bin  │  https://ctf.site  │  CTFd 주소
  └─▶ 판별 → 트리아지/라우팅 → 샌드박스 하네스(도구 실험) → 증거 검증 → 후보 플래그
```

**두 가지 풀이 엔진**
- **`ctf-solve` 에이전트 (기본 엔진)** — 세션이 오케스트레이터가 되어 문제마다 실제 솔버 서브에이전트를 띄우고, 같은 프레임워크(하네스·skill_pack·검증기)를 돌려 푸는 세션-오케스트레이션 멀티에이전트 방식. `.claude/skills/ctf-solve/`
- **`solve.py` (관리형 진입점)** — 입력을 자동 판별해 파이프라인을 결정론적으로 구동. 수집·플랜·스크립트 베이스라인.

---

## 설치

도구는 **호스트(pip)** 와 **샌드박스 이미지(docker)** 두 군데에 나뉩니다. `pip` 하나로는 솔버 도구가 깔리지 않습니다.

```bash
# 1) 호스트 의존성 — requests · flask · numpy 뿐 (오케스트레이터는 stdlib 중심)
pip install -r requirements.txt            # python 3.12 권장

# 2) 솔버 도구 이미지 — 쓰는 카테고리만 한 번 빌드
docker build -f docker/Dockerfile.crypto -t ctfagent-crypto:0.1 .
docker build -f docker/Dockerfile.rev    -t ctfagent-rev:0.1    .
docker build -f docker/Dockerfile.pwn    -t ctfagent-pwn:0.1    .
docker build -f docker/Dockerfile.web    -t ctfagent-web:0.1    .
docker build -f docker/Dockerfile.misc   -t ctfagent-misc:0.1   .
```

| 카테고리 | 기본 이미지 | 대표 도구 |
|---|---|---|
| crypto | `ctfagent-crypto:0.1` | sympy, pycryptodome, gmpy2, z3-solver |
| rev | `ctfagent-rev:0.1` | angr, unicorn, capstone |
| pwn | `ctfagent-pwn:0.1` | pwntools |
| web | `ctfagent-web:0.1` | sqlmap (`web:0.3` = + ffuf·playwright/chromium) |
| misc | `ctfagent-misc:0.1` | volatility3, pillow (finals = + sleuthkit·john·zbar·tesseract·stegseek) |

도구가 더 필요한 web·misc는 finals 이미지도 빌드합니다(하네스가 `image=`로 선택):
`docker build -f docker/Dockerfile.web3 -t ctfagent-web:0.3 .`,
`docker build -f docker/Dockerfile.misc7 -t ctfagent-misc:0.7 docker/`.
docker가 없으면 비신뢰 코드 실행이 거부되므로(안전장치), crypto/rev/pwn/misc 풀이에는 docker가 사실상 필수입니다.

---

## 사용
```bash
python3 -m tools.probe                              # 격리·도구 가용성 점검
python3 solve.py <파일 | 디렉터리 | URL | CTFd주소>  [--bench] [--ctfd] [--run]
python3 -m unittest discover -s tests -v            # 테스트 (docker 미가용 e2e는 자동 skip)
```
CTFd 대회에 붙일 때만 접속 정보를 설정합니다(`.gitignore`됨 — 절대 커밋 금지):
```bash
cp config/acdc.env.example config/acdc.env          # 값만 채운 뒤
python3 solve.py <CTFd주소> --ctfd
```

---

## 저장소 범위
**소스·설계 전용 스냅샷**입니다. 프레임워크·설계는 그대로 재현되지만, 측정 데이터는 비공개라
[RESULTS.md](RESULTS.md)의 수치는 똑같이 재현되지 않습니다(벤치 오염·보안 방지를 위한 의도).

| 들어있음 | 빠져있음 |
|---|---|
| 파이프라인·오케스트레이터 코드, 하네스·스킬 팩 `skills/`, docker 빌드 `docker/`, 테스트 `tests/` | 정답 볼트 `vault/`, 스코어러 키 `eval/scorer_keys/`, dev 데이터셋 `eval/datasets/`, 실행 이력 `store/`, 시크릿 `config/*.env` |

---

## 핵심 설계
- **안전 격리 실행** — 모든 도구/실험은 샌드박스(stdlib+`unshare` netns·rlimit, 또는 docker)에서
  실행하고, 네트워크 차단·CPU/메모리/파일크기 상한·월타임 타임아웃·셸 주입 차단을 강제합니다.
  보장 불가 호스트에서는 `network_guaranteed=False`로 **정직하게 표시**하고 비신뢰 실행을 막습니다.
- **증거 기반 검증** — 플래그는 추측·패턴매칭으로 보고하지 않습니다. "매칭 후보 + 실제로 실행되어
  플래그를 출력한 컨테이너 실험"이 둘 다 있어야 SOLVED입니다(`solver/verifier.py`).
- **`[cyber]` 게이트** — 익스플로잇 무기화가 필요한 지점은 우회하지 않고 `cyber_gate.jsonl`에
  `logged_not_bypassed`로 기록한 뒤 StopLoss가 정직하게 멈춥니다.
- **경험/growth 루프** — 성공·실패를 경험 저장소에 축적해 재시도 비용을 줄입니다
  (측정 예: AI 가드레일 카테고리에서 평균 시도 6.5→1.83, [RESULTS.md](RESULTS.md)).
- **2가지 모드** — `contest`(기본, 실대회: 타깃 네트워크 허용, 서버/플래그포맷으로 검증) /
  `--bench`(블라인드 정직측정: `--network none` + 봉인 볼트·스코어러 키).

## 더 읽을 거리
- **[`ARCHITECTURE.md`](ARCHITECTURE.md)** — 전체 구조·동작·도구·스킬 총정리 (다이어그램 포함)
- **[`CLAUDE.md`](CLAUDE.md)** — 운영 규칙 (ctf-solve 기본 엔진 · contest/bench 모드 · governance 불변식)
- **[`RESULTS.md`](RESULTS.md)** — 측정 결과 요약
- **[`docs/`](docs/)** — 카테고리·정책 설계
- **[`docs/INTERNALS.md`](docs/INTERNALS.md)** — clean-room 빌드 로그 · 데이터 계약 (Phase 0~CM9)
