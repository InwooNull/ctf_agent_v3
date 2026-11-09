# RESULTS — 측정 요약

> **정직성 원칙.** 아래는 개발·growth 단계에서 **실제로 측정된** 내부 결과입니다. 공개
> 리더보드 점수가 아니라, 블라인드 dev 세트/합성·실(NYU CTF Bench 계열) 문제에 대한 A/B·
> 전환(conversion) 측정입니다. 실행 산출물 원본(`store/`)·벤치 데이터(`arena/`)·정답 볼트
> (`vault/`)는 공개 저장소에서 제외했습니다. 수치는 재현 조건(이미지·예산)과 함께 적습니다.
> SOLVED 기준은 `solver/verifier.py`와 동일합니다: **매칭 후보 + 실제 실행되어 플래그를
> 출력한 컨테이너 실험**이 둘 다 있어야 합니다(추측·패턴매칭 보고 금지).

## 1. 경험/growth 효과 — AI 가드레일 카테고리 (Phase 27)

경험 저장소(retention/supersede)를 끈 설정(C0)과 켠 설정(C2)을 **동일 6문제 페어링**으로 비교.

| 설정 | 해결 | 평균 시도수 | 시도 분포 |
|---|---|---|---|
| C0 (경험 off) | 6 / 6 | 6.50 | [5,6,6,7,7,8] |
| C2 (경험 on)  | 6 / 6 | **1.83** | [1,1,1,2,2,4] |

- **시도수 평균 −4.67** (경험이 기여한 가드 6/6). 정답률은 양쪽 100%지만 경험이 **비용을 크게 절감**.
- 무결성 체크 전부 0: forced-win-stub 0 · subagent 직접제출 0 · live 접근 0 · 부정 읽기 0.

## 2. Reverse — 라우터팩 + angr 도입 A/B (Phase 40 / 41)

router pack 없이·angr 없이(C0) vs reverse 라우터팩 + angr 10.0.5(C1)를, 이전 단계에서
rev로 실패했던 문제들에 대해 **paired 전환** 측정 (image `rev:0.2`).

- P40: 예산 12 experiments / 1800s / exp 240s / 2g
- P41(공정 재측정: `/work` 영속화 + 예산 상향): 20 exp / 3000s / exp 300s / 2g
- 측정 대상 예: `halfpike`(Intel-4004 에뮬레이터, 2019q) 등 — C0는 분석/도구부족으로 FAILED,
  C1에서 심볼릭 실행 경로로 전환 가능성 측정. (문제별 전환표는 내부 `store/p4x_rev/report.json`)

> 이 단계의 핵심은 "성공률 1개 숫자"가 아니라 **어떤 도구/라우팅이 어떤 실패를 전환시키는지**를
> paired로 분리 측정한 것입니다.

## 3. Misc / Forensics — 블라인드 dev 배치 (Phase 51, image `misc:0.5`)

예산 12 exp / 1200s / exp 90s, K=1, 블라인드 dev 11문제.

| 카테고리 | n | 해결 |
|---|---|---|
| forensics | 9 | 3 |
| misc | 2 | 2 |
| **합계** | **11** | **5 (45%)** |

- 실패 6건의 진단 분포: 접근(approach) 3 · 예산(budget) 1 · 도구부족(tool_gap) 2 — **다음
  사이클의 개선 타깃을 자동 분류**(growth diagnoser).
- forced-win-stub 0.

## 4. 홀드아웃 게이트 — 정직한 음성 (Phase 53)

cap20 예산에서 홀드아웃 misc 문제(`mr_8c08a5`, `mr_a5950f`)는 K=2 반복에도 **UNVERIFIED /
solved=false**. 검증기가 증거 없는 solve를 거부한 사례로, **실패를 실패로 기록**합니다.

---

## 재현 메모
- 위 수치는 특정 docker 하네스 이미지·예산에서 측정됐습니다(각 절 명시). 이미지·벤치 데이터는
  공개 범위 밖이라, 외부에서 **동일 수치 재현은 불가**하고 코드·방법론·측정 설계만 공개됩니다.
- 측정 원본 스키마: `store/<phase>/report.json`, `store/contest/<run>/writeup_log.jsonl`,
  `store/experience_*.jsonl` (저장소에는 미포함).

## TODO (평가자용으로 채우면 좋은 것)
- [ ] 공개 벤치(예: NYU CTF Bench) 서브셋에 대한 **end-to-end 성공률 표** 1장
- [ ] 플래그를 가린 **샘플 실행 트랜스크립트** 1~2개 (`store/contest/.../writeup_log.jsonl` 발췌)
- [ ] 카테고리별 평균 소요 experiments·wall-time
