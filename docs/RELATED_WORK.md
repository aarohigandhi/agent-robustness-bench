# Related work and positioning

Survey conducted 2026-08-12. Its purpose is to decide what this project should claim,
and it changed that answer substantially.

**Summary: both differentiators this project was founded on are now occupied.** The
persistence angle was published on repeatedly between May and July 2026, including the
defense side. The honest positioning is narrower than originally planned, and is set out
in [What is actually left](#what-is-actually-left).

Sources marked ✅ were read directly. Sources marked ◻ come from search summaries and
still need to be read before anything is cited in a writeup.

---

## 1. General indirect prompt injection benchmarks

| Work | What it is | Relevance |
|---|---|---|
| ◻ [AgentDojo](https://openreview.net/pdf?id=m1YYAQjO3w) | 97 tasks, 629 security test cases, 4 scenarios (workspace, Slack, travel, banking). Dynamic environment with attack and defense paradigms | **The standard.** Described in the 2026 survey below as "the primary benchmark for evaluating injection defenses" |
| ◻ [InjecAgent](https://arxiv.org/pdf/2403.02691) | 1,054 cases, 17 user tools, 62 attacker tools. ReAct GPT-4 vulnerable ~24% | Single-step, ≤3 visible tools per task |
| ◻ [Agent Security Bench](https://arxiv.org/pdf/2410.02644) | Formalizes attacks and defenses across agent components | Single-step, like InjecAgent |
| ◻ [AgentDyn](https://arxiv.org/html/2602.03117v1) | Dynamic open-ended benchmark | 2026, not yet reviewed |

AgentDojo's trajectories are substantially longer than InjecAgent's (avg ~3,823 vs ~1,033
tokens), which is the main axis on which these differ.

**Implication for this repo.** The general-purpose IPI benchmark space is saturated and
well-executed. There is no reason to compete here, and the current 5 scenarios are not a
contribution — they are a harness demonstration.

---

## 2. Persistence and memory poisoning — the lane that closed

This project was scoped on the premise that "nearly all existing work is single-turn."
**That premise was true when the plan was written and is no longer true.**

| Work | Date | What it does |
|---|---|---|
| ✅ [MemSecBench](https://arxiv.org/abs/2607.27080) | Jul 2026 | 310 cases, 48 contexts, 24 configurations. Write–Execute–Forget lifecycle protocol, 7 checkpoints |
| ◻ [MemPoison](https://arxiv.org/html/2607.14651v1) | Jul 2026 | 1,227 hand-validated cases, 4 attack vectors, 3 injection channels, 3 memory architectures |
| ◻ [MPBench / Bad Memory](https://arxiv.org/html/2607.14611) | Jul 2026 | Write-phase and retrieval-phase evaluation of memory poisoning |
| ◻ [Plant, Persist, Trigger](https://arxiv.org/pdf/2605.28201) | May 2026 | Sleeper attacks on LLM agents |
| ◻ [Hidden in Memory](https://arxiv.org/pdf/2605.15338) | May 2026 | Sleeper memory poisoning |
| ◻ [Cross-Session Threats in AI Agents](https://arxiv.org/pdf/2604.21131) | Apr 2026 | Benchmark, evaluation, algorithms |
| ◻ [From Untrusted Input to Trusted Memory](https://arxiv.org/pdf/2606.04329) | Jun 2026 | Systematic study of memory poisoning |
| ◻ [An Empirical Study of Memory Poisoning Defenses](https://icml.cc/virtual/2026/poster/61006) | ICML 2026 | Defense-side comparison |

### The metric collision

MemSecBench's lifecycle metrics are, term for term, the ones this repo independently
implemented:

| This repo | MemSecBench | Their reported average |
|---|---|---|
| plant rate | **MPSR** — Memory Poisoning Success Rate | 84.2% |
| (not measured) | **MESR** — Memory Exploitation Success Rate | 53.7% |
| latent ASR | **E2E-ASR** — end-to-end write-then-execute | 50.3% |
| (not measured) | **SRSR** — Selective Repair Success Rate | 56.1% |

Convergent design is a reasonable signal that the framing was right. It is not a
contribution, and **the README must not claim it as one.**

---

## 3. Defenses, and the result that undermines static benchmarks

✅ [Zylos, *Indirect Prompt Injection: Attacks, Defenses, and the 2026 State of the
Art*](https://zylos.ai/research/2026-04-12-indirect-prompt-injection-defenses-agents-untrusted-content/)

Reported head-to-head numbers, all on AgentDojo:

| Defense | Result |
|---|---|
| Undefended baseline | 84% task success |
| CaMeL (dual-LLM privilege separation) | 77% task success with security guarantees — 7pt utility cost |
| MELON (masked re-execution) | 0.32% ASR at 68.72% utility — "best trade-off in the literature" |
| LlamaFirewall stack | 17.6% → 1.75% ASR |

Architectural controls (capability scoping, dual-LLM, information-flow control) are
reported as materially stronger than model-level or prompt-level mitigations. The survey's
own conclusion is that prompt injection "cannot be fully solved within current LLM
architectures."

### The Attacker Moves Second

◻ [Nasr et al., USENIX Security 2026](https://arxiv.org/abs/2510.09023) — authors from
OpenAI, Anthropic, and Google DeepMind. **12 defenses spanning prompting, adversarial
training, filtering, and secret-knowledge mechanisms were all bypassed at >90% ASR** by
adaptive attacks using gradient descent, RL, random search, and human red-teaming. Human
red-teaming reached 100%. Most of those defenses had reported near-zero ASR in their
original evaluations.

**This is the most important paper for this project, and it cuts against its design.**

This benchmark's core scoping rule — *payloads are fixed, defenses are the variable* —
is an ethics rule, and it is the right one. But it means every number produced here is
**static-payload robustness**, and Nasr et al. is direct evidence that static-payload
rankings do not survive adaptive attack. A defense scoring 0% here should be assumed to
be breakable by a motivated attacker.

The correct response is not to start optimizing payloads. It is to **state this
limitation prominently and stop making claims the methodology cannot support.** See
[Limitations](../README.md#limitations).

---

## 4. What is actually left

Explicit open problems named by the newest work in the field:

1. **Selective repair is the bottleneck.** MemSecBench measures 86.3% removal of
   malicious memory but only 56.1% *selective* repair — a **30.2 point gap**, which is
   benign memories being destroyed along with the payload. They name benign-memory
   preservation as "the primary bottleneck."

2. **No memory defense achieves both high TPR and low FPR off-the-shelf.** MPBench's best
   performer (PromptArmor) reaches 67.67% TPR at 1.00% FPR; the study reports that no
   off-the-shelf defense manages both. ◻ needs verification.

3. **Memory poisoning defenses are nascent**; storage-layer scanning lacks
   standardization (Zylos, ✅).

4. **The adoption checkpoint** — the boundary between stored malicious semantics and
   harmful behavior — is named by MemSecBench as meriting deeper investigation.

### The proposed lane

Every item above is about the same thing: **the false-positive and utility cost of memory
defenses.** The attack side is thoroughly measured. The defense side reports ASR
reduction. What is under-measured is what those defenses destroy in the process.

That is a good fit for this repository for three reasons:

- **It is already the design center.** This harness was built so that ASR is never
  reported without TCR. That principle is exactly what the open problem needs.
- **It is defensive.** It requires no attack development and no payload optimization, so
  it stays inside the scoping rule.
- **It survives the Attacker Moves Second critique.** Measuring how much legitimate
  behavior a defense breaks does not depend on the attack being strong — a defense's
  false-positive rate is a property of the defense, not of the adversary.

Concretely: add benign memories and benign-but-superficially-suspicious content to the
environment, then measure what each defense wrongly destroys or blocks. The current
`taint_tracking` defense should score badly on this by construction — it vetoes any
sensitive call containing a 6-gram from untrusted data, which will catch a great deal of
legitimate work.

**This is a strategic decision, not a technical one, and it has not been made yet.**

---

## Reading queue

Before any of the above is cited in a writeup, read in this order:

1. `The Attacker Moves Second` (2510.09023) — sets the honest ceiling on all claims here
2. `MemSecBench` (2607.27080) — closest neighbour; read the SRSR methodology carefully
3. `AgentDojo` (OpenReview m1YYAQjO3w) — the standard to position against
4. `An Empirical Study of Memory Poisoning Defenses` (ICML 2026) — check whether the
   false-positive lane is already taken
5. `MPBench` (2607.14611) — verify the TPR/FPR claim above
