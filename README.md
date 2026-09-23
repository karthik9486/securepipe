# SecurePipe — DevSecOps for student project pipelines

Automated security gate for student GitHub repos. Every push runs secret,
dependency, and static-analysis scans, and produces a security scorecard
faculty can review before evaluating the project.

## How it works

1. Student pushes code / opens a PR.
2. GitHub Actions (`.github/workflows/security-scan.yml`) runs:
   - **Gitleaks** — hardcoded secrets
   - **Trivy** — vulnerable dependencies
   - **Semgrep** — static code analysis (SQLi, eval, XSS, etc.)
3. `scripts/generate_scorecard.py` merges all three reports into one
   weighted security score (0-100, grade A-F) and a static HTML dashboard.
4. Faculty view `dashboard.html` (or `scorecard.json` for automation)
   before evaluating the submission.

## Quick local test (no need to wait for CI)

```bash
cd securepipe
pip install -r scripts/requirements.txt

# Run the scanners yourself against the sample vulnerable repo, e.g.:
cd sample-vulnerable-repo
pip install semgrep
semgrep --config=auto --json --output=../semgrep-report.json .
cd ..

# (Optional) run gitleaks / trivy locally if installed, or skip —
# generate_scorecard.py tolerates missing report files.

python scripts/generate_scorecard.py
open dashboard.html   # or just open the file in a browser
```

Running it against `sample-vulnerable-repo/` should surface the three
planted issues (hardcoded credential, SQL injection pattern, `eval()`
usage, outdated Flask/requests versions) and produce a low score/grade.
Running it against a clean repo should produce a 100/A "clean" scorecard —
useful for the live demo contrast.

## Suggested team split (2-day build)

| Role | Owns |
|---|---|
| CI/pipeline engineer | `.github/workflows/security-scan.yml` — get all three scanners running end-to-end |
| Backend/scoring engineer | `scripts/generate_scorecard.py` — tune severity weights, parsing edge cases |
| Dashboard/frontend engineer | `dashboard.html` styling/layout, maybe a trend view if time allows |
| Demo lead + integration | Prep `sample-vulnerable-repo` (clean vs. vulnerable versions), rehearse the 5-min demo + Q&A |

## Ideas if you have extra time

- Turn the commented-out `enforce_gate.py` step in the workflow into a
  real merge-blocking gate (fail the build below a score threshold).
- Publish `dashboard.html` to GitHub Pages per-repo so faculty get a
  shareable link instead of downloading an artifact.
- Add a trend line if scorecards are stored across multiple pushes
  (e.g. commit scorecard.json to a `security-history/` branch).
- Extend severity weighting to reflect your institution's specific
  rubric (e.g. heavier penalty for exposed DB credentials).

## Institutional impact talking points (for Q&A)

- Removes reliance on manual security review, which doesn't scale across
  hundreds of student submissions per semester.
- Gives students immediate, specific feedback (file + line number) instead
  of a grade deduction after the fact — turns evaluation into a teaching
  moment.
- Reusable across any course that uses GitHub for submissions, not just
  security-focused courses.
- Extensible to DevSecOps training pipelines for internship/placement
  prep, given industry expectations around secure coding practices.
