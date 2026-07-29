# SentinelFlow Loghub test excerpts

These three small files are controlled Week 9-10 test inputs for the LD7237
SentinelFlow supervised university prototype. They are excerpts from the
LogPAI Loghub Linux and OpenSSH datasets.

## Source and permission

- Repository: https://github.com/logpai/loghub
- Licence notice: https://github.com/logpai/loghub/blob/master/LICENSE
- Permitted use stated by Loghub: research or academic work, with repository
  attribution, the Loghub paper citation where applicable, and inclusion of
  the Loghub licence notice with copies.
- Citation: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, and Michael R.
  Lyu. "Loghub: A Large Collection of System Log Datasets for AI-driven Log
  Analytics." ISSRE, 2023.

## Preparation

The selected source lines were excerpted with their visible log content
unchanged. Surrounding records were removed, the original order was preserved,
CRLF line endings were normalised to LF, trailing whitespace was removed, and
no ground-truth label was inserted into the log files. Exact source files and
line numbers are recorded in `source_manifest.json`.

The excerpts are used only as approved academic test evidence. They must not be
treated as current operational intelligence or submitted to unrelated public
services.

## Test intent

- `SF-REAL-001`: narrow session-open/session-close sequence for the SIMPLE path.
- `SF-REAL-002`: correlated repeated authentication failures for the COMPLEX
  path.
- `SF-REAL-003`: ambiguous "possible break-in" evidence for the HUMAN_REVIEW
  safety path.

The expected result is not a claim that Loghub supplied case-level labels for
these excerpts. The expectations are SentinelFlow test hypotheses that must be
compared with the actual route, decision, evidence coverage, ledger result,
Supervisor result and final report outcome.
