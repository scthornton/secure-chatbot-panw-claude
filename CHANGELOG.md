# Changelog

## [Unreleased]

### Added
- Response-side scanning: every Claude reply is sent back to Prisma AIRS
  (prompt + response) and withheld on a block verdict. The README promised
  this; the code only scanned prompts.
- `PANW_AI_SEC_ENDPOINT` is now honored, so EU, India, and Singapore keys
  work. The variable was already in `.env.example` but the code ignored it.
- Scan metadata (`app_name`, `app_user`, `ai_model`) on every request, with
  `PANW_AI_SEC_APP_NAME` / `PANW_AI_SEC_APP_USER` overrides.
- MIT `LICENSE` file.

### Changed
- Default model bumped to `claude-sonnet-5-5`; override with `ANTHROPIC_MODEL`.
- Claude text is assembled from all `text` content blocks instead of assuming
  `content[0]` is text.
- `.env` loading uses python-dotenv. Real environment variables now win over
  `.env` values (the hand-rolled loader overwrote them and did not strip
  quotes).
- `setup.py` renamed to `setup_script.py` so pip does not mistake the repo
  for an installable package. Python floor in the setup check raised to 3.10
  to match `requirements.txt`.
- HTTP calls to the scan API now carry a 30 second timeout.
- SDK variant maps scan-API errors correctly: 401 is an auth failure, 400 is a
  bad request (usually a wrong profile name), 429 and 5xx retry with backoff.
  The old code reported 404 as "profile not found", which AIRS never returns.
- Comments and README no longer claim that AIRS "predicts" the model's
  response. `response_detected` is populated only when a response is sent.
- `requirements.txt` trimmed to what the code imports (dropped unused
  `httpx`, `pydantic`, `asyncio-throttle`, `urllib3` pins).
- README: removed the nonexistent `MONITORING_GUIDE.md`, the retired
  claude-3 model list, and the wrong 403/404 troubleshooting codes.

### Fixed
- `messages.create(temperature=0.7)` raises `TypeError` on the current
  `anthropic` SDK (2.x removed the parameter), so no reply was ever produced.
  The argument is gone; the SDK default applies.
- Leftover Perplexity references in code comments, `DEPLOYMENT_GUIDE.md`,
  `CUSTOMER_PACKAGE.md`, and this changelog (which still described the
  Perplexity repo this one was cloned from).

## [1.0.0]

### Added
- Secure Python chatbot with PANW AIRS protection
- Anthropic Claude API integration
- Deployment guide and customer package

[Unreleased]: https://github.com/scthornton/secure-chatbot-panw-claude/commits/main
