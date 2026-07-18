# Running the evaluation demo

This is the **how-to-run** guide for the evaluation demo (epic [#142](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/142)). For *what the demo is and why it's shaped this way*, read the PRD: [`docs/evaluation-demo.md`](../docs/evaluation-demo.md).

The demo is a single [marimo](https://marimo.io) notebook ([`notebooks/publish_demo.py`](notebooks/publish_demo.py)) that drives the **live `compose.publish.yaml` stack over real HTTP — nothing mocked**. It tells one continuous story about one team of three co-owners:

- **Act 0 — the admin's chair.** An admin stands up a 3-of-3 publishing service and the co-owners come to life (real encrypted DB rows).
- **Act 1 — the happy path.** The team publishes `acme-widgets 1.0.0`: real twine upload → approval emails in Mailpit → re-authenticated, Ed25519-signed votes → quorum → real publish → `pip install` succeeds.
- **Act 2 — the compromise.** A stolen co-owner *seat* (not their mailbox) submits a malicious `1.0.1` and self-approves; a careless teammate rubber-stamps; the request **freezes at 2/3**. A diligent co-owner verifies out-of-band by real email and **denies**. `1.0.1` never reaches the index.

## What's in the stack

`docker compose -f compose.publish.yaml up` brings up four containers ([`compose.base.yaml`](../compose.base.yaml) + [`compose.publish.yaml`](../compose.publish.yaml)):

| Service | URL | Role |
|---|---|---|
| **marimo** | http://localhost:2718 | the demo notebook (this is what you record) |
| **proxy** | http://localhost:8080 | the MPA proxy under test |
| **mailpit** | http://localhost:8025 | real inbox — approval emails + the human email thread |
| **pypiserver** | http://localhost:8081 | local PyPI stand-in — the publish target **and** the demo's oracle |

Everything is throwaway and demo-only. The publish endpoint points at the local pypiserver, so **a publish never touches real PyPI**; SMTP points at Mailpit.

## Prerequisites

- **Docker + Docker Compose** — the only requirement to *run the demo*.
- [`uv`](https://docs.astral.sh/uv/) — only if you also want to run the backing tests (see below).

## One-time setup

From the repo root, seed the git-ignored runtime files from the checked-in examples/seed:

```sh
# 1. The demo's 3-of-3 service config (hardcoded demo secret_key + local pypiserver endpoint)
cp demo/seed/config.demo.yaml   config/config.yaml

# 2. The born-enrolled co-owner bundle (throwaway, demo-only credentials — never real keys)
cp demo/seed/users.demo.yaml    config/users.yaml

# 3. An .env must EXIST (the proxy service declares `env_file: .env`). The demo config
#    hardcodes its own values, so the contents don't matter here — an empty copy is fine.
cp .env.example .env

# 4. The proxy's writable SQLite volume (shared with the marimo container)
mkdir -p data
```

Notes:
- `config/config.yaml`, `config/users.yaml`, and `.env` are **git-ignored** — copying them is expected, you won't be committing them.
- `config/users.yaml` is optional: Act 0 provisions the team into the shared DB from the notebook (`demo_lib.provision_demo_team`), so you can start from an empty users file and let Act 0 do the work. Copying the seed bundle just gives you a known-good starting state.
- The seed credentials are **throwaway and non-reversible** (bcrypt hash + AES-GCM-wrapped signing key and TOTP secret). The one planted "secret" is the demo password in `demo_lib.DEMO_TEAM`, on purpose, so Act 2's simulated compromise is reproducible. Never reuse any of this anywhere real.

## Bring it up

```sh
docker compose -f compose.publish.yaml up --build   # add -d to detach
```

`--build` is needed on the first run (and whenever you change the proxy source): the `proxy` image is **built locally** from [`Dockerfile`](../Dockerfile) and exists in no registry, so any attempt to *pull* it fails. The other three services are public images and pull normally.

Then open the notebook at **http://localhost:2718** and walk the acts top to bottom, pressing each button in order. Keep the **Mailpit inbox (http://localhost:8025)** and the **pypiserver index (http://localhost:8081/simple/acme-widgets/)** open in side tabs — they're the live oracles the story points at.

### `run` mode vs `edit` mode

The compose file launches marimo in **`run` mode** — the clean, button-driven web app, the default for recording (Demo Requirement 2). To get the **code-visible view** that proves the HTTP/DB calls are real (Demo Requirement 3), edit the `marimo` service `command` in [`compose.publish.yaml`](../compose.publish.yaml) and swap `run` → `edit`, then bring the stack up again.

## Driving the demo

Each act is a short column of buttons. Pressing one performs a **real** HTTP call against the proxy and advances the Maltego-style board (nodes light up, the live hash / `2/3` tally / `DENIED` verdict paint on). The presenter runs one co-owner on camera; the notebook self-drives the rest (show one, automate the rest). The full beat list is in the PRD's User Stories.

Bookends you can verify yourself while recording:
- **Act 1 end:** `pip install --index-url http://localhost:8081/simple/ acme-widgets==1.0.0` succeeds.
- **Act 2 end:** the same install for `acme-widgets==1.0.1` fails ("No matching distribution found") — it was denied, so it never reached the index.

## Reset between takes

The notebook has a **reset-demo** button/cell that clears the demo's DB rows and drops the package from pypiserver, so you can re-run in seconds **without** tearing down containers. TOTP codes are computed live (`current_totp_at(offset)`), so single-use TOTP ([#73](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/73)) doesn't break re-runs.

For a full cold start (fresh DB and index):

```sh
docker compose -f compose.publish.yaml down -v      # -v drops the volumes
```

## The backing tests (the reproducible twin)

The demo is the *legible* artifact; the pytest suite is its *reproducible / worst-case-rigorous* twin. The flow logic the notebook runs lives in plain, tested modules — [`notebooks/demo_flow.py`](notebooks/demo_flow.py) (drives the proxy) and [`notebooks/demo_lib.py`](notebooks/demo_lib.py) (cast + board) — exercised end to end over the **same code the notebook runs**, against the proxy served by uvicorn on a localhost port. A real socket rather than an in-process app, because the upload is driven by **real `twine`** in a subprocess, exactly as on camera:

```sh
uv run pytest tests/demo                                        # Acts 0/1/2 backing checks + board
uv run pytest tests/service_types/one_time/test_compromise_boundary.py   # the t = m-1 worst case
```

Every capability shown on the board traces to one of these tests via the notebook's capability checklist (Demo Requirement 29), which reads [`docs/evaluation-capabilities.yaml`](../docs/evaluation-capabilities.yaml) — the same catalog the report and CI read.

## Troubleshooting

- **`pull access denied for msig-proxy ... repository does not exist or may require 'docker login'`** — the `proxy` image is built locally, not pulled. Bring the stack up with `--build` (`docker compose -f compose.publish.yaml up --build`), and don't run a separate `docker compose pull` (it can't pull a build-only image).
- **`env file .env not found`** — you skipped step 3 of setup; `cp .env.example .env`.
- **Ports already in use** (2718 / 8080 / 8025 / 8081) — stop whatever else is bound, or remap the left-hand side of the `ports:` entries in the compose files.
- **Notebook can't reach the proxy / Mailpit / pypiserver** — inside the compose network the notebook resolves the other containers by **service name** (`proxy:8080`, `mailpit:8025`, `pypiserver:8080`); this is the default. Only set the `MSIG_DEMO_*_URL` env vars (see `demo_flow.DemoStack.from_env`) if you're running the notebook outside compose.
- **Act 1/2 buttons error on a re-run** — press **reset demo** first; a leftover request or published package from the previous take can collide.
