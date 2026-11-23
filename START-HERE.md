# Start here

New to the repo? Read the [README](README.md). It says what Clockchain is, how
to run it and where everything lives.

Then, by what you want to do:

- Run it on your machine: [docs/LOCAL-DEV.md](docs/LOCAL-DEV.md).
- Understand how it fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), then [docs/TOPOLOGY.md](docs/TOPOLOGY.md).
- Read the data: [docs/PUBLIC-ACCESS.md](docs/PUBLIC-ACCESS.md) and the HTTP routes in [docs/reference/openapi.json](docs/reference/openapi.json).
- Change code: [CONTRIBUTING.md](CONTRIBUTING.md).
- Find a doc: [docs/README.md](docs/README.md) sorts every doc into start here, reference, operations and historical.

## Rules that apply to everyone

- [AGENTS.md](AGENTS.md) has the current working instructions, for people and agents.
- [HOLD.md](HOLD.md) lists the standing owner constraints. Read it before any release, publication, generation or fixture work.
- Work starts from the owner's explicit scope. Production data, credentials and private research are not in this repo.
- Security reports: [SECURITY.md](SECURITY.md).

## Continuing an owner session

Agents continuing an owner session follow [docs/SESSION-HANDOFF.md](docs/SESSION-HANDOFF.md). The owner's private handoff files are outside this checkout. Cloud sessions do not have them; their scope comes from the owner's prompt and the current stage contract.
