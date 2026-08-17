# Facts CLI

A simple, adaptable substrate for trusted knowledge.

Fact is a local-first command-line system for recording decisions, claims,
notes, and durable domain knowledge as signed, reviewable propositions. It's
designed for teams and agents that need more than a wiki or a pile of markdown
files.

Use `fact` when knowledge needs provenance, review, history, and a clear
current answer (that's also retractable). A proposition can be proposed,
discussed, accepted, rejected, revised, withdrawn, archived, searched, tagged,
exported, and synchronized. The Fact system is for serious workloads that need
living distributable context.

## Nomenclature

- Fact – The CLI
- [Facts](https://github.com/facts-kms/spec) – The Protocol, and System

## Philosophical Language

- Proposition – A statement that can be either true or false.
- Fact – A true proposition.

## Why Facts

Most existing knowledge management tools optimize for capture. Some also
optimize for recall. That's great, but almost none of them are designed to
discern trusted knowledge. The Fact system optimizes for knowing what is
currently trusted, how it got that way, and who had the authority to change it.

**It's as much about multi-player consensus as it is about fast capture and
recall.**

Here are some of the benefits of the Fact system:

- The proposition vs. fact distinction separates information from accepted
  knowledge.
- Revisions, decisions, comments, invitations, and conflicts are first-class
  workflows.
- Multi-player workflows let humans and agents collaborate and *curate*
  knowledge.
- Zero-config datastores let you use fact as a substrate to support topologies,
  e.g., personal ledgers, project ledgers, shared team ledgers, read-only
  mirrors, and remote synchronization.
- Human output is readable in a terminal; JSON output is available for scripts,
  automation, and agents.
- Knowledge is stored in append-only ledgers as immutable signed events which
  preserve authorship, ordering, and audit history.
- Distributed ledgers can be synchronized between local files, remotes, mirrors,
  and synchronization workflows.

## Demo

Create a local Fact environment:

```sh
fact init
```

Create a proposition from markdown:

```sh
cat > decision.md <<'EOF'
# Use SQLite for the local ledger

SQLite keeps the first implementation portable, inspectable, and easy to run in
developer workspaces and CI jobs.
EOF

fact propose decision.md
```

Accept the proposition:

```sh
fact accept
```

Find and inspect the accepted knowledge later:

```sh
fact find sqlite
fact show 01a00
fact echo 01a00
```

Revise it when the knowledge changes:

```sh
cat > decision-v2.md <<'EOF'
# Use SQLite for local ledgers

SQLite remains the default local ledger store. Remote synchronization can layer
on top without changing the local developer workflow.
EOF

fact revise 01a00 decision-v2.md
fact accept 01a00
```

Use JSON when another program needs to consume the result:

```sh
fact --json search sqlite
```

## Common Workflows

Start or select ledgers:

```sh
fact init
fact status
fact use default
fact clone ./ledger.bundle
```

Work with propositions:

```sh
fact propose decision.md
fact list
fact pending
fact accept 01a00
fact reject 01a00
fact revise 01a00 update.md
fact withdraw 01a00 --reason "superseded by another decision"
fact archive 01a00 --reason "kept for historical reference"
```

Collaborate around knowledge:

```sh
fact comment 01a00
fact comments 01a00
fact invite 01a00 alice
fact invitations
fact conflicts
fact resolve 01a00
```

Organize and retrieve:

```sh
fact tags 01a00 add architecture storage
fact tags --search architecture
fact search "local ledger"
fact find "accepted storage decision"
fact history 01a00
```

## Repository Scope

This repository owns the Rust `fact` binary and the terminal experience around
Facts Protocol v0:

- command-line argument parsing and help text
- editor, stdin, stdout, pager, and JSON output handling
- human-readable command output and errors
- command compatibility and CLI integration tests

Reusable protocol, storage, search, sync, and workflow behavior lives in the
sibling `facts/sdk` repository.

## Build and verify

This repository expects the Facts SDK checkout to exist next to it:

```text
facts/
  cli/
  sdk/
```

Then build and test the CLI:

```sh
cargo build --locked
cargo test --locked
```

For CI-style verification:

```sh
./run deploy phase lint
./run deploy phase test
./run deploy phase build
```

## License

MIT
