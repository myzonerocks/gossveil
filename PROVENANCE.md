# Provenance

This project is an independent implementation.

Protocol behaviour was developed from the publicly available protocol specifications and
cryptographic standards, and checked against wire vectors recorded by this project's own tooling.
The architecture the code follows is this project's own and is written down in
[docs/DESIGN.md](docs/DESIGN.md) before the code that implements it.

No source code from any other implementation was incorporated, translated, ported or modified.
All implementation code, tests, documentation and build tooling were authored for this project.
The one dependency is the Zig standard library, under the MIT licence, noted in
[NOTICE.md](NOTICE.md).

Where two implementations of the same protocol must agree, they agree on bytes: key encodings,
record layouts, message framing and key schedules are fixed by the protocol, and the names of
those things (root key, chain key, message key, pre-key, sender key, distribution id) are the
protocol's vocabulary. Everything else here, the module layout, the types, the functions, the
comments and the tests, is this project's own expression.
