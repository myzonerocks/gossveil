# Gossveil, C SDK

The C ABI at [`include/gossveil.h`](../../include/gossveil.h), staged as a library any language
with a C FFI can link. This is the direct surface: the [Swift](../swift/README.md),
[Kotlin](../kotlin/README.md) and [TypeScript](../ts/README.md) packages are thin wrappers over the
same `gv_*` functions, so a C, C++, Rust, Go or Python host reaches the core through this header
rather than a wrapper of its own.

There is no second header to drift from the ABI. `zig build c` stages the one in `include/` beside
the library it was built with.

## Build

```sh
zig build c
```

stages, under `zig-out/c/`:

```text
include/gossveil.h      the C ABI, copied from include/
lib/libgossveil.dylib   the shared library (.so on Linux)
lib/libgossveil.a       the static archive
```

Both carry the whole core. There is nothing else to link: no runtime, no allocator to install, no
system library beyond libc.

## Link

```c
#include <gossveil.h>
```

```sh
cc app.c \
    -I zig-out/c/include \
    -L zig-out/c/lib -lgossveil \
    -Wl,-rpath,"$PWD/zig-out/c/lib" \
    -o app
```

The static archive links the same way, with `zig-out/c/lib/libgossveil.a` in place of the `-L` and
`-l` pair. On macOS build that link with `zig cc`: Apple's linker refuses the archive's member
alignment, and the shared library has no such trouble with either toolchain.

A CMake project imports the staged library through [`CMakeLists.txt`](CMakeLists.txt) rather than
rebuilding anything:

```cmake
add_subdirectory(path/to/gossveil/sdk/c gossveil)
target_link_libraries(app PRIVATE gossveil)
```

## The calling convention

Five rules cover the whole header.

1. Every call returns `int32_t`. `GV_OK` is 0; anything else is a `GvStatus`, and
   `gv_status_text` names it.
2. Bytes go in as a pointer and a length. `NULL` with 0 means absent, which is how an optional
   input, an unused address or a missing one-time key is passed.
3. Bytes come out in `GvBuffer` cells the library fills. Free each one with `gv_free(b.ptr, b.len)`,
   once.
4. On any status but `GV_OK` every output cell is left empty, so a failed call frees nothing and
   leaks nothing.
5. Records are bytes. The host stores them and hands them back; the library keeps nothing between
   calls.

`gv_abi_version()` is the first call to make. It returns the ABI the library was built with, and a
program that reads something other than `GV_ABI_VERSION` from its header is holding a mismatched
pair and must refuse to run.

`gv_alloc` exists for a host that cannot hand the library a pointer of its own, which in practice
means wasm. A C program never needs it.

## A session

Two parties, a published bundle, a message each way. The full program is
[`example/main.c`](example/main.c).

```c
#include <gossveil.h>

GvBuffer identity_secret = {0}, identity_public = {0};
if (gv_curve_pair(&identity_secret, &identity_public) != GV_OK) return 1;

/* The recipient's bundle, as it arrived from your service. */
GvPublished published = {
    .registration_id = 4242, .device = 1,
    .one_time_id = -1, .one_time = NULL, .one_time_len = 0,
    .signed_id = 1, .signed_key = signed_public, .signed_len = signed_public_len,
    .signed_signature = signed_sig, .signed_signature_len = signed_sig_len,
    .identity = their_identity, .identity_len = their_identity_len,
    .pq_id = 1, .pq_key = pq_public, .pq_len = pq_public_len,
    .pq_signature = pq_sig, .pq_signature_len = pq_sig_len,
};

/* An empty record starts the session; every call hands back the next record. */
GvBuffer session = {0};
if (gv_session_start(identity_secret.ptr, identity_secret.len, 1234, NULL, 0, &published, now_secs, &session) != GV_OK) return 1;

uint8_t kind = 0;
GvBuffer sealed = {0}, next = {0};
if (gv_session_seal(session.ptr, session.len, (const uint8_t *)"hello", 5, now_secs,
                    NULL, 0, 1, NULL, 0, 1, &kind, &sealed, &next) != GV_OK) return 1;
gv_free(session.ptr, session.len);
session = next;
```

`kind` is what goes on the wire in front of the body: `GV_KIND_FIRST` for the message that carries
the handshake, `GV_KIND_WHISPER` after that. The recipient picks its call by that byte,
`gv_session_open_first` for the first one and `gv_session_open` for the rest, and each hands back
the record to store in place of the old one.

`gv_session_open_first` also fills a `GvConsumed`, which says whether the message spent a one-time
key and which id, so the host can drop that key.

## The surface

| Area | Functions |
|---|---|
| Keys | `gv_curve_pair`, `gv_curve_public`, `gv_curve_sign`, `gv_curve_verify`, `gv_curve_agree`, `gv_curve_check`, `gv_pq_pair`, `gv_pq_encapsulate`, `gv_pq_open`, `gv_identity_*` |
| Published records | `gv_one_time_record`, `gv_signed_record`, `gv_pq_record`, and a `_parse` for each |
| Sessions | `gv_session_start`, `gv_session_seal`, `gv_session_open`, `gv_session_open_first`, `gv_session_info`, `gv_session_shelve`, `gv_session_ratchet_is`, `gv_opener_parse`, `gv_whisper_parse` |
| Circles | `gv_circle_announce`, `gv_circle_admit`, `gv_circle_seal`, `gv_circle_open`, `gv_announce_parse`, `gv_note_parse` |
| Envelopes | `gv_server_cert`, `gv_sender_cert`, their `_parse` and `_check`, `gv_content`, `gv_content_parse`, `gv_envelope_seal`, `gv_envelope_open`, `gv_envelope_seal_many`, `gv_envelope_for_single`, `gv_envelope_for_recipient` |
| Safety numbers | `gv_safety`, `gv_safety_matches` |
| Handles | `gv_handle_hash`, `gv_handle_proof`, `gv_handle_verify`, `gv_handle_candidates`, `gv_handle_from_parts`, `gv_handle_link`, `gv_handle_link_open` |
| Vault | `gv_pool_random`, `gv_pool_derive`, `gv_backup_key_*`, `gv_circle_master_random`, `gv_circle_secret_params`, `gv_circle_params_info` |
| Primitives | `gv_hkdf`, `gv_siv_seal`, `gv_siv_open`, `gv_random`, `gv_chunk_tags`, `gv_chunk_check` |
| Reports | `gv_report`, `gv_report_parse`, `gv_report_in_body`, `gv_plain_from_report`, `gv_plain_body` |

The header is the reference and carries the argument order for each. What the same operation is
called in the other packages is in [docs/API.md](../../docs/API.md).

## Status codes

| Status | What happened |
|---|---|
| `GV_BAD_ARGUMENT` | a length, a pointer or a field the call cannot work with |
| `GV_BAD_STATE` | the record cannot do what was asked of it |
| `GV_BAD_KEY`, `GV_BAD_SIGNATURE` | a key or a signature did not check out |
| `GV_BAD_MESSAGE` | the bytes are not the message they claim to be |
| `GV_UNKNOWN_KEY_ID` | the message names a key the host did not hand over |
| `GV_UNTRUSTED_IDENTITY` | the peer's identity key is not the one on record |
| `GV_NO_SESSION` | there is no session for this peer yet |
| `GV_REPLAY` | this message was already opened |
| `GV_LEGACY_VERSION`, `GV_UNKNOWN_VERSION` | a message from an older or a newer protocol |
| `GV_VERIFY_FAILED` | a proof or a certificate did not verify |
| `GV_OUT_OF_MEMORY`, `GV_INTERNAL` | the library could not finish the call |

## Notes

- Calls are synchronous and hold no state of their own, so any thread may call in. Two threads
  must not work on the same record at once, since each call returns the next one and the last
  writer would win.
- Every `GvBuffer` is yours once the call returns. Free it with `gv_free`, not `free`.
- Timestamps are seconds where a call says `now_secs` and milliseconds where it says `_ms`.
- Addresses are optional. Passing a name and a device on both sides binds the message to that
  pair, and a message sealed with them only opens with the same pair.

## Run the example

```sh
zig build c-example      # builds it against the static archive and checks its output
sdk/c/example/build.sh   # builds the staged shared library and links the example against it
```
