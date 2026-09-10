/* One conversation through the C surface: two parties, a published bundle,
 * a session in both directions, a circle, a sealed envelope, a safety number. */
#include "gossveil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NEED(call)                                                                       \
    do {                                                                                 \
        int32_t status_ = (call);                                                        \
        if (status_ != GV_OK) {                                                          \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, gv_status_text(status_)); \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

#define EXPECT(cond, what)                                             \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, what); \
            return 1;                                                  \
        }                                                              \
    } while (0)

static const uint64_t NOW_SECS = 1700000000ull;
static const uint64_t NOW_MS = 1700000000000ull;

static void release(GvBuffer *b) {
    gv_free(b->ptr, b->len);
    b->ptr = NULL;
    b->len = 0;
}

static int reads(GvBuffer b, const char *text) {
    return b.len == strlen(text) && memcmp(b.ptr, text, b.len) == 0;
}

typedef struct Party {
    GvBuffer identity_secret, identity_public;
    GvBuffer signed_secret, signed_public, signed_signature, signed_record;
    GvBuffer pq_public, pq_secret, pq_signature, pq_record;
    GvBuffer session;
    uint32_t registration_id;
} Party;

static int make_party(Party *p, uint32_t registration_id) {
    memset(p, 0, sizeof *p);
    p->registration_id = registration_id;
    NEED(gv_curve_pair(&p->identity_secret, &p->identity_public));
    NEED(gv_curve_pair(&p->signed_secret, &p->signed_public));
    NEED(gv_curve_sign(p->identity_secret.ptr, p->identity_secret.len, p->signed_public.ptr, p->signed_public.len, &p->signed_signature));
    NEED(gv_signed_record(1, 1000, p->signed_secret.ptr, p->signed_secret.len, p->signed_signature.ptr, p->signed_signature.len, &p->signed_record));
    NEED(gv_pq_pair(GV_PQ_ROUND_THREE, &p->pq_public, &p->pq_secret));
    NEED(gv_curve_sign(p->identity_secret.ptr, p->identity_secret.len, p->pq_public.ptr, p->pq_public.len, &p->pq_signature));
    NEED(gv_pq_record(1, 1000, p->pq_public.ptr, p->pq_public.len, p->pq_secret.ptr, p->pq_secret.len, p->pq_signature.ptr, p->pq_signature.len, &p->pq_record));
    return 0;
}

static void free_party(Party *p) {
    GvBuffer *all[] = { &p->identity_secret, &p->identity_public, &p->signed_secret, &p->signed_public, &p->signed_signature,
                        &p->signed_record, &p->pq_public, &p->pq_secret, &p->pq_signature, &p->pq_record, &p->session };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) release(all[i]);
}

static int send(Party *from, const char *text, uint8_t *kind, GvBuffer *sealed) {
    GvBuffer next = {0};
    NEED(gv_session_seal(from->session.ptr, from->session.len, (const uint8_t *)text, strlen(text), NOW_SECS,
                         NULL, 0, 1, NULL, 0, 1, kind, sealed, &next));
    release(&from->session);
    from->session = next;
    return 0;
}

static int receive(Party *at, uint8_t kind, GvBuffer sealed, GvBuffer *plain) {
    GvBuffer next = {0};
    if (kind == GV_KIND_FIRST) {
        GvConsumed consumed;
        NEED(gv_session_open_first(at->identity_secret.ptr, at->identity_secret.len, at->registration_id,
                                   at->session.ptr, at->session.len, sealed.ptr, sealed.len,
                                   at->signed_record.ptr, at->signed_record.len, NULL, 0, at->pq_record.ptr, at->pq_record.len,
                                   NULL, 0, 1, NULL, 0, 1, plain, &next, &consumed));
        EXPECT(consumed.used == 1 && consumed.one_time_id == -1, "the first message consumes the signed and post-quantum keys only");
    } else {
        NEED(gv_session_open(at->session.ptr, at->session.len, sealed.ptr, sealed.len, NULL, 0, 1, NULL, 0, 1, plain, &next));
    }
    release(&at->session);
    at->session = next;
    return 0;
}

static int exchange(Party *from, Party *to, const char *text) {
    uint8_t kind;
    GvBuffer sealed = {0}, plain = {0};
    if (send(from, text, &kind, &sealed)) return 1;
    if (receive(to, kind, sealed, &plain)) return 1;
    EXPECT(reads(plain, text), "the recipient reads what was sent");
    release(&sealed);
    release(&plain);
    return 0;
}

int main(void) {
    EXPECT(gv_abi_version() == GV_ABI_VERSION, "header and library agree on the surface");
    Party alice, bob;
    if (make_party(&alice, 1234) || make_party(&bob, 4242)) return 1;

    GvPublished published = {
        .registration_id = bob.registration_id, .device = 1, .one_time_id = -1, .one_time = NULL, .one_time_len = 0,
        .signed_id = 1, .signed_key = bob.signed_public.ptr, .signed_len = bob.signed_public.len,
        .signed_signature = bob.signed_signature.ptr, .signed_signature_len = bob.signed_signature.len,
        .identity = bob.identity_public.ptr, .identity_len = bob.identity_public.len,
        .pq_id = 1, .pq_key = bob.pq_public.ptr, .pq_len = bob.pq_public.len,
        .pq_signature = bob.pq_signature.ptr, .pq_signature_len = bob.pq_signature.len,
    };
    NEED(gv_session_start(alice.identity_secret.ptr, alice.identity_secret.len, alice.registration_id, NULL, 0, &published, NOW_SECS, &alice.session));
    GvSessionInfo info;
    NEED(gv_session_info(alice.session.ptr, alice.session.len, NOW_SECS, &info));
    EXPECT(info.has_live && info.usable && info.remote_registration_id == 4242 && info.version == 4, "alice holds a fresh version 4 session");

    uint8_t kind;
    GvBuffer sealed = {0}, plain = {0};
    if (send(&alice, "hello bob", &kind, &sealed)) return 1;
    EXPECT(kind == GV_KIND_FIRST, "the first message carries the handshake");
    if (receive(&bob, kind, sealed, &plain)) return 1;
    EXPECT(reads(plain, "hello bob"), "bob reads the first message");
    release(&sealed);
    release(&plain);

    for (int i = 0; i < 12; i++) {
        if (exchange(&bob, &alice, "reply") || exchange(&alice, &bob, "again")) return 1;
    }

    GvBuffer skipped = {0}, late = {0};
    uint8_t kind_skipped, kind_late;
    if (send(&bob, "skipped", &kind_skipped, &skipped) || send(&bob, "late", &kind_late, &late)) return 1;
    EXPECT(kind_late == GV_KIND_WHISPER, "later messages are whispers");
    if (receive(&alice, kind_late, late, &plain)) return 1;
    EXPECT(reads(plain, "late"), "alice reads ahead");
    release(&plain);
    if (receive(&alice, kind_skipped, skipped, &plain)) return 1;
    EXPECT(reads(plain, "skipped"), "alice reads the skipped message from its stored key");
    release(&plain);
    GvBuffer next = {0};
    EXPECT(gv_session_open(alice.session.ptr, alice.session.len, skipped.ptr, skipped.len, NULL, 0, 1, NULL, 0, 1, &plain, &next) == GV_REPLAY, "a replay is refused");
    release(&skipped);
    release(&late);

    uint8_t circle_id[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    GvBuffer ours = {0}, announce = {0}, theirs = {0}, note = {0}, note_plain = {0}, ours_next = {0}, theirs_next = {0};
    NEED(gv_circle_announce(NULL, 0, circle_id, 16, &ours, &announce));
    NEED(gv_circle_admit(NULL, 0, announce.ptr, announce.len, &theirs));
    NEED(gv_circle_seal(ours.ptr, ours.len, circle_id, 16, (const uint8_t *)"to the circle", 13, &note, &ours_next));
    NEED(gv_circle_open(theirs.ptr, theirs.len, note.ptr, note.len, &note_plain, &theirs_next));
    EXPECT(reads(note_plain, "to the circle"), "the circle member reads the note");
    release(&ours); release(&announce); release(&theirs); release(&note); release(&note_plain); release(&ours_next); release(&theirs_next);

    GvBuffer trust_secret = {0}, trust_public = {0}, server_secret = {0}, server_public = {0}, server_cert = {0}, sender_cert = {0};
    NEED(gv_curve_pair(&trust_secret, &trust_public));
    NEED(gv_curve_pair(&server_secret, &server_public));
    NEED(gv_server_cert(1, server_public.ptr, server_public.len, trust_secret.ptr, trust_secret.len, &server_cert));
    const char *alice_id = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    NEED(gv_sender_cert((const uint8_t *)alice_id, strlen(alice_id), NULL, 0, 1, alice.identity_public.ptr, alice.identity_public.len,
                        1800000000000ull, server_cert.ptr, server_cert.len, server_secret.ptr, server_secret.len, &sender_cert));
    uint8_t ok = 0;
    NEED(gv_sender_cert_check(sender_cert.ptr, sender_cert.len, trust_public.ptr, trust_public.len, NOW_MS, &ok));
    EXPECT(ok == 1, "the sender certificate chains to the trust root");

    if (send(&alice, "sealed", &kind, &sealed)) return 1;
    GvBuffer content = {0}, envelope = {0}, opened = {0}, body = {0}, opened_cert = {0}, opened_circle = {0};
    NEED(gv_content(kind, sender_cert.ptr, sender_cert.len, sealed.ptr, sealed.len, 0, NULL, 0, 0, &content));
    NEED(gv_envelope_seal(alice.identity_secret.ptr, alice.identity_secret.len, bob.identity_public.ptr, bob.identity_public.len, content.ptr, content.len, &envelope));
    NEED(gv_envelope_open(bob.identity_secret.ptr, bob.identity_secret.len, envelope.ptr, envelope.len, &opened));
    GvContentInfo content_info;
    NEED(gv_content_parse(opened.ptr, opened.len, &content_info, &body, &opened_cert, &opened_circle));
    EXPECT(content_info.kind == kind, "the envelope carries the kind of its message");
    if (receive(&bob, content_info.kind, body, &plain)) return 1;
    EXPECT(reads(plain, "sealed"), "bob reads the sealed message");
    release(&sealed); release(&plain); release(&content); release(&envelope); release(&opened); release(&body); release(&opened_cert); release(&opened_circle);
    release(&trust_secret); release(&trust_public); release(&server_secret); release(&server_public); release(&server_cert); release(&sender_cert);

    GvBuffer display_a = {0}, scannable_a = {0}, display_b = {0}, scannable_b = {0};
    NEED(gv_safety(2, 5200, (const uint8_t *)"alice", 5, alice.identity_public.ptr, alice.identity_public.len, (const uint8_t *)"bob", 3, bob.identity_public.ptr, bob.identity_public.len, &display_a, &scannable_a));
    NEED(gv_safety(2, 5200, (const uint8_t *)"bob", 3, bob.identity_public.ptr, bob.identity_public.len, (const uint8_t *)"alice", 5, alice.identity_public.ptr, alice.identity_public.len, &display_b, &scannable_b));
    EXPECT(display_a.len == 60 && memcmp(display_a.ptr, display_b.ptr, 60) == 0, "both parties show the same safety number");
    uint8_t matches = 0;
    NEED(gv_safety_matches(scannable_a.ptr, scannable_a.len, scannable_b.ptr, scannable_b.len, &matches));
    EXPECT(matches == 1, "the scannable halves match");
    release(&display_a); release(&scannable_a); release(&display_b); release(&scannable_b);

    free_party(&alice);
    free_party(&bob);
    puts("ok");
    return 0;
}
