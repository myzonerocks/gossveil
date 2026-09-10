/* gossveil: the C surface. Inputs are a pointer and a length, NULL with zero
 * meaning absent. Byte outputs are GvBuffer cells the library fills; free each
 * once with gv_free. Every call returns a GvStatus, zero on success, and on any
 * other status every output cell is left empty. Records go in and out as bytes. */
#ifndef GOSSVEIL_H
#define GOSSVEIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GV_ABI_VERSION 1u

typedef struct GvBuffer {
    uint8_t *ptr;
    size_t len;
} GvBuffer;

typedef enum GvStatus {
    GV_OK = 0,
    GV_BAD_ARGUMENT = 1,
    GV_BAD_STATE = 2,
    GV_BAD_KEY = 3,
    GV_BAD_SIGNATURE = 4,
    GV_BAD_MESSAGE = 5,
    GV_UNKNOWN_KEY_ID = 6,
    GV_UNTRUSTED_IDENTITY = 7,
    GV_NO_SESSION = 8,
    GV_REPLAY = 9,
    GV_LEGACY_VERSION = 10,
    GV_UNKNOWN_VERSION = 11,
    GV_OUT_OF_MEMORY = 12,
    GV_VERIFY_FAILED = 13,
    GV_INTERNAL = 14
} GvStatus;

/* The kind of a sealed message, as the first byte a client puts on the wire. */
#define GV_KIND_WHISPER 2u
#define GV_KIND_FIRST 3u
#define GV_KIND_CIRCLE 7u
#define GV_KIND_PLAIN 8u

/* Post-quantum parameter sets, as the tag byte on a serialized key. */
#define GV_PQ_ROUND_THREE 0x08u
#define GV_PQ_STANDARD 0x0Au

uint32_t gv_abi_version(void);
void gv_free(uint8_t *ptr, size_t len);
/* Input memory for a host that cannot pass its own (wasm); freed with gv_free. */
uint8_t *gv_alloc(size_t len);
const char *gv_status_text(int32_t status);

/* Keys */

int32_t gv_curve_pair(GvBuffer *secret, GvBuffer *public_key);
int32_t gv_curve_public(const uint8_t *secret, size_t secret_len, GvBuffer *public_key);
int32_t gv_curve_sign(const uint8_t *secret, size_t secret_len, const uint8_t *message, size_t message_len, GvBuffer *signature);
int32_t gv_curve_verify(const uint8_t *public_key, size_t public_len, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, uint8_t *ok);
int32_t gv_curve_agree(const uint8_t *secret, size_t secret_len, const uint8_t *public_key, size_t public_len, GvBuffer *shared);
int32_t gv_curve_check(const uint8_t *public_key, size_t public_len);
int32_t gv_pq_pair(uint8_t scheme, GvBuffer *public_key, GvBuffer *secret);
int32_t gv_pq_encapsulate(const uint8_t *public_key, size_t public_len, GvBuffer *capsule, GvBuffer *shared);
int32_t gv_pq_open(const uint8_t *secret, size_t secret_len, const uint8_t *capsule, size_t capsule_len, GvBuffer *shared);
int32_t gv_identity_pair(GvBuffer *serialized);
int32_t gv_identity_serialize(const uint8_t *secret, size_t secret_len, GvBuffer *serialized);
int32_t gv_identity_parse(const uint8_t *serialized, size_t len, GvBuffer *public_key, GvBuffer *secret);
int32_t gv_identity_vouch(const uint8_t *secret, size_t secret_len, const uint8_t *other, size_t other_len, GvBuffer *signature);
int32_t gv_identity_vouched(const uint8_t *public_key, size_t public_len, const uint8_t *other, size_t other_len, const uint8_t *signature, size_t signature_len, uint8_t *ok);

/* Published key records */

int32_t gv_one_time_record(uint32_t id, const uint8_t *secret, size_t secret_len, GvBuffer *record);
int32_t gv_one_time_parse(const uint8_t *record, size_t len, uint32_t *id, GvBuffer *public_key, GvBuffer *secret);
int32_t gv_signed_record(uint32_t id, uint64_t stamp, const uint8_t *secret, size_t secret_len, const uint8_t *signature, size_t signature_len, GvBuffer *record);
int32_t gv_signed_parse(const uint8_t *record, size_t len, uint32_t *id, uint64_t *stamp, GvBuffer *public_key, GvBuffer *secret, GvBuffer *signature);
int32_t gv_pq_record(uint32_t id, uint64_t stamp, const uint8_t *public_key, size_t public_len, const uint8_t *secret, size_t secret_len, const uint8_t *signature, size_t signature_len, GvBuffer *record);
int32_t gv_pq_record_parse(const uint8_t *record, size_t len, uint32_t *id, uint64_t *stamp, GvBuffer *public_key, GvBuffer *secret, GvBuffer *signature);

/* Sessions: an empty record starts one; addresses are optional and bind a
 * message to its sender and recipient when both are service ids. */

typedef struct GvSessionInfo {
    uint8_t has_live;
    uint8_t can_send;
    uint8_t usable;
    uint32_t version;
    uint32_t local_registration_id;
    uint32_t remote_registration_id;
    uint32_t shelved;
    uint8_t local_identity[33];
    uint8_t remote_identity[33];
    uint8_t base[33];
} GvSessionInfo;

typedef struct GvPublished {
    uint32_t registration_id;
    uint32_t device;
    int64_t one_time_id; /* -1 when no one-time key is offered */
    const uint8_t *one_time;
    size_t one_time_len;
    uint32_t signed_id;
    const uint8_t *signed_key;
    size_t signed_len;
    const uint8_t *signed_signature;
    size_t signed_signature_len;
    const uint8_t *identity;
    size_t identity_len;
    uint32_t pq_id;
    const uint8_t *pq_key;
    size_t pq_len;
    const uint8_t *pq_signature;
    size_t pq_signature_len;
} GvPublished;

typedef struct GvConsumed {
    uint8_t used;
    int64_t one_time_id; /* -1 when no one-time key was consumed */
    uint32_t signed_id;
    uint32_t pq_id;
    uint8_t base[33];
} GvConsumed;

typedef struct GvOpenerInfo {
    uint8_t version;
    uint32_t registration_id;
    int64_t one_time_id;
    uint32_t signed_id;
    int64_t pq_id;
    uint8_t base[33];
    uint8_t identity[33];
} GvOpenerInfo;

typedef struct GvWhisperInfo {
    uint8_t version;
    uint32_t index;
    uint32_t previous_index;
    uint8_t ratchet[33];
} GvWhisperInfo;

int32_t gv_session_info(const uint8_t *record, size_t len, uint64_t now_secs, GvSessionInfo *info);
int32_t gv_session_shelve(const uint8_t *record, size_t len, GvBuffer *out_record);
int32_t gv_session_ratchet_is(const uint8_t *record, size_t len, const uint8_t *key, size_t key_len, uint8_t *ok);
int32_t gv_session_start(const uint8_t *identity_secret, size_t secret_len, uint32_t registration_id, const uint8_t *record, size_t record_len, const GvPublished *published, uint64_t now_secs, GvBuffer *out_record);
int32_t gv_session_seal(const uint8_t *record, size_t record_len, const uint8_t *plain, size_t plain_len, uint64_t now_secs, const uint8_t *sender, size_t sender_len, uint32_t sender_device, const uint8_t *recipient, size_t recipient_len, uint32_t recipient_device, uint8_t *kind, GvBuffer *sealed, GvBuffer *out_record);
int32_t gv_session_open(const uint8_t *record, size_t record_len, const uint8_t *whisper, size_t whisper_len, const uint8_t *sender, size_t sender_len, uint32_t sender_device, const uint8_t *recipient, size_t recipient_len, uint32_t recipient_device, GvBuffer *plain, GvBuffer *out_record);
int32_t gv_session_open_first(const uint8_t *identity_secret, size_t secret_len, uint32_t registration_id, const uint8_t *record, size_t record_len, const uint8_t *opener, size_t opener_len, const uint8_t *signed_record, size_t signed_len, const uint8_t *one_time_record, size_t one_time_len, const uint8_t *pq_record, size_t pq_len, const uint8_t *sender, size_t sender_len, uint32_t sender_device, const uint8_t *recipient, size_t recipient_len, uint32_t recipient_device, GvBuffer *plain, GvBuffer *out_record, GvConsumed *consumed);
int32_t gv_opener_parse(const uint8_t *opener, size_t len, GvOpenerInfo *info, GvBuffer *inner);
int32_t gv_whisper_parse(const uint8_t *whisper, size_t len, GvWhisperInfo *info, GvBuffer *body);

/* Circles */

typedef struct GvAnnounceInfo {
    uint8_t version;
    uint8_t circle_id[16];
    uint32_t chain_id;
    uint32_t step;
    uint8_t seed[32];
    uint8_t signing[33];
} GvAnnounceInfo;

typedef struct GvNoteInfo {
    uint8_t version;
    uint8_t circle_id[16];
    uint32_t chain_id;
    uint32_t step;
} GvNoteInfo;

int32_t gv_circle_announce(const uint8_t *record, size_t record_len, const uint8_t *circle_id, size_t id_len, GvBuffer *out_record, GvBuffer *announce);
int32_t gv_circle_admit(const uint8_t *record, size_t record_len, const uint8_t *announce, size_t announce_len, GvBuffer *out_record);
int32_t gv_announce_parse(const uint8_t *announce, size_t len, GvAnnounceInfo *info);
int32_t gv_circle_seal(const uint8_t *record, size_t record_len, const uint8_t *circle_id, size_t id_len, const uint8_t *plain, size_t plain_len, GvBuffer *note, GvBuffer *out_record);
int32_t gv_circle_open(const uint8_t *record, size_t record_len, const uint8_t *note, size_t note_len, GvBuffer *plain, GvBuffer *out_record);
int32_t gv_note_parse(const uint8_t *note, size_t len, GvNoteInfo *info, GvBuffer *body);

/* Envelopes */

typedef struct GvServerCertInfo {
    uint32_t key_id;
    uint8_t key[33];
} GvServerCertInfo;

typedef struct GvSenderCertInfo {
    uint32_t device;
    uint64_t expires_ms;
    uint8_t key[33];
    uint8_t has_phone;
} GvSenderCertInfo;

typedef struct GvContentInfo {
    uint8_t kind;
    uint8_t hint;
    uint8_t has_circle;
} GvContentInfo;

int32_t gv_server_cert(uint32_t key_id, const uint8_t *key, size_t key_len, const uint8_t *trust_secret, size_t trust_len, GvBuffer *cert);
int32_t gv_server_cert_parse(const uint8_t *cert, size_t len, GvServerCertInfo *info, GvBuffer *body, GvBuffer *signature);
int32_t gv_server_cert_check(const uint8_t *cert, size_t len, const uint8_t *trust_root, size_t trust_len, uint8_t *ok);
int32_t gv_sender_cert(const uint8_t *sender_id, size_t id_len, const uint8_t *phone, size_t phone_len, uint32_t device, const uint8_t *key, size_t key_len, uint64_t expires_ms, const uint8_t *server_cert, size_t server_len, const uint8_t *server_secret, size_t secret_len, GvBuffer *cert);
int32_t gv_sender_cert_parse(const uint8_t *cert, size_t len, GvSenderCertInfo *info, GvBuffer *sender_id, GvBuffer *phone, GvBuffer *server_cert, GvBuffer *body, GvBuffer *signature);
int32_t gv_sender_cert_check(const uint8_t *cert, size_t len, const uint8_t *trust_root, size_t trust_len, uint64_t now_ms, uint8_t *ok);
int32_t gv_content(uint8_t kind, const uint8_t *sender_cert, size_t cert_len, const uint8_t *body, size_t body_len, uint8_t hint, const uint8_t *circle_id, size_t circle_len, uint8_t has_circle, GvBuffer *content);
int32_t gv_content_parse(const uint8_t *content, size_t len, GvContentInfo *info, GvBuffer *body, GvBuffer *sender_cert, GvBuffer *circle_id);
int32_t gv_envelope_seal(const uint8_t *identity_secret, size_t secret_len, const uint8_t *recipient_identity, size_t recipient_len, const uint8_t *content, size_t content_len, GvBuffer *envelope);
int32_t gv_envelope_open(const uint8_t *identity_secret, size_t secret_len, const uint8_t *envelope, size_t envelope_len, GvBuffer *content);
/* Recipients: a count byte, then per recipient a 17-byte service id, a device
 * count, (device, big-endian registration id) pairs and a 33-byte identity key.
 * Excluded: a count byte, then 17 bytes each. */
int32_t gv_envelope_seal_many(const uint8_t *identity_secret, size_t secret_len, const uint8_t *recipients, size_t recipients_len, const uint8_t *excluded, size_t excluded_len, const uint8_t *content, size_t content_len, GvBuffer *sent);
int32_t gv_envelope_for_single(const uint8_t *sent, size_t len, GvBuffer *received);
int32_t gv_envelope_for_recipient(const uint8_t *sent, size_t len, const uint8_t *service_id, size_t id_len, uint8_t device, GvBuffer *received);

/* Safety numbers */

int32_t gv_safety(uint32_t version, uint32_t iterations, const uint8_t *local_id, size_t local_id_len, const uint8_t *local_key, size_t local_key_len, const uint8_t *remote_id, size_t remote_id_len, const uint8_t *remote_key, size_t remote_key_len, GvBuffer *display, GvBuffer *scannable);
int32_t gv_safety_matches(const uint8_t *ours, size_t ours_len, const uint8_t *theirs, size_t theirs_len, uint8_t *ok);

/* Handles */

int32_t gv_handle_hash(const uint8_t *name, size_t len, GvBuffer *hash);
int32_t gv_handle_proof(const uint8_t *name, size_t len, const uint8_t *randomness, size_t randomness_len, GvBuffer *proof);
int32_t gv_handle_verify(const uint8_t *proof, size_t proof_len, const uint8_t *hash, size_t hash_len, uint8_t *ok);
int32_t gv_handle_candidates(const uint8_t *nickname, size_t len, uint32_t min_len, uint32_t max_len, GvBuffer *newline_separated);
int32_t gv_handle_from_parts(const uint8_t *nickname, size_t nickname_len, const uint8_t *discriminator, size_t discriminator_len, uint32_t min_len, uint32_t max_len, GvBuffer *name, GvBuffer *hash);
int32_t gv_handle_link(const uint8_t *name, size_t len, const uint8_t *entropy, size_t entropy_len, GvBuffer *out_entropy, GvBuffer *sealed);
int32_t gv_handle_link_open(const uint8_t *entropy, size_t entropy_len, const uint8_t *sealed, size_t sealed_len, GvBuffer *name);

/* The vault: account entropy, backup keys, circle parameters */

int32_t gv_pool_random(GvBuffer *pool);
uint8_t gv_pool_valid(const uint8_t *pool, size_t len);
int32_t gv_pool_derive(const uint8_t *pool, size_t len, GvBuffer *recovery_key, GvBuffer *backup_key);
int32_t gv_backup_key_random(GvBuffer *key);
int32_t gv_backup_key_for_account(const uint8_t *key, size_t key_len, const uint8_t *account_id, size_t id_len, GvBuffer *backup_id, GvBuffer *signing_key);
int32_t gv_backup_key_local_metadata(const uint8_t *key, size_t key_len, GvBuffer *metadata_key);
int32_t gv_backup_key_media(const uint8_t *key, size_t key_len, const uint8_t *media_name, size_t name_len, GvBuffer *media_id, GvBuffer *media_key, GvBuffer *thumbnail_key);
int32_t gv_backup_key_media_keys(const uint8_t *key, size_t key_len, const uint8_t *media_id, size_t id_len, GvBuffer *media_key, GvBuffer *thumbnail_key);
int32_t gv_circle_master_random(GvBuffer *master);
int32_t gv_circle_secret_params(const uint8_t *master, size_t len, GvBuffer *secret_params);
int32_t gv_circle_params_info(const uint8_t *secret_params, size_t len, GvBuffer *master, GvBuffer *identifier, GvBuffer *public_params);

/* Streams, primitives, reports */

typedef struct GvReportInfo {
    uint64_t stamp_ms;
    uint32_t device;
    uint8_t has_ratchet;
    uint8_t ratchet[33];
} GvReportInfo;

int32_t gv_hkdf(const uint8_t *material, size_t material_len, const uint8_t *salt, size_t salt_len, uint8_t has_salt, const uint8_t *info, size_t info_len, uint32_t out_len, GvBuffer *out);
int32_t gv_siv_seal(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *plain, size_t plain_len, const uint8_t *aad, size_t aad_len, GvBuffer *sealed);
int32_t gv_siv_open(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *sealed, size_t sealed_len, const uint8_t *aad, size_t aad_len, GvBuffer *plain);
int32_t gv_random(uint32_t len, GvBuffer *out);
int32_t gv_chunk_tags(const uint8_t *key, size_t key_len, uint32_t chunk, const uint8_t *data, size_t data_len, GvBuffer *tags);
int32_t gv_chunk_check(const uint8_t *key, size_t key_len, uint32_t chunk, const uint8_t *data, size_t data_len, const uint8_t *tags, size_t tags_len);
int32_t gv_report(const uint8_t *original, size_t len, uint8_t kind, uint64_t stamp_ms, uint32_t device, GvBuffer *report);
int32_t gv_report_parse(const uint8_t *report, size_t len, GvReportInfo *info);
int32_t gv_report_in_body(const uint8_t *body, size_t len, GvBuffer *report);
int32_t gv_plain_from_report(const uint8_t *report, size_t len, GvBuffer *plain);
int32_t gv_plain_body(const uint8_t *plain, size_t len, GvBuffer *body);

#ifdef __cplusplus
}
#endif

#endif
