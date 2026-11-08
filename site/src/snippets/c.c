#include <gossveil.h>

/* Every call returns a status, and every byte output is a cell you free once. */
GvBuffer sealed = {0}, next_record = {0};

int32_t status = gv_session_seal(
    record.ptr, record.len,
    plaintext, plaintext_len,
    &sealed, &next_record
);
if (status != GV_OK) return status;

/* Persist next_record before you send sealed, or a crash loses a step. */
store_session(address, next_record.ptr, next_record.len);

gv_free(sealed.ptr, sealed.len);
gv_free(next_record.ptr, next_record.len);
