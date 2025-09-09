#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DaveBuffer {
    uint8_t* data;
    size_t size;
} DaveBuffer;

typedef struct DaveHashRatchet {
    uint16_t cipher_suite;
    DaveBuffer base_secret;
} DaveHashRatchet;

typedef struct DaveCommitProcessingResult {
    bool failed;
    bool ignored;
    void *roster_update;
} DaveCommitProcessingResult;

typedef void (*DaveMlsFailureCallback)(const char*, const char*);

typedef void (*DaveProtocolVersionChangedCallback)(void);

extern const int DAVE_INIT_TRANSITION_ID;

extern const int DAVE_DISABLED_VERSION;

typedef enum DaveMediaType : uint8_t {
    AUDIO,
    VIDEO
} DaveMediaType;

typedef enum DaveCodec : uint8_t {
    UNKNOWN,
    OPUS,
    VP8,
    VP9,
    H264,
    H265,
    AV1
} DaveCodec;

uint16_t dave_max_supported_protocol_version(void);

void* dave_session_create(const char *context, const char *auth_session_id, DaveMlsFailureCallback mls_failure_callback);

void dave_session_free(void *session);

void dave_session_init(void *session, uint16_t protocol_version, uint64_t group_id, const char *self_user_id, const void *transient_key);

void dave_session_reset(void *session);

void dave_session_set_protocol_version(void *session, uint16_t protocol_version);

uint16_t dave_session_get_protocol_version(const void *session);

DaveBuffer dave_session_get_last_epoch_authenticator(const void *session);

void dave_session_set_external_sender(void *session, DaveBuffer marshalled_external_sender);

DaveBuffer dave_session_process_proposals(void *session, DaveBuffer proposals, const char * const *recognized_user_ids, size_t recognized_user_ids_count);

DaveCommitProcessingResult dave_session_process_commit(void *session, DaveBuffer commit);

void* dave_session_process_welcome(void *session, DaveBuffer welcome, const char * const *recognized_user_ids, size_t recognized_user_ids_count);

DaveBuffer dave_session_get_marshalled_key_package(void *session);

DaveHashRatchet dave_session_get_key_ratchet(const void *session, const char *user_id);

void dave_buffer_free(DaveBuffer buffer);

void* dave_encryptor_create(void);

void dave_encryptor_free(void *encryptor);

void dave_encryptor_set_key_ratchet(void *encryptor, DaveHashRatchet key_ratchet);

void dave_encryptor_set_passthrough_mode(void *encryptor, bool passthrough_mode);

void dave_encryptor_assign_ssrc_to_codec(void *encryptor, uint32_t ssrc, DaveCodec codec_type);

uint16_t dave_encryptor_get_protocol_version(const void *encryptor);

size_t dave_encryptor_get_max_ciphertext_byte_size(void *encryptor, DaveMediaType media_type, size_t frame_size);

size_t dave_encryptor_encrypt(void *encryptor, DaveMediaType media_type, uint32_t ssrc, DaveBuffer frame, DaveBuffer encrypted_frame);

void dave_encryptor_set_protocol_version_changed_callback(void *encryptor, DaveProtocolVersionChangedCallback callback);

void* dave_decryptor_create(void);

void dave_decryptor_free(void *decryptor);

void dave_decryptor_transition_to_key_ratchet(void *decryptor, DaveHashRatchet key_ratchet, int64_t transition_expiry_seconds);

void dave_decryptor_transition_to_passthrough_mode(void *decryptor, bool passthrough_mode, int64_t transition_expiry_seconds);

size_t dave_decryptor_decrypt(void *decryptor, DaveMediaType media_type, DaveBuffer encrypted_frame, DaveBuffer frame);

size_t dave_decryptor_get_max_plaintext_byte_size(void *decryptor, DaveMediaType media_type, size_t encrypted_frame_size);

void* dave_transient_private_key_generate(uint16_t protocol_version);

void dave_transient_private_key_free(void *key);

DaveBuffer dave_roster_map_find(const void *roster_map, uint64_t key);

void dave_roster_map_free(void *roster_map);

void dave_commit_processing_result_free(DaveCommitProcessingResult result);

void dave_hash_ratchet_free(DaveHashRatchet hash_ratchet);

#ifdef __cplusplus
}
#endif
