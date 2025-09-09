#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Buffer {
    uint8_t* data;
    size_t size;
} Buffer;

typedef struct HashRatchet {
    uint16_t cipher_suite;
    Buffer base_secret;
} HashRatchet;

typedef struct CommitProcessingResult {
    bool failed;
    bool ignored;
    void *roster_update;
} CommitProcessingResult;

extern const int DAVE_INIT_TRANSITION_ID;

extern const int DAVE_DISABLED_VERSION;

typedef enum MediaType : uint8_t {
    AUDIO,
    VIDEO
} MediaType;

typedef enum Codec : uint8_t {
    UNKNOWN,
    OPUS,
    VP8,
    VP9,
    H264,
    H265,
    AV1
} Codec;

uint16_t dave_max_supported_protocol_version(void);

void *dave_session_create(char *context, char *auth_session_id, void (*mls_failure_callback)(const char*, const char*));

void dave_session_free(void *session);

void dave_session_init(void *session, uint16_t protocol_version, uint64_t group_id, char *self_user_id, void *transient_key);

void dave_session_reset(void *session);

void dave_session_set_protocol_version(void *session, uint16_t protocol_version);

uint16_t dave_session_get_protocol_version(void *session);

Buffer dave_session_get_last_epoch_authenticator(void *session);

void dave_session_set_external_sender(void *session, Buffer marshalled_external_sender);

Buffer dave_session_process_proposals(void *session, Buffer proposals, char **recognized_user_ids, size_t recognized_user_ids_count);

CommitProcessingResult dave_session_process_commit(void *session, Buffer commit);

void *dave_session_process_welcome(void *session, Buffer welcome, char **recognized_user_ids, size_t recognized_user_ids_count);

Buffer dave_session_get_marshalled_key_package(void *session);

HashRatchet dave_session_get_key_ratchet(void *session, char *user_id);

void dave_buffer_free(Buffer buffer);

void *dave_encryptor_create(void);

void dave_encryptor_free(void *encryptor);

void dave_encryptor_set_key_ratchet(void *encryptor, HashRatchet key_ratchet);

void dave_encryptor_set_passthrough_mode(void *encryptor, bool passthrough_mode);

void dave_encryptor_assign_ssrc_to_codec(void *encryptor, uint32_t ssrc, Codec codec_type);

uint16_t dave_encryptor_get_protocol_version(void *encryptor);

size_t dave_encryptor_get_max_ciphertext_byte_size(void *encryptor, MediaType media_type, size_t frame_size);

size_t dave_encryptor_encrypt(void *encryptor, MediaType media_type, uint32_t ssrc, Buffer frame, Buffer encrypted_frame);

void dave_encryptor_set_protocol_version_changed_callback(void *encryptor, void (*callback)(void));

void *dave_decryptor_create(void);

void dave_decryptor_free(void *decryptor);

void dave_decryptor_transition_to_key_ratchet(void *decryptor, HashRatchet key_ratchet, int64_t transition_expiry_seconds);

void dave_decryptor_transition_to_passthrough_mode(void *decryptor, bool passthrough_mode, int64_t transition_expiry_seconds);

size_t dave_decryptor_decrypt(void *decryptor, MediaType media_type, Buffer encrypted_frame, Buffer frame);

size_t dave_decryptor_get_max_plaintext_byte_size(void *decryptor, MediaType media_type, size_t encrypted_frame_size);

void *dave_transient_private_key_generate(uint16_t protocol_version);

void dave_transient_private_key_free(void *key);

Buffer dave_roster_map_find(void *roster_map, uint64_t key);

void dave_roster_map_free(void *roster_map);

void dave_commit_processing_result_free(CommitProcessingResult result);

void dave_hash_ratchet_free(HashRatchet hash_ratchet);

#ifdef __cplusplus
}
#endif
