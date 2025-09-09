#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Buffer {
    uint8_t* data;
    size_t size;
};

struct HashRatchet {
    uint16_t cipher_suite;
    struct Buffer base_secret;
};

struct CommitProcessingResult {
    bool failed;
    bool ignored;
    void *roster_update;
};

extern const int DAVE_INIT_TRANSITION_ID;

extern const int DAVE_DISABLED_VERSION;

extern const uint8_t DAVE_MEDIA_TYPE_AUDIO;

extern const uint8_t DAVE_MEDIA_TYPE_VIDEO;

extern const uint8_t DAVE_CODEC_UNKNOWN;

extern const uint8_t DAVE_CODEC_OPUS;

extern const uint8_t DAVE_CODEC_VP8;

extern const uint8_t DAVE_CODEC_VP9;

extern const uint8_t DAVE_CODEC_H264;

extern const uint8_t DAVE_CODEC_H265;

extern const uint8_t DAVE_CODEC_AV1;

uint16_t dave_max_supported_protocol_version(void);

void *dave_session_create(char *context, char *auth_session_id, void (*mls_failure_callback)(const char*, const char*));

void dave_session_free(void *session);

void dave_session_init(void *session, uint16_t protocol_version, uint64_t group_id, char *self_user_id, void *transient_key);

void dave_session_reset(void *session);

void dave_session_set_protocol_version(void *session, uint16_t protocol_version);

uint16_t dave_session_get_protocol_version(void *session);

struct Buffer dave_session_get_last_epoch_authenticator(void *session);

void dave_session_set_external_sender(void *session, struct Buffer marshalled_external_sender);

struct Buffer dave_session_process_proposals(void *session, struct Buffer proposals, char **recognized_user_ids, size_t recognized_user_ids_count);

struct CommitProcessingResult dave_session_process_commit(void *session, struct Buffer commit);

void *dave_session_process_welcome(void *session, struct Buffer welcome, char **recognized_user_ids, size_t recognized_user_ids_count);

struct Buffer dave_session_get_marshalled_key_package(void *session);

struct HashRatchet dave_session_get_key_ratchet(void *session, char *user_id);

void dave_buffer_free(struct Buffer buffer);

void *dave_encryptor_create(void);

void dave_encryptor_free(void *encryptor);

void dave_encryptor_set_key_ratchet(void *encryptor, struct HashRatchet key_ratchet);

void dave_encryptor_set_passthrough_mode(void *encryptor, bool passthrough_mode);

void dave_encryptor_assign_ssrc_to_codec(void *encryptor, uint32_t ssrc, uint8_t codec_type);

uint16_t dave_encryptor_get_protocol_version(void *encryptor);

size_t dave_encryptor_get_max_ciphertext_byte_size(void *encryptor, uint8_t media_type, size_t frame_size);

size_t dave_encryptor_encrypt(void *encryptor, uint8_t media_type, uint32_t ssrc, struct Buffer frame, struct Buffer encrypted_frame);

void dave_encryptor_set_protocol_version_changed_callback(void *encryptor, void (*callback)(void));

void *dave_decryptor_create(void);

void dave_decryptor_free(void *decryptor);

void dave_decryptor_transition_to_key_ratchet(void *decryptor, struct HashRatchet key_ratchet, int64_t transition_expiry_seconds);

void dave_decryptor_transition_to_passthrough_mode(void *decryptor, bool passthrough_mode, int64_t transition_expiry_seconds);

size_t dave_decryptor_decrypt(void *decryptor, uint8_t media_type, struct Buffer encrypted_frame, struct Buffer frame);

size_t dave_decryptor_get_max_plaintext_byte_size(void *decryptor, uint8_t media_type, size_t encrypted_frame_size);

void *dave_transient_private_key_generate(uint16_t protocol_version);

void dave_transient_private_key_free(void *key);

struct Buffer dave_roster_map_find(void *roster_map, uint64_t key);

void dave_roster_map_free(void *roster_map);

void dave_commit_processing_result_free(struct CommitProcessingResult result);

void dave_hash_ratchet_free(struct HashRatchet hash_ratchet);

#ifdef __cplusplus
}
#endif
