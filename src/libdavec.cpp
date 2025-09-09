#include <dave/common.h>
#include <dave/mls/session.h>
#include <dave/mls/parameters.h>
#include <dave/encryptor.h>
#include <dave/decryptor.h>
#include <dave/logger.h>
#include <cstring>

extern "C" {

extern const int DAVE_INIT_TRANSITION_ID;

extern const int DAVE_DISABLED_VERSION;

typedef enum DaveMediaType : uint8_t {
    AUDIO = discord::dave::MediaType::Audio,
    VIDEO = discord::dave::MediaType::Video
} DaveMediaType;

typedef enum DaveCodec : uint8_t {
    UNKNOWN = discord::dave::Codec::Unknown,
    OPUS = discord::dave::Codec::Opus,
    VP8 = discord::dave::Codec::VP8,
    VP9 = discord::dave::Codec::VP9,
    H264 = discord::dave::Codec::H264,
    H265 = discord::dave::Codec::H265,
    AV1 = discord::dave::Codec::AV1
} DaveCodec;

extern const int DAVE_INIT_TRANSITION_ID = discord::dave::kInitTransitionId;

extern const int DAVE_DISABLED_VERSION = discord::dave::kDisabledVersion;

typedef struct DaveBuffer {
    uint8_t* data;
    size_t size;
} DaveBuffer;

#ifdef __cplusplus
}
#endif

static DaveBuffer buffer_from_vector(const std::vector<uint8_t>& vector) {
    auto size = vector.size();
    auto data = (uint8_t*)malloc(size);
    if (!data)
        return {};

    memcpy(data, vector.data(), size);
    return { data, size };
}

static std::set<std::string> recognized_user_ids_to_set(const char * const *recognized_user_ids, size_t recognized_user_ids_count) {
    std::set<std::string> set;
    for (size_t i = 0; i < recognized_user_ids_count; i++)
        set.insert(recognized_user_ids[i]);
    return std::move(set);
}

static std::vector<uint8_t> buffer_to_vector(DaveBuffer buffer) {
    return std::vector<uint8_t>(buffer.data, buffer.data + buffer.size);
}

#ifdef __cplusplus
extern "C" {
#endif

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

uint16_t dave_max_supported_protocol_version(void) {
    return discord::dave::MaxSupportedProtocolVersion();
}

void* dave_session_create(const char *context, const char *auth_session_id, DaveMlsFailureCallback mls_failure_callback) {
    discord::dave::mls::Session::MLSFailureCallback mls_failure_callback_obj;
    if (mls_failure_callback) {
        mls_failure_callback_obj = [mls_failure_callback](const std::string& func, const std::string& reason) {
            mls_failure_callback(func.c_str(), reason.c_str());
        };
    }
    else
        mls_failure_callback_obj = nullptr;
    
    return new discord::dave::mls::Session(context, auth_session_id, mls_failure_callback_obj);
}

void dave_session_free(void *session) {
    delete (discord::dave::mls::Session*)session;
}

void dave_session_init(void *session, uint16_t protocol_version, uint64_t group_id, const char *self_user_id, const void *transient_key) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto transient_key_obj = (::mlspp::SignaturePrivateKey*)transient_key;

    auto transient_key_ptr = std::shared_ptr<::mlspp::SignaturePrivateKey>(
        transient_key_obj, 
        [](::mlspp::SignaturePrivateKey*){}
    );

    session_obj->Init(protocol_version, group_id, self_user_id, transient_key_ptr);
}

void dave_session_reset(void *session) {
    auto session_obj = (discord::dave::mls::Session*)session;

    session_obj->Reset();
}

void dave_session_set_protocol_version(void *session, uint16_t protocol_version) {
    auto session_obj = (discord::dave::mls::Session*)session;

    session_obj->SetProtocolVersion(protocol_version);
}

uint16_t dave_session_get_protocol_version(const void *session) {
    auto session_obj = (const discord::dave::mls::Session*)session;

    return session_obj->GetProtocolVersion();
}

DaveBuffer dave_session_get_last_epoch_authenticator(const void *session) {
    auto session_obj = (const discord::dave::mls::Session*)session;
    
    auto result = session_obj->GetLastEpochAuthenticator();

    return buffer_from_vector(result);
}

void dave_session_set_external_sender(void *session, DaveBuffer marshalled_external_sender) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto vector = buffer_to_vector(marshalled_external_sender);

    session_obj->SetExternalSender(std::move(vector));
}

DaveBuffer dave_session_process_proposals(void *session, DaveBuffer proposals, const char * const *recognized_user_ids, size_t recognized_user_ids_count) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto proposals_vector = buffer_to_vector(proposals);

    auto set = recognized_user_ids_to_set(recognized_user_ids, recognized_user_ids_count);

    auto result = session_obj->ProcessProposals(std::move(proposals_vector), std::move(set));
    if (result)
        return buffer_from_vector(*result);

    return {};
}

DaveCommitProcessingResult dave_session_process_commit(void *session, DaveBuffer commit) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto commit_vector = buffer_to_vector(commit);

    auto result = session_obj->ProcessCommit(std::move(commit_vector));

    auto failed = std::holds_alternative<discord::dave::failed_t>(result);
    auto ignored = std::holds_alternative<discord::dave::ignored_t>(result);
    auto roster_update = discord::dave::GetOptional<discord::dave::RosterMap>(std::move(result));

    auto roster_update_ptr = roster_update
        ? new discord::dave::RosterMap(std::move(*roster_update))
        : nullptr;

    return { .failed = failed, .ignored = ignored, .roster_update = roster_update_ptr };
}

void* dave_session_process_welcome(void *session, DaveBuffer welcome, const char * const *recognized_user_ids, size_t recognized_user_ids_count){
    auto session_obj = (discord::dave::mls::Session*)session;

    auto welcome_vector = buffer_to_vector(welcome);

    auto set = recognized_user_ids_to_set(recognized_user_ids, recognized_user_ids_count);

    auto result = session_obj->ProcessWelcome(std::move(welcome_vector), std::move(set));
    if (result)
        return new discord::dave::RosterMap(std::move(*result));

    return nullptr;
}

DaveBuffer dave_session_get_marshalled_key_package(void *session) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto result = session_obj->GetMarshalledKeyPackage();

    return buffer_from_vector(result);
}

DaveHashRatchet dave_session_get_key_ratchet(const void *session, const char *user_id) {
    auto session_obj = (const discord::dave::mls::Session*)session;

    auto result = session_obj->GetKeyRatchet(user_id);
    if (result) {
        auto hash_ratchet = result->GetHashRatchet();
        return { static_cast<uint16_t>(hash_ratchet.suite.cipher_suite()), buffer_from_vector(hash_ratchet.next_secret) };
    }

    return {};
}

void* dave_encryptor_create(void) {
    return new discord::dave::Encryptor();
}

void dave_encryptor_free(void *encryptor) {
    delete (discord::dave::Encryptor*)encryptor;
}

void dave_encryptor_set_key_ratchet(void *encryptor, DaveHashRatchet key_ratchet) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto cipher_suite = ::mlspp::CipherSuite(static_cast<::mlspp::CipherSuite::ID>(key_ratchet.cipher_suite));

    auto base_secret = buffer_to_vector(key_ratchet.base_secret);

    auto key_ratchet_ptr = std::make_unique<discord::dave::MlsKeyRatchet>(cipher_suite, std::move(base_secret));

    encryptor_obj->SetKeyRatchet(std::move(key_ratchet_ptr));
}

void dave_encryptor_set_passthrough_mode(void *encryptor, bool passthrough_mode) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    encryptor_obj->SetPassthroughMode(passthrough_mode);
}

void dave_encryptor_assign_ssrc_to_codec(void *encryptor, uint32_t ssrc, DaveCodec codec_type) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto codec_type_obj = (discord::dave::Codec)codec_type;

    encryptor_obj->AssignSsrcToCodec(ssrc, codec_type_obj);
}

uint16_t dave_encryptor_get_protocol_version(const void *encryptor) {
    auto encryptor_obj = (const discord::dave::Encryptor*)encryptor;

    return encryptor_obj->GetProtocolVersion();
}

size_t dave_encryptor_get_max_ciphertext_byte_size(void *encryptor, DaveMediaType media_type, size_t frame_size) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    return encryptor_obj->GetMaxCiphertextByteSize(media_type_obj, frame_size);
}

size_t dave_encryptor_encrypt(void *encryptor, DaveMediaType media_type, uint32_t ssrc, DaveBuffer frame, DaveBuffer encrypted_frame) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    auto frame_view = discord::dave::MakeArrayView((const uint8_t*)frame.data, frame.size);

    auto encrypted_frame_view = discord::dave::MakeArrayView(encrypted_frame.data, encrypted_frame.size);

    size_t bytes_written;
    auto result = encryptor_obj->Encrypt(media_type_obj, ssrc, frame_view, encrypted_frame_view, &bytes_written);

    if (result != 0)
        return 0;

    return bytes_written;
}

void dave_encryptor_set_protocol_version_changed_callback(void *encryptor, DaveProtocolVersionChangedCallback callback) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    encryptor_obj->SetProtocolVersionChangedCallback([callback]() {
        callback();
    });
}

void* dave_decryptor_create(void) {
    return new discord::dave::Decryptor();
}

void dave_decryptor_free(void *decryptor) {
    delete (discord::dave::Decryptor*)decryptor;
}

void dave_decryptor_transition_to_key_ratchet(void *decryptor, DaveHashRatchet key_ratchet, int64_t transition_expiry_seconds) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    auto cipher_suite = ::mlspp::CipherSuite(static_cast<::mlspp::CipherSuite::ID>(key_ratchet.cipher_suite));

    auto base_secret = buffer_to_vector(key_ratchet.base_secret);

    auto key_ratchet_ptr = std::make_unique<discord::dave::MlsKeyRatchet>(cipher_suite, std::move(base_secret));

    decryption_obj->TransitionToKeyRatchet(std::move(key_ratchet_ptr), std::chrono::seconds(transition_expiry_seconds));
}

void dave_decryptor_transition_to_passthrough_mode(void *decryptor, bool passthrough_mode, int64_t transition_expiry_seconds) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    decryption_obj->TransitionToPassthroughMode(passthrough_mode, std::chrono::seconds(transition_expiry_seconds));
}

size_t dave_decryptor_decrypt(void *decryptor, DaveMediaType media_type, DaveBuffer encrypted_frame, DaveBuffer frame) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    auto encrypted_frame_view = discord::dave::MakeArrayView((const uint8_t*)encrypted_frame.data, encrypted_frame.size);

    auto frame_view = discord::dave::MakeArrayView(frame.data, frame.size);

    return decryption_obj->Decrypt(media_type_obj, encrypted_frame_view, frame_view);
}

size_t dave_decryptor_get_max_plaintext_byte_size(void *decryptor, DaveMediaType media_type, size_t encrypted_frame_size) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    return decryption_obj->GetMaxPlaintextByteSize(media_type_obj, encrypted_frame_size);
}

void* dave_transient_private_key_generate(uint16_t protocol_version) {
    return new ::mlspp::SignaturePrivateKey(
        ::mlspp::SignaturePrivateKey::generate(
            ::discord::dave::mls::CiphersuiteForProtocolVersion(protocol_version)));
}

void dave_transient_private_key_free(void *key) {
    delete (::mlspp::SignaturePrivateKey*)key;
}

DaveBuffer dave_roster_map_find(const void *roster_map, uint64_t key) {
    auto roster = (const discord::dave::RosterMap*)roster_map;
    auto it = roster->find(key);
    if (it == roster->end())
        return {};

    return buffer_from_vector(it->second);
}

void dave_roster_map_free(void *roster_map) {
    delete (discord::dave::RosterMap*)roster_map;
}

void dave_buffer_free(DaveBuffer buffer) {
    free(buffer.data);
}

void dave_commit_processing_result_free(DaveCommitProcessingResult result) {
    dave_roster_map_free(result.roster_update);
}

void dave_hash_ratchet_free(DaveHashRatchet hash_ratchet) {
    dave_buffer_free(hash_ratchet.base_secret);
}

}
