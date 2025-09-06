#include <dave/common.h>
#include <dave/mls/session.h>
#include <dave/mls/parameters.h>
#include <dave/encryptor.h>
#include <dave/decryptor.h>
#include <dave/logger.h>
#include <cstring>

extern "C" {

extern const int DAVE_INIT_TRANSITION_ID = discord::dave::kInitTransitionId;

extern const int DAVE_DISABLED_VERSION = discord::dave::kDisabledVersion;

extern const uint8_t DAVE_MEDIA_TYPE_AUDIO = discord::dave::MediaType::Audio;

extern const uint8_t DAVE_MEDIA_TYPE_VIDEO = discord::dave::MediaType::Video;

extern const uint8_t DAVE_CODEC_UNKNOWN = discord::dave::Codec::Unknown;

extern const uint8_t DAVE_CODEC_OPUS = discord::dave::Codec::Opus;

extern const uint8_t DAVE_CODEC_VP8 = discord::dave::Codec::VP8;

extern const uint8_t DAVE_CODEC_VP9 = discord::dave::Codec::VP9;

extern const uint8_t DAVE_CODEC_H264 = discord::dave::Codec::H264;

extern const uint8_t DAVE_CODEC_H265 = discord::dave::Codec::H265;

extern const uint8_t DAVE_CODEC_AV1 = discord::dave::Codec::AV1;

struct Buffer {
    uint8_t* data;
    size_t size;
};

#ifdef __cplusplus
}
#endif

static Buffer buffer_from_vector(std::vector<uint8_t> vector) {
    Buffer buffer{};
    
    auto size = vector.size();
    auto data = (uint8_t*)malloc(size);
    if (data) {
        memcpy(data, vector.data(), size);
        buffer.data = data;
        buffer.size = size;
    }
    else {
        buffer.data = nullptr;
        buffer.size = 0;
    }

    return buffer;
}

static std::set<std::string> recognized_user_ids_to_set(char **recognized_user_ids, size_t recognized_user_ids_count) {
    std::set<std::string> set;
    for (size_t i = 0; i < recognized_user_ids_count; i++)
        set.insert(recognized_user_ids[i]);
    return set;
}

static std::vector<uint8_t> buffer_to_vector(Buffer buffer) {
    return std::vector<uint8_t>(buffer.data, buffer.data + buffer.size);
}

#ifdef __cplusplus
extern "C" {
#endif

struct HashRatchet {
    uint16_t cipher_suite;
    Buffer base_secret;
};

struct CommitProcessingResult {
    bool failed;
    bool ignored;
    void *roster_update;
};

uint16_t dave_max_supported_protocol_version(void) {
    return discord::dave::MaxSupportedProtocolVersion();
}

void *dave_session_create(char *context, char *auth_session_id, void (*mls_failure_callback)(const char*, const char*)) {
    discord::dave::mls::Session::MLSFailureCallback cppCallback = nullptr;
    if (mls_failure_callback) {
        cppCallback = [mls_failure_callback](const std::string& func, const std::string& reason) {
            mls_failure_callback(func.c_str(), reason.c_str());
        };
    }
    
    return new discord::dave::mls::Session(context, auth_session_id, cppCallback);
}

void dave_session_free(void *session) {
    delete (discord::dave::mls::Session*)session;
}

void dave_session_init(void *session, uint16_t protocol_version, uint64_t group_id, char *self_user_id, void *transient_key) {
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

Buffer dave_session_get_last_epoch_authenticator(void *session) {
    auto session_obj = (discord::dave::mls::Session*)session;
    
    auto result = session_obj->GetLastEpochAuthenticator();

    return buffer_from_vector(result);
}

void dave_session_set_external_sender(void *session, Buffer marshalled_external_sender) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto vector = buffer_to_vector(marshalled_external_sender);

    session_obj->SetExternalSender(vector);
}

Buffer dave_session_process_proposals(void *session, Buffer proposals, char **recognized_user_ids, size_t recognized_user_ids_count) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto proposals_vector = buffer_to_vector(proposals);

    auto set = recognized_user_ids_to_set(recognized_user_ids, recognized_user_ids_count);

    auto result = session_obj->ProcessProposals(proposals_vector, set);
    if (result)
        return buffer_from_vector(*result);

    return { nullptr, 0 };
}

CommitProcessingResult dave_session_process_commit(void *session, Buffer commit) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto commit_vector = buffer_to_vector(commit);

    auto result = session_obj->ProcessCommit(commit_vector);

    auto failed = std::holds_alternative<discord::dave::failed_t>(result);
    auto ignored = std::holds_alternative<discord::dave::ignored_t>(result);
    auto rosterUpdate = discord::dave::GetOptional<discord::dave::RosterMap>(std::move(result));

    auto rosterUpdatePtr = rosterUpdate
        ? new discord::dave::RosterMap(*rosterUpdate)
        : nullptr;

    return { failed, ignored, rosterUpdatePtr };
}

void *dave_session_process_welcome(void *session, Buffer welcome, char **recognized_user_ids, size_t recognized_user_ids_count){
    auto session_obj = (discord::dave::mls::Session*)session;

    auto welcome_vector = buffer_to_vector(welcome);

    auto set = recognized_user_ids_to_set(recognized_user_ids, recognized_user_ids_count);

    auto result = session_obj->ProcessWelcome(welcome_vector, set);
    if (result)
        return new discord::dave::RosterMap(*result);

    return nullptr;
}

Buffer dave_session_get_marshalled_key_package(void *session) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto result = session_obj->GetMarshalledKeyPackage();

    return buffer_from_vector(result);
}

HashRatchet dave_session_get_key_ratchet(void *session, char *user_id) {
    auto session_obj = (discord::dave::mls::Session*)session;

    auto result = session_obj->GetKeyRatchet(user_id);
    if (result) {
        auto hash_ratchet = result->GetHashRatchet();
        return { static_cast<uint16_t>(hash_ratchet.suite.cipher_suite()), buffer_from_vector(hash_ratchet.next_secret) };
    }

    return { 0, { nullptr, 0 } };
}

void *dave_encryptor_create(void) {
    return new discord::dave::Encryptor();
}

void dave_encryptor_free(void *encryptor) {
    delete (discord::dave::Encryptor*)encryptor;
}

void dave_encryptor_set_key_ratchet(void *encryptor, HashRatchet key_ratchet) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto cipher_suite = ::mlspp::CipherSuite(static_cast<::mlspp::CipherSuite::ID>(key_ratchet.cipher_suite));

    auto base_secret = buffer_to_vector(key_ratchet.base_secret);

    auto key_ratchet_ptr = std::make_unique<discord::dave::MlsKeyRatchet>(cipher_suite, base_secret);

    encryptor_obj->SetKeyRatchet(std::move(key_ratchet_ptr));
}

void dave_encryptor_set_passthrough_mode(void *encryptor, bool passthrough_mode) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    encryptor_obj->SetPassthroughMode(passthrough_mode);
}

void dave_encryptor_assign_ssrc_to_codec(void *encryptor, uint32_t ssrc, uint8_t codec_type) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto codec_type_obj = (discord::dave::Codec)codec_type;

    encryptor_obj->AssignSsrcToCodec(ssrc, codec_type_obj);
}

uint16_t dave_encryptor_get_protocol_version(void *encryptor) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    return encryptor_obj->GetProtocolVersion();
}

size_t dave_encryptor_get_max_ciphertext_byte_size(void *encryptor, uint8_t media_type, size_t frame_size) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    return encryptor_obj->GetMaxCiphertextByteSize(media_type_obj, frame_size);
}

size_t dave_encryptor_encrypt(void *encryptor, uint8_t media_type, uint32_t ssrc, Buffer frame, Buffer encrypted_frame) {
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

void dave_encryptor_set_protocol_version_changed_callback(void *encryptor, void (*callback)(void)) {
    auto encryptor_obj = (discord::dave::Encryptor*)encryptor;

    encryptor_obj->SetProtocolVersionChangedCallback([callback]() {
        callback();
    });
}

void *dave_decryptor_create(void) {
    return new discord::dave::Decryptor();
}

void dave_decryptor_free(void *decryptor) {
    delete (discord::dave::Decryptor*)decryptor;
}

void dave_decryptor_transition_to_key_ratchet(void *decryptor, HashRatchet key_ratchet, int64_t transition_expiry_seconds) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    auto cipher_suite = ::mlspp::CipherSuite(static_cast<::mlspp::CipherSuite::ID>(key_ratchet.cipher_suite));

    auto base_secret = buffer_to_vector(key_ratchet.base_secret);

    auto key_ratchet_ptr = std::make_unique<discord::dave::MlsKeyRatchet>(cipher_suite, base_secret);

    decryption_obj->TransitionToKeyRatchet(std::move(key_ratchet_ptr), std::chrono::seconds(transition_expiry_seconds));
}

void dave_decryptor_transition_to_passthrough_mode(void *decryptor, bool passthrough_mode, int64_t transition_expiry_seconds) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    decryption_obj->TransitionToPassthroughMode(passthrough_mode, std::chrono::seconds(transition_expiry_seconds));
}

size_t dave_decryptor_decrypt(void *decryptor, uint8_t media_type, Buffer encrypted_frame, Buffer frame) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    auto encrypted_frame_view = discord::dave::MakeArrayView((const uint8_t*)encrypted_frame.data, encrypted_frame.size);

    auto frame_view = discord::dave::MakeArrayView(frame.data, frame.size);

    return decryption_obj->Decrypt(media_type_obj, encrypted_frame_view, frame_view);
}

size_t dave_decryptor_get_max_plaintext_byte_size(void *decryptor, uint8_t media_type, size_t encrypted_frame_size) {
    auto decryption_obj = (discord::dave::Decryptor*)decryptor;

    auto media_type_obj = (discord::dave::MediaType)media_type;

    return decryption_obj->GetMaxPlaintextByteSize(media_type_obj, encrypted_frame_size);
}

void *dave_transient_private_key_generate(uint16_t protocol_version) {
    return new ::mlspp::SignaturePrivateKey(
        ::mlspp::SignaturePrivateKey::generate(
            ::discord::dave::mls::CiphersuiteForProtocolVersion(protocol_version)));
}

void dave_transient_private_key_free(void *key) {
    delete (::mlspp::SignaturePrivateKey*)key;
}

Buffer dave_roster_map_find(void *roster_map, uint64_t key) {
    auto roster = (discord::dave::RosterMap*)roster_map;
    auto it = roster->find(key);
    if (it == roster->end())
        return { nullptr, 0 };

    return buffer_from_vector(it->second);
}

void dave_roster_map_free(void *roster_map) {
    delete (discord::dave::RosterMap*)roster_map;
}

void dave_buffer_free(Buffer buffer) {
    free(buffer.data);
}

void dave_commit_processing_result_free(CommitProcessingResult result) {
    dave_roster_map_free(result.roster_update);
}

void dave_hash_ratchet_free(HashRatchet hash_ratchet) {
    dave_buffer_free(hash_ratchet.base_secret);
}

}
