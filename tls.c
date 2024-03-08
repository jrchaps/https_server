#include "certificate.h"

slice copy_u16_be(slice out, u16 in) {
    u16_to_be(out.items, in);
    out = slice_cut(out, 0, 2);
    return out;
}

slice append_u16_be(slice out, u16 in) {
    u16_to_be(out.items + out.length, in);
    out = slice_up(out, 2);
    return out;
}

slice append_random(slice out, size_t length) {
    crypto_random(out.items + out.length, (u32) length);
    out = slice_up(out, length);
    return out;
}

slice read(slice* in, slice out) {
    if (out.length > in->length) {
        out = slice_cut(out, 0, in->length);
    }

    for (size_t i = 0; i < out.length; i += 1) {
        out.items[i] = in->items[i];
    }

    *in = slice_cut(*in, out.length, in->length);

    return out;
} 

#define curve25519_key_length 32
#define chacha20_key_length 32
#define chacha20_nonce_length 12
#define poly1305_auth_tag_length 16

typedef struct tls_ctx tls_ctx;
struct tls_ctx {
    u8 encryption_key[chacha20_key_length];
    u8 encryption_nonce[chacha20_nonce_length];
    u64 encryption_count;
    u8 decryption_key[chacha20_key_length];
    u8 decryption_nonce[chacha20_nonce_length];
    u64 decryption_count;
    u8 handshake_secret[sha256_hash_length];
    u8 encryption_secret[sha256_hash_length];
    u8 decryption_secret[sha256_hash_length];
    u8 transcript_hash[sha256_hash_length];
};

slice tls_derived_secret_info = slice_alloc(49);
u8 tls_derived_secret[sha256_hash_length];

// todo: This only works single-threaded. These should be treated as read-only
// when multi-threading. Either each thread will need it's own copy of these
// or the key schedule function must copy the slices before appending to them. 
// Ideally these are generated at compile time, but it shouldn't be a big deal either way.
slice tls_handshake_encryption_secret_info = slice_alloc(54);
slice tls_handshake_decryption_secret_info = slice_alloc(54);
slice tls_encryption_secret_info = slice_alloc(54);
slice tls_decryption_secret_info = slice_alloc(54);
slice tls_key_info = slice_alloc(13);
slice tls_iv_info = slice_alloc(12);
slice tls_finished_info = slice_alloc(18);
slice tls_signature_message = slice_alloc(130);

void tls_xor_nonce(
    u8 out[chacha20_nonce_length], 
    u8 nonce[chacha20_nonce_length], 
    u64 record_count
) {
    size_t padding_length = chacha20_nonce_length - 8;
    for (size_t i = 0; i < padding_length; i += 1) {
        out[i] = nonce[i];
    }
    u8 count[8];
    u64_to_be(count, record_count);
    for (size_t i = 0; i < 8; i += 1) {
        out[i + padding_length] = nonce[i + padding_length] ^ count[i];
    }
}

typedef struct tls_record_ctx tls_record_ctx;
struct tls_record_ctx {
    u8 error;
    slice header;
    slice type;
    slice fragment;
    slice after;
};

tls_record_ctx tls_decode_record(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-59

    tls_record_ctx record;

    size_t header_length = 5;
    record.header = next(&in, header_length);
    if (record.header.length != header_length) {
        record.error = 1; // decode_error
        return record;
    }

    size_t type_length = 1;    
    record.type = slice_cut(record.header, 0, type_length);

    size_t legacy_version_length = 2;
    slice legacy_version = slice_cut(
        record.type,
        record.type.length,
        record.type.length +
        legacy_version_length
    );

    size_t fragment_length_length = 2;
    slice fragment_length = slice_cut(
        legacy_version,
        legacy_version.length,
        legacy_version.length +
        fragment_length_length
    );

    size_t decoded_length = be_to_u16(fragment_length.items);
    record.fragment = next(&in, decoded_length);
    if (record.fragment.length != decoded_length) {
        record.error = 1; // decode_error
        return record;
    }

    record.error = 0;
    record.after = in;
    return record;
}

tls_record_ctx tls_decrypt_record(tls_record_ctx record, tls_ctx* tls) {
    if (record.fragment.length < poly1305_auth_tag_length) {
        record.error = 1; // bad_record_mac
        return record;
    }

    slice auth_tag = slice_cut(
        record.fragment,
        record.fragment.length - poly1305_auth_tag_length,
        record.fragment.length
    );

    record.fragment = slice_cut(
        record.fragment,
        0,
        record.fragment.length - poly1305_auth_tag_length
    );

    u8 nonce[chacha20_nonce_length];
    tls_xor_nonce(
        nonce, 
        tls->decryption_nonce, 
        tls->decryption_count
    );

    int error = chacha20_poly1305_decrypt(
        record.fragment,
        tls->decryption_key,
        nonce,
        record.header,
        auth_tag.items 
    );

    if (error) {
        record.error = 1; // bad_record_mac
        return record;
    }

    tls->decryption_count += 1;

    while (true) {
        if (!record.fragment.length) {
            record.error = 1; // decode_error
            return record;
        }
        if (record.fragment.items[record.fragment.length - 1]) {
            break;
        }
        record.fragment = slice_down(record.fragment, 1);
    }

    record.type = slice_cut(record.fragment, record.fragment.length - 1, record.fragment.length);
    //record.type = record.fragment.items[record.fragment.length - 1]; 
    record.fragment = slice_down(record.fragment, 1);

    return record;
}

tls_record_ctx tls_decode_encrypted_record(slice cargo, tls_ctx* tls) {
    tls_record_ctx record = tls_decode_record(cargo);
    if (record.error) {
        return record;
    }

    record = tls_decrypt_record(record, tls);

    return record;
}

slice tls_record_begin(slice in, u8 type) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-59

    slice out = slice_end(in);
    out = append_item(out, type);
    u8 version[2] = { 0x03, 0x03 };
    out = append_length(out, version, array_length(version));
    out = slice_up(out, 2);

    return out;
}

slice tls_record_end(slice in) {
    slice body = slice_cut(in, 5, in.length);
    u16_to_be(&in.items[3], (u16) body.length);

    return in;
}

slice tls_encrypted_record_begin(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-60

    slice out = slice_end(in);
    out = append_item(out, 23);
    u8 version[2] = { 0x03, 0x03 };
    out = append_length(out, version, array_length(version));
    out = slice_up(out, 2);

    return out;
}

slice tls_encrypted_record_end(slice in, u8 type, tls_ctx* tls) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-60

    slice header = slice_cut(in, 0, 5);
    slice body = slice_cut(in, header.length, in.length);
    body = append_item(body, type);

    u16 length = (u16) body.length + poly1305_auth_tag_length;
    u16_to_be(&in.items[3], length);

    u8 nonce[chacha20_nonce_length];
    tls_xor_nonce(
        nonce, 
        tls->encryption_nonce, 
        tls->encryption_count
    );
    tls->encryption_count += 1;

    body = chacha20_poly1305_encrypt(
        body,
        tls->encryption_key, 
        nonce,
        header
    );

    in = slice_up(header, body.length);
    return in;
}

typedef struct tls_handshake_ctx tls_handshake_ctx;
struct tls_handshake_ctx {
    u8 error;
    slice type;
    slice message;
    slice after;
};

tls_handshake_ctx tls_decode_handshake(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-18

    tls_handshake_ctx handshake;

    size_t type_length = 1;
    handshake.type = next(&in, type_length);
    if (handshake.type.length != type_length) {
        handshake.error = 1; // decode_error
        return handshake;
    }

    size_t message_length_length = 3;
    slice message_length = next(&in, message_length_length);
    if (message_length.length != message_length_length) {
        handshake.error = 1; // decode_error
        return handshake;
    }

    if (message_length.items[0]) {
        handshake.error = 1; // decode_error
        return handshake;
    }

    message_length = slice_bump(message_length, 1);

    size_t decoded_length = be_to_u16(message_length.items);
    handshake.message = next(&in, decoded_length);
    if (handshake.message.length != decoded_length) {
        handshake.error = 1; // decode_error
        return handshake;
    }

    handshake.error = 0;
    handshake.after = in;
    return handshake;
}

slice tls_handshake_begin(slice in, u8 type) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-94

    slice out = slice_end(in);
    out = append_item(out, type);
    out = slice_up(out, 3);

    return out;
}

slice tls_handshake_end(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-94

    slice body = slice_cut(in, 4, in.length);
    in.items[1] = 0;
    u16_to_be(&in.items[2], (u16) body.length);

    return in;
}

u8 tls_verify_handshake_finished(tls_handshake_ctx handshake, tls_ctx tls) {
    // todo. fix this
    u8 finished_key[sha256_hash_length];
    hkdf_expand_sha256(
        finished_key,
        sha256_hash_length,
        array_to_slice(tls.decryption_secret),
        tls_finished_info
    );

    u8 verify_data[sha256_hash_length];
    hmac_sha256(
        verify_data,
        array_to_slice(finished_key),
        array_to_slice(tls.transcript_hash)
    );

    if (!slices_equal(handshake.message, array_to_slice(verify_data))) {
        return 1; // decrypt_error
    }

    return 0;
}

typedef struct tls_extension_ctx tls_extension_ctx;
struct tls_extension_ctx {
    u8 error;
    slice type;
    slice body;
};

tls_extension_ctx tls_decode_extension(slice* in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-24

    tls_extension_ctx extension;

    size_t type_length = 2;
    extension.type = next(in, type_length);
    if (extension.type.length != type_length) {
        extension.error = 1; // decode_error
        return extension;
    }

    size_t body_length_length = 2;
    slice body_length = next(in, body_length_length);
    if (body_length.length != body_length_length) {
        extension.error = 1; // decode_error
        return extension;
    } 
    size_t decoded_length = be_to_u16(body_length.items);
    extension.body = next(in, decoded_length);
    if (extension.body.length != decoded_length) {
        extension.error = 1; // decode_error
        return extension;
    }

    extension.error = 0;
    return extension;
}

slice tls_extension_set_begin(slice in) {
    slice out = slice_end(in);
    out = slice_up(out, 2);

    return out;
}

slice tls_extension_set_end(slice in) {
    slice body = slice_cut(in, 2, in.length);
    u16_to_be(&in.items[0], (u16) body.length);

    return in;
}

slice tls_extension_begin(slice in, u8 type[2]) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-24

    slice out = slice_end(in);
    out = append_length(out, type, 2);
    out = slice_up(out, 2);

    return out;
}

slice tls_extension_end(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-24

    slice body = slice_cut(in, 4, in.length); 
    u16_to_be(&in.items[2], (u16) body.length);

    return in;
}

typedef struct tls_key_share_ctx tls_key_share_ctx;
struct tls_key_share_ctx {
    u8 error;
    slice keys;
};

tls_key_share_ctx tls_decode_key_share(slice* in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-32

    tls_key_share_ctx key_share;

    size_t keys_length_length = 2;
    slice keys_length = next(in, keys_length_length);
    if (keys_length.length != keys_length_length) {
        key_share.error = 1; // decode_error
        return key_share;
    } 

    size_t decoded_length = be_to_u16(keys_length.items);
    key_share.keys = next(in, decoded_length);
    if (key_share.keys.length != decoded_length) {
        key_share.error = 1; // decode_error
        return key_share;
    }

    key_share.error = 0;
    return key_share;
}

typedef struct tls_key_ctx tls_key_ctx;
struct tls_key_ctx {
    u8 error;
    slice group;
    slice body;
};

tls_key_ctx tls_decode_key(slice* in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-32

    tls_key_ctx key;

    size_t group_length = 2;
    key.group = next(in, group_length);
    if (key.group.length != group_length) {
        key.error = 1; // decode_error
        return key;
    }

    size_t body_length_length = 2;
    slice body_length = next(in, body_length_length);
    if (body_length.length != body_length_length) {
        key.error = 1; // decode_error
        return key;
    }

    size_t decoded_length = be_to_u16(body_length.items);
    key.body = next(in, decoded_length); 
    if (key.body.length != decoded_length) {
        key.error = 1; // decode_error
        return key;
    }

    key.error = 0;
    return key;
}

u8 tls_decode_curve25519_key(slice* in, u8 out[curve25519_key_length]) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-32

    while (in->length) {
        tls_key_ctx key = tls_decode_key(in);
        if (key.error) {
            return key.error;
        }

        slice curve25519 = slice_literal(0x00, 0x1d);
        if (!slices_equal(key.group, curve25519)) {
            continue;
        }

        if (key.body.length != curve25519_key_length) {
            return 1; // handshake_failure
        }

        for (size_t i = 0; i < key.body.length; i += 1) {
            out[i] = key.body.items[i];
        }

        return 0;
    }

    return 1; // handshake_failure
}

slice tls_certificate_list_begin(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-46

    slice out = slice_end(in);
    out = slice_up(out, 3);

    return out;
}

slice tls_certificate_list_end(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-46

    slice body = slice_cut(in, 3, in.length);
    in.items[0] = 0;
    u16_to_be(&in.items[1], (u16) body.length);

    return in;
}

slice tls_signature_begin(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-51

    slice out = slice_end(in);
    out = slice_up(out, 2);

    return out;
}

slice tls_signature_end(slice in) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-51

    slice body = slice_cut(in, 2, in.length);
    u16_to_be(&in.items[0], (u16) body.length);

    return in;
}

u8 tls_decode_client_hello(
    slice cargo,
    sha256_ctx* transcript_hash_ctx,
    u8 public_key[curve25519_key_length],
    slice* session_id
) {
    tls_record_ctx record = tls_decode_record(cargo);
    if (record.error) {
        return record.error;
    }

    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, record.fragment);

    tls_handshake_ctx handshake = tls_decode_handshake(record.fragment);
    if (handshake.error) {
        return handshake.error;
    }

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-21

    size_t version_length = 2;
    slice version = next(&handshake.message, version_length);
    if (version.length != version_length) {
        return 1; // decode_error
    }

    size_t random_length = 32;
    slice random = next(&handshake.message, random_length);
    if (random.length != random_length) {
        return 1; // decode_error
    }

    size_t session_id_length_length = 1;
    slice session_id_length = next(&handshake.message, session_id_length_length); 
    if (session_id_length.length != session_id_length_length) {
        return 1; // decode_error
    } 
    size_t decoded_length = session_id_length.items[0];
    if (decoded_length > 32) {
        return 1; // decode_error
    }
    *session_id = slice_cut(*session_id, 0, decoded_length);
    *session_id = read(&handshake.message, *session_id);
    if (session_id->length != decoded_length) {
        return 1; // decode_error
    }

    size_t ciphers_length_length = 2;
    slice ciphers_length = next(&handshake.message, ciphers_length_length);
    if (ciphers_length.length != ciphers_length_length) {
        return 1; // decode_error
    }
    decoded_length = be_to_u16(ciphers_length.items);
    slice ciphers = next(&handshake.message, decoded_length);
    if (ciphers.length != decoded_length) {
        return 1; // decode_error
    }

    size_t compression_length_length = 1;
    slice compression_length = next(&handshake.message, compression_length_length);
    if (compression_length.length != compression_length_length) {
        return 1; // decode_error
    }
    decoded_length = compression_length.items[0];
    slice compression = next(&handshake.message, decoded_length);
    if (compression.length != decoded_length) {
        return 1; // decode_error
    }

    size_t extensions_length_length = 2;
    slice extensions_length = next(&handshake.message, extensions_length_length);
    if (extensions_length.length != extensions_length_length) {
        return 1; // decode_error
    }
    decoded_length = be_to_u16(extensions_length.items);
    slice extensions = next(&handshake.message, decoded_length);
    if (extensions.length != decoded_length) {
        return 1; // decode_error
    }

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-24

    while (extensions.length) {
        tls_extension_ctx extension = tls_decode_extension(&extensions);
        if (extension.error) {
            return extension.error;
        }

        slice extension_type_key_share = slice_literal(0, 51);
        if (slices_equal(extension.type, extension_type_key_share)) {
            tls_key_share_ctx key_share = tls_decode_key_share(&extension.body);
            if (key_share.error) {
                return key_share.error;
            }

            u8 error = tls_decode_curve25519_key(
                &key_share.keys,
                public_key
            );

            if (error) {
                return error;
            }
        }
    }

    return 0;
}

slice tls_append_server_hello(
    slice cargo,
    sha256_ctx* transcript_hash_ctx,
    u8 private_key[curve25519_key_length],
    slice session_id
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-22

    slice record = tls_record_begin(cargo, 22);

    slice handshake = tls_handshake_begin(record, 2);

    u8 legacy_version[2] = { 0x03, 0x03 };
    handshake = append_length(handshake, legacy_version, array_length(legacy_version));
    u8 tls_hello_random_length = 32;
    handshake = append_random(handshake, tls_hello_random_length);
    handshake = append_item(handshake, (u8) session_id.length);
    handshake = append(handshake, session_id);
    u8 cipher_suite[2] = { 0x13, 0x03 };
    handshake = append_length(handshake, cipher_suite, array_length(cipher_suite));
    handshake = append_item(handshake, 0); // legacy compression method;
    
    slice extension_set = tls_extension_set_begin(handshake);

    u8 supported_version_type[2] = { 0, 43 };
    slice supported_version = tls_extension_begin(extension_set, supported_version_type);
    u8 version[2] = { 0x03, 0x04 };
    supported_version = append_length(supported_version, version, array_length(version));
    supported_version = tls_extension_end(supported_version);
    extension_set = slice_up(extension_set, supported_version.length);

    u8 key_share_type[2] = { 0, 51 };
    slice key_share = tls_extension_begin(extension_set, key_share_type);
    u8 group_x25519[2] = { 0x00, 0x1d };
    key_share = append_length(key_share, group_x25519, array_length(group_x25519));
    key_share = append_u16_be(key_share, curve25519_key_length);
    crypto_random(private_key, curve25519_key_length);
    curve25519_scale_base(&key_share.items[key_share.length], private_key);
    key_share = slice_up(key_share, curve25519_key_length);
    key_share = tls_extension_end(key_share);
    extension_set = slice_up(extension_set, key_share.length);

    extension_set = tls_extension_set_end(extension_set);
    handshake = slice_up(handshake, extension_set.length);

    handshake = tls_handshake_end(handshake);
    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, handshake);
    record = slice_up(record, handshake.length);

    record = tls_record_end(record);
    cargo = slice_up(cargo, record.length);

    return cargo;
}

tls_ctx tls_handshake_cipher_keys(
    tls_ctx tls, 
    sha256_ctx transcript_hash_ctx, 
    u8 public_key[curve25519_key_length],
    u8 private_key[curve25519_key_length]
) {
    sha256_end(transcript_hash_ctx, tls.transcript_hash);

    u8 shared_secret[curve25519_key_length];
    curve25519_scale(shared_secret, private_key, public_key);

    hkdf_extract_sha256(
        tls.handshake_secret,
        array_to_slice(shared_secret),
        array_to_slice(tls_derived_secret)
    );

    slice encryption_secret_info = append_length(
        tls_handshake_encryption_secret_info,
        tls.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        tls.encryption_secret,
        sha256_hash_length,
        array_to_slice(tls.handshake_secret),
        encryption_secret_info
    );

    hkdf_expand_sha256(
        tls.encryption_key,
        chacha20_key_length,
        array_to_slice(tls.encryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        tls.encryption_nonce,
        chacha20_nonce_length,
        array_to_slice(tls.encryption_secret),
        tls_iv_info
    );

    slice decryption_secret_info = append_length(
        tls_handshake_decryption_secret_info,
        tls.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        tls.decryption_secret,
        sha256_hash_length,
        array_to_slice(tls.handshake_secret),
        decryption_secret_info
    );

    hkdf_expand_sha256(
        tls.decryption_key,
        chacha20_key_length,
        array_to_slice(tls.decryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        tls.decryption_nonce,
        chacha20_nonce_length,
        array_to_slice(tls.decryption_secret),
        tls_iv_info
    );

    return tls;
}

tls_ctx tls_cipher_keys(tls_ctx tls) {

    u8 derived_secret[sha256_hash_length];
    hkdf_expand_sha256(
        derived_secret,
        sha256_hash_length,
        array_to_slice(tls.handshake_secret),
        tls_derived_secret_info
    );

    slice zeros = slice_alloc(sha256_hash_length);
    zeros = slice_up(zeros, sha256_hash_length);

    u8 master_secret[sha256_hash_length];
    hkdf_extract_sha256(
        master_secret,
        zeros,
        array_to_slice(derived_secret)
    );

    slice encryption_secret_info = append_length(
        tls_encryption_secret_info,
        tls.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        tls.encryption_secret,
        sha256_hash_length,
        array_to_slice(master_secret),
        encryption_secret_info
    );

    hkdf_expand_sha256(
        tls.encryption_key,
        chacha20_key_length,
        array_to_slice(tls.encryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        tls.encryption_nonce,
        chacha20_nonce_length,
        array_to_slice(tls.encryption_secret),
        tls_iv_info
    );

    slice decryption_secret_info = append_length(
        tls_decryption_secret_info,
        tls.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        tls.decryption_secret,
        sha256_hash_length,
        array_to_slice(master_secret),
        decryption_secret_info
    );

    hkdf_expand_sha256(
        tls.decryption_key,
        chacha20_key_length,
        array_to_slice(tls.decryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        tls.decryption_nonce,
        chacha20_nonce_length,
        array_to_slice(tls.decryption_secret),
        tls_iv_info
    );

    return tls;
}

slice tls_append_change_cipher_spec(slice cargo) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-115
    
    u8 tls_record_type_change_cipher_spec = 20;
    cargo = append_item(cargo, tls_record_type_change_cipher_spec);

    u8 tls_legacy_version[2] = { 0x03, 0x03 };
    cargo = append_length(cargo, tls_legacy_version, array_length(tls_legacy_version));

    u8 length[2] = { 0, 1 };
    cargo = append_length(cargo, length, array_length(length));

    u8 value = 1;
    cargo = append_item(cargo, value);

    return cargo;
}

slice tls_append_encrypted_extensions(
    slice cargo,
    tls_ctx* tls,
    sha256_ctx* transcript_hash_ctx
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-42

    slice record = tls_encrypted_record_begin(cargo);

    slice handshake = tls_handshake_begin(record, 8);
    slice value = slice_literal(0, 0);
    handshake = append(handshake, value);
    handshake = tls_handshake_end(handshake);
    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, handshake);

    record = slice_up(record, handshake.length);
    tls->encryption_count = 0;
    record = tls_encrypted_record_end(record, 22, tls);

    cargo = slice_up(cargo, record.length);

    return cargo;
} 

slice tls_append_certificate(
    slice cargo,
    tls_ctx* tls,
    sha256_ctx* transcript_hash_ctx
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-46

    slice record = tls_encrypted_record_begin(cargo);

    u8 tls_handshake_type_certificate = 11;
    slice handshake = tls_handshake_begin(record, tls_handshake_type_certificate);

    u8 request_context = 0;
    handshake = append_item(handshake, request_context);

    slice list = tls_certificate_list_begin(handshake);
    list = append_item(list, 0);
    list = append_u16_be(list, (u16) tls_certificate.length);
    list = append(list, tls_certificate);
    u8 extensions_length[2] = { 0, 0 };
    list = append_length(list, extensions_length, array_length(extensions_length));
    list = tls_certificate_list_end(list);
    handshake = slice_up(handshake, list.length);

    handshake = tls_handshake_end(handshake);
    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, handshake);
    record = slice_up(record, handshake.length);

    record = tls_encrypted_record_end(record, 22, tls);

    cargo = slice_up(cargo, record.length);

    return cargo;
}

slice tls_append_certificate_verify(
    slice cargo,
    tls_ctx* tls,
    sha256_ctx* transcript_hash_ctx
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-51

    slice record = tls_encrypted_record_begin(cargo);

    u8 tls_handshake_type_certificate_verify = 15;
    slice handshake = tls_handshake_begin(record, tls_handshake_type_certificate_verify);

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-27
    u8 signature_algorithm[2] = { 0x04, 0x03 };
    handshake = append_length(handshake, signature_algorithm, array_length(signature_algorithm));

    sha256_end(*transcript_hash_ctx, tls->transcript_hash);
    slice ecdsa_message = append_length(tls_signature_message, tls->transcript_hash, array_length(tls->transcript_hash));
    slice signature = tls_signature_begin(handshake);

    slice sig = slice_end(signature);
    sig = ecdsa_secp256r1_sha256(
        sig,
        tls_certificate_key,
        ecdsa_message
    );
    signature = slice_up(signature, sig.length);

    signature = tls_signature_end(signature);
    handshake = slice_up(handshake, signature.length);

    handshake = tls_handshake_end(handshake);
    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, handshake);
    record = slice_up(record, handshake.length);

    record = tls_encrypted_record_end(record, 22, tls);
    cargo = slice_up(cargo, record.length);

    return cargo;
}

slice tls_append_handshake_finished(
    slice cargo,
    tls_ctx* tls,
    sha256_ctx transcript_hash_ctx
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-52

    slice record = tls_encrypted_record_begin(cargo);

    u8 tls_handshake_type_finished = 20;
    slice handshake = tls_handshake_begin(record, tls_handshake_type_finished);

    u8 finished_key[sha256_hash_length];
    hkdf_expand_sha256(
        finished_key,
        sha256_hash_length,
        array_to_slice(tls->encryption_secret),
        tls_finished_info
    );

    sha256_end(transcript_hash_ctx, tls->transcript_hash);

    u8 verify_data[sha256_hash_length];
    hmac_sha256(
        verify_data,
        array_to_slice(finished_key),
        array_to_slice(tls->transcript_hash)
    );

    handshake = append_length(handshake, verify_data, array_length(verify_data));
    handshake = tls_handshake_end(handshake);
    transcript_hash_ctx = sha256_run(transcript_hash_ctx, handshake);
    sha256_end(transcript_hash_ctx, tls->transcript_hash);
    record = slice_up(record, handshake.length);

    record = tls_encrypted_record_end(record, 22, tls); 
    cargo = slice_up(cargo, record.length);

    return cargo;
}

u8 tls_process_handshake(tls_ctx* ctx, slice* cargo) {
    sha256_ctx transcript_hash_ctx = sha256_begin();

    u8 public_key[curve25519_key_length];
    slice session_id = slice_alloc(32);
    u8 error = tls_decode_client_hello(
        *cargo,
        &transcript_hash_ctx,
        public_key,
        &session_id
    );

    if (error) {
        return error;
    }

    u8 private_key[curve25519_key_length];
    *cargo = slice_clear(*cargo);
    *cargo = tls_append_server_hello(
        *cargo,
        &transcript_hash_ctx,
        private_key,
        session_id
    );

    *ctx = tls_handshake_cipher_keys(
        *ctx,
        transcript_hash_ctx,
        public_key,
        private_key
    );

    *cargo = tls_append_change_cipher_spec(*cargo);

    *cargo = tls_append_encrypted_extensions(
        *cargo,
        ctx,
        &transcript_hash_ctx
    );

    *cargo = tls_append_certificate(
        *cargo,
        ctx,
        &transcript_hash_ctx
    );

    *cargo = tls_append_certificate_verify(
        *cargo,
        ctx,
        &transcript_hash_ctx
    );

    *cargo = tls_append_handshake_finished(
        *cargo,
        ctx,
        transcript_hash_ctx
    );

    return 0;
}

slice tls_make_derived_secret_info(slice info) {
    slice empty = slice_make(0, 0, 0);
    u8 empty_hash[sha256_hash_length];
    sha256(empty_hash, empty);

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 derived");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    info = append_length(info, empty_hash, sha256_hash_length);
    assert(info.length == info.capacity);

    return info;
}

void tls_make_derived_secret(u8 tls_derived_secret[sha256_hash_length]) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    slice zeros = slice_alloc(sha256_hash_length);
    zeros = slice_up(zeros, sha256_hash_length);

    slice early_secret = slice_alloc(sha256_hash_length);
    hkdf_extract_sha256(early_secret.items, zeros, zeros);
    early_secret = slice_up(early_secret, sha256_hash_length);

    hkdf_expand_sha256(
        tls_derived_secret,
        sha256_hash_length,
        early_secret,
        tls_derived_secret_info
    );
}

slice tls_make_handshake_encryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 s hs traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice tls_make_handshake_decryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 c hs traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice tls_make_encryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 s ap traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice tls_make_decryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 c ap traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice tls_make_key_info(slice info) {
    //https://datatracker.ietf.org/doc/html/rfc8446#autoid-69

    info = copy_u16_be(info, chacha20_key_length);
    slice label = string_to_slice("tls13 key");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    u8 context_length = 0;
    info = append_item(info, context_length);
    assert(info.length == info.capacity);

    return info;
}

slice tls_make_iv_info(slice info) {
    //https://datatracker.ietf.org/doc/html/rfc8446#autoid-69

    info = copy_u16_be(info, chacha20_nonce_length);
    slice label = string_to_slice("tls13 iv");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    u8 context_length = 0;
    info = append_item(info, context_length);
    assert(info.length == info.capacity);
    
    return info;
}

slice tls_make_finished_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-52

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 finished"); 
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    u8 context_length = 0;
    info = append_item(info, context_length);
    assert(info.length == info.capacity);

    return info;
}

slice tls_make_signature_message(slice message) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-51

    for (size_t i = 0; i < 64; i += 1) {
        message = append_item(message, ' ');
    }

    slice context = string_to_slice("TLS 1.3, server CertificateVerify");
    message = append(message, context);

    u8 separator = 0;
    message = append_item(message, separator);
    assert(message.length == message.capacity - sha256_hash_length);

    return message;
}

void tls_key_schedule_info() {
    tls_derived_secret_info
    = tls_make_derived_secret_info(tls_derived_secret_info);

    tls_make_derived_secret(tls_derived_secret);

    tls_handshake_encryption_secret_info 
    = tls_make_handshake_encryption_secret_info(tls_handshake_encryption_secret_info);

    tls_handshake_decryption_secret_info 
    = tls_make_handshake_decryption_secret_info(tls_handshake_decryption_secret_info); 

    tls_encryption_secret_info 
    = tls_make_encryption_secret_info(tls_encryption_secret_info);

    tls_decryption_secret_info 
    = tls_make_decryption_secret_info(tls_decryption_secret_info);

    tls_key_info = tls_make_key_info(tls_key_info);
    tls_iv_info = tls_make_iv_info(tls_iv_info);
    tls_finished_info = tls_make_finished_info(tls_finished_info);

    tls_signature_message = tls_make_signature_message(tls_signature_message);
}