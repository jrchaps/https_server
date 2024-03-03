//
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
//

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

u8 tls_decode_client_hello(
    slice cargo,
    sha256_ctx* transcript_hash_ctx,
    u8 public_key[curve25519_key_length]
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
    slice session_id = next(&handshake.message, decoded_length); 
    if (session_id.length != decoded_length) {
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

#if 0
slice tls_append_server_hello(
    slice cargo,
    sha256_ctx* transcript_hash_ctx,
    u8 private_key[curve25519_key_length]
) {
    slice record = tls_record_start(cargo, tls_record_type_handshake);
    slice handshake = tls_handshake_start(record, tls_message_type_server_hello);
    handshake = slice_up(handshake, 2);
    handshake = append_random(handshake, 32);
    handshake = slice_up(handshake, 33);
    handshake = append(handshake, cipher_suite);
}
#endif

slice tls_append_server_hello(
    slice cargo, 
    sha256_ctx* transcript_hash_ctx, 
    u8 private_key[curve25519_key_length]
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-59

    u8 content_type_handshake = 22;
    cargo = append_item(cargo, content_type_handshake);

    slice legacy_record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, legacy_record_version);

    size_t fragment_length_length = 2;
    slice fragment_length = slice_end(cargo);

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-18

    slice fragment = slice_bump(
        fragment_length, 
        fragment_length_length
    );

    u8 handshake_type_server_hello = 2;
    fragment = append_item(
        fragment, 
        handshake_type_server_hello
    );

    size_t message_length_length = 3;
    slice message_length = slice_end(fragment);

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-22

    slice message = slice_bump(
        message_length,
        message_length_length
    );

    message = slice_up(message, 2);
    //message = append(message, legacy_record_version); // not needed if client hello version is verified;

    size_t random_length = 32;
    message = append_random(message, random_length);

    message = slice_up(message, 33);
    //message = append_item(message, (u8) legacy_session_id.length);
    //message = append(message, legacy_session_id); // not needed because it is in the same place

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-104

    slice cipher_suite_chacha20_poly1305_sha256 = slice_literal(0x13, 0x03);
    message = append(
        message, 
        cipher_suite_chacha20_poly1305_sha256
    ); 

    u8 legacy_compression_method = 0;
    message = append_item(message, legacy_compression_method);

    size_t extensions_length_length = 2;
    slice extensions_length = slice_end(message);

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-24

    slice supported_version_type = slice_bump(
        extensions_length,
        extensions_length_length
    );

    slice extension_type_supported_version = slice_literal(0, 43);
    supported_version_type = append(
        supported_version_type, 
        extension_type_supported_version
    );

    size_t extension_length_length = 2;
    slice supported_version_length = slice_end(supported_version_type);

    slice supported_version = slice_bump(
        supported_version_length,
        extension_length_length
    );

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-25
    slice selected_version = slice_literal(0x03, 0x04);
    supported_version = append(supported_version, selected_version);

    supported_version_length = copy_u16_be(
        supported_version_length, 
        (u16) supported_version.length
    );

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-32

    slice key_share_type = slice_end(supported_version);

    slice extension_type_key_share = slice_literal(0, 51);
    key_share_type = append(
        key_share_type, 
        extension_type_key_share
    );

    slice key_share_length = slice_end(key_share_type);

    slice key_share = slice_bump(
        key_share_length,
        extension_length_length
    );

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-31
    slice group_x25519 = slice_literal(0x00, 0x1d);
    key_share = append(key_share, group_x25519);

    key_share = append_u16_be(key_share, curve25519_key_length);

    crypto_random(private_key, curve25519_key_length);
    curve25519_scale_base(
        &key_share.items[key_share.length], 
        private_key
    );

    key_share = slice_up(key_share, curve25519_key_length);

    key_share_length = copy_u16_be(
        key_share_length, 
        (u16) key_share.length
    );

    {
        size_t length = (
            supported_version_type.length +
            supported_version_length.length + 
            supported_version.length + 

            key_share_type.length +
            key_share_length.length +
            key_share.length
        );

        extensions_length = copy_u16_be(extensions_length, (u16) length);

        message = slice_up(
            message,
            length +
            extensions_length_length
        );
    }

    message_length = copy_item(message_length, 0);
    message_length = append_u16_be(
        message_length, 
        (u16) message.length
    );

    fragment = slice_up(
        fragment,
        message.length +
        message_length_length
    );

    fragment_length = copy_u16_be(
        fragment_length, 
        (u16) fragment.length
    );

    cargo = slice_up(
        cargo,
        fragment.length +
        fragment_length_length
    );

    *transcript_hash_ctx = sha256_run(
        *transcript_hash_ctx, 
        fragment
    );

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
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-58
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-115

    u8 content_type_change_cipher_spec = 20;
    cargo = append_item(cargo, content_type_change_cipher_spec);

    slice legacy_record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, legacy_record_version);

    slice change_cipher_spec_length = slice_literal(0, 1);
    cargo = append(cargo, change_cipher_spec_length);

    u8 change_cipher_spec = 1;
    cargo = append_item(cargo, change_cipher_spec);

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

slice tls_certificate = slice_literal(
    0x30, 0x82, 0x03, 0xB8, 0x30, 0x82, 0x02, 0x20, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00,
    0xBD, 0x19, 0x4A, 0x85, 0x5D, 0xEF, 0xE4, 0x0F, 0xD4, 0xE3, 0x01, 0x95, 0x7E, 0x96, 0xA2, 0x93,
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30,
    0x81, 0xAD, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x6D, 0x6B, 0x63,
    0x65, 0x72, 0x74, 0x20, 0x64, 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x6D, 0x65, 0x6E, 0x74, 0x20,
    0x43, 0x41, 0x31, 0x41, 0x30, 0x3F, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x38, 0x44, 0x45, 0x53,
    0x4B, 0x54, 0x4F, 0x50, 0x2D, 0x4B, 0x47, 0x38, 0x38, 0x4C, 0x56, 0x55, 0x5C, 0x6A, 0x72, 0x63,
    0x68, 0x61, 0x40, 0x44, 0x45, 0x53, 0x4B, 0x54, 0x4F, 0x50, 0x2D, 0x4B, 0x47, 0x38, 0x38, 0x4C,
    0x56, 0x55, 0x20, 0x28, 0x4A, 0x6F, 0x6E, 0x61, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x43, 0x68, 0x61,
    0x70, 0x6D, 0x61, 0x6E, 0x29, 0x31, 0x48, 0x30, 0x46, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x3F,
    0x6D, 0x6B, 0x63, 0x65, 0x72, 0x74, 0x20, 0x44, 0x45, 0x53, 0x4B, 0x54, 0x4F, 0x50, 0x2D, 0x4B,
    0x47, 0x38, 0x38, 0x4C, 0x56, 0x55, 0x5C, 0x6A, 0x72, 0x63, 0x68, 0x61, 0x40, 0x44, 0x45, 0x53,
    0x4B, 0x54, 0x4F, 0x50, 0x2D, 0x4B, 0x47, 0x38, 0x38, 0x4C, 0x56, 0x55, 0x20, 0x28, 0x4A, 0x6F,
    0x6E, 0x61, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x43, 0x68, 0x61, 0x70, 0x6D, 0x61, 0x6E, 0x29, 0x30,
    0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x38, 0x30, 0x36, 0x30, 0x33, 0x30, 0x39, 0x34, 0x36, 0x5A,
    0x17, 0x0D, 0x32, 0x35, 0x31, 0x31, 0x30, 0x36, 0x30, 0x34, 0x30, 0x39, 0x34, 0x36, 0x5A, 0x30,
    0x6C, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x1E, 0x6D, 0x6B, 0x63, 0x65,
    0x72, 0x74, 0x20, 0x64, 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x6D, 0x65, 0x6E, 0x74, 0x20, 0x63,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x31, 0x41, 0x30, 0x3F, 0x06, 0x03,
    0x55, 0x04, 0x0B, 0x0C, 0x38, 0x44, 0x45, 0x53, 0x4B, 0x54, 0x4F, 0x50, 0x2D, 0x4B, 0x47, 0x38,
    0x38, 0x4C, 0x56, 0x55, 0x5C, 0x6A, 0x72, 0x63, 0x68, 0x61, 0x40, 0x44, 0x45, 0x53, 0x4B, 0x54,
    0x4F, 0x50, 0x2D, 0x4B, 0x47, 0x38, 0x38, 0x4C, 0x56, 0x55, 0x20, 0x28, 0x4A, 0x6F, 0x6E, 0x61,
    0x74, 0x68, 0x61, 0x6E, 0x20, 0x43, 0x68, 0x61, 0x70, 0x6D, 0x61, 0x6E, 0x29, 0x30, 0x59, 0x30,
    0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x10, 0xAB, 0x35, 0x77, 0x09, 0x8A, 0x81, 0x15,
    0xD0, 0x0F, 0x7C, 0xA8, 0xEF, 0x78, 0x52, 0xF0, 0x13, 0xBC, 0x0E, 0x45, 0xA7, 0x5B, 0x7F, 0xFB,
    0x81, 0xAB, 0x2F, 0xAC, 0x14, 0x2F, 0x2E, 0x9F, 0xBB, 0x40, 0x85, 0xD4, 0x60, 0x5F, 0x8E, 0x87,
    0x71, 0x29, 0x90, 0xDF, 0xA1, 0xA4, 0xEB, 0xAD, 0x29, 0x2C, 0x31, 0x61, 0x17, 0x3E, 0xD4, 0x4C,
    0xC7, 0x33, 0xC3, 0x89, 0xE6, 0xC0, 0x05, 0xE0, 0xA3, 0x5E, 0x30, 0x5C, 0x30, 0x0E, 0x06, 0x03,
    0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x05, 0xA0, 0x30, 0x13, 0x06, 0x03,
    0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
    0x01, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x5F, 0x25,
    0xAE, 0x81, 0x0E, 0x1D, 0x53, 0xFD, 0x79, 0x0F, 0x77, 0x55, 0xC7, 0x50, 0x22, 0x6F, 0x40, 0x4A,
    0xF3, 0x6A, 0x30, 0x14, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x0D, 0x30, 0x0B, 0x82, 0x09, 0x6C,
    0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x81, 0x00, 0x73, 0xFE, 0x3A, 0x42,
    0x2E, 0x53, 0x5E, 0xAE, 0x4C, 0x4E, 0x9B, 0x2B, 0x85, 0xA1, 0x19, 0x38, 0x67, 0x38, 0x89, 0x68,
    0xB2, 0x56, 0x68, 0x8F, 0xCD, 0x43, 0xB2, 0x6E, 0xC7, 0x70, 0x32, 0xEB, 0x8D, 0x91, 0x4F, 0x42,
    0xD1, 0xD5, 0x36, 0xA0, 0xC9, 0x6E, 0xF3, 0xF7, 0x60, 0xEC, 0x24, 0x35, 0x7B, 0xA1, 0xF6, 0xE7,
    0xAE, 0x09, 0xE7, 0x33, 0x0D, 0x59, 0x72, 0x3E, 0x33, 0xB1, 0x7A, 0xC6, 0xD8, 0xBB, 0xCC, 0x68,
    0x59, 0x1B, 0x77, 0x40, 0x62, 0x8B, 0xE7, 0xC8, 0x9D, 0x3E, 0x54, 0xDB, 0x2A, 0x9F, 0x2B, 0x21,
    0x51, 0xC2, 0xCA, 0xDC, 0xCB, 0x8F, 0x16, 0x17, 0xD5, 0x15, 0xD3, 0xAE, 0xD8, 0x06, 0x67, 0x02,
    0x42, 0x55, 0xBA, 0xB7, 0x3A, 0x29, 0x2D, 0x0A, 0x70, 0xB8, 0x57, 0x5A, 0xF6, 0xE1, 0x4A, 0x54,
    0x78, 0x8A, 0x28, 0xE8, 0x10, 0x81, 0xF4, 0xAC, 0x56, 0xFE, 0xFD, 0x81, 0x00, 0x09, 0xB6, 0x62,
    0x90, 0xD3, 0xF7, 0x14, 0xB2, 0x85, 0x30, 0x60, 0xB0, 0x38, 0x2E, 0x05, 0x04, 0x93, 0x50, 0x37,
    0xF2, 0x00, 0xFB, 0xC9, 0xE8, 0xFA, 0x4D, 0x22, 0x80, 0x10, 0x4A, 0x4C, 0x21, 0xFF, 0xF0, 0x01,
    0x0E, 0xEC, 0x1D, 0x7F, 0xC8, 0x0A, 0x8E, 0x38, 0xAF, 0x34, 0x1A, 0x8E, 0x67, 0x9E, 0xCD, 0x0E,
    0x40, 0x41, 0xEF, 0x8F, 0x21, 0xF9, 0x80, 0x7D, 0x4F, 0x12, 0x6D, 0xAF, 0x99, 0xC8, 0x63, 0xB1,
    0x98, 0xFD, 0xBE, 0x1F, 0x0F, 0x08, 0x25, 0xD8, 0x6E, 0xCC, 0x62, 0x8E, 0x85, 0x0A, 0xC2, 0x06,
    0xE5, 0xAF, 0xA4, 0x5B, 0xF0, 0xBE, 0x83, 0xE8, 0x84, 0x49, 0x88, 0x88, 0x54, 0x60, 0x97, 0x3C,
    0x2F, 0x03, 0x86, 0x5C, 0xE3, 0x03, 0x43, 0x53, 0xCD, 0x9A, 0xF7, 0x66, 0x3C, 0xF5, 0xDE, 0x08,
    0xDE, 0xD9, 0x5F, 0x99, 0x66, 0x29, 0x73, 0x4F, 0x0A, 0x31, 0xBC, 0xC8, 0x1C, 0xBD, 0x7C, 0xB0,
    0x01, 0xB6, 0x93, 0x54, 0xE5, 0x7D, 0xDD, 0x53, 0x63, 0xA4, 0x6D, 0xD8, 0x00, 0xA9, 0xE0, 0x19,
    0x87, 0x79, 0x1B, 0xE5, 0x17, 0x8C, 0x4F, 0xAB, 0x11, 0x96, 0xB4, 0x98, 0x67, 0x1D, 0xCE, 0x9A,
    0xBE, 0x3C, 0xBB, 0xF5, 0x0B, 0x4B, 0xDB, 0x90, 0x7D, 0x4F, 0x6D, 0x44, 0x66, 0xE3, 0xB5, 0x33,
    0x2D, 0xBE, 0x25, 0xCE, 0xDE, 0xFA, 0x2B, 0x53, 0x7D, 0xF0, 0xF6, 0x22, 0x9C, 0x54, 0x61, 0x67,
    0x0B, 0x84, 0x93, 0x88, 0xF5, 0xC5, 0x52, 0x08, 0xC9, 0xFE, 0x96, 0xAC, 0x84, 0xCE, 0x76, 0x5C,
    0x5A, 0xE0, 0x9A, 0x42, 0x20, 0xDF, 0xD9, 0x11, 0xFB, 0xA9, 0xD7, 0x53, 0x78, 0xB1, 0x1A, 0x69,
    0x3E, 0xD1, 0x1B, 0x84, 0x0E, 0xB8, 0x9E, 0xCD, 0x74, 0x1B, 0xCB, 0x1D, 0x76, 0x1D, 0xF4, 0xDE,
    0xBE, 0x3A, 0x71, 0xD0, 0x48, 0xBC, 0xC1, 0xC7, 0x39, 0x02, 0x01, 0xDF
);

u8 tls_certificate_key[32] = {
    0x19, 0x87, 0x11, 0x45, 0x30, 0x8A, 0x61, 0x0B, 
    0xF6, 0xC2, 0x60, 0x73, 0x89, 0xA0, 0xA1, 0x51, 
    0x83, 0x27, 0x61, 0x35, 0x4D, 0xD7, 0x4C, 0x69, 
    0xD2, 0xA8, 0xD3, 0x6D, 0xE9, 0x1B, 0x44, 0xFC
};

slice tls_append_certificate(
    slice cargo, 
    tls_ctx client, 
    sha256_ctx* transcript_hash_ctx
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-46

    slice header = slice_end(cargo);

    u8 content_type_app_data = 23;
    header = append_item(header, content_type_app_data);

    slice legacy_record_version = slice_literal(0x03, 0x03);
    header = append(header, legacy_record_version);

    size_t fragment_length_length = 2;
    slice fragment_length = slice_end(header);

    header = slice_up(header, fragment_length_length);

    slice fragment = slice_end(header);

    u8 handshake_type_certificate = 11;
    fragment = append_item(fragment, handshake_type_certificate);
    
    size_t message_length_length = 3;
    slice message_length = slice_end(fragment);

    slice message = slice_bump(
        message_length,
        message_length_length
    );

    u8 certificate_request_context = 0;
    message = append_item(message, certificate_request_context);
    
    size_t certificate_list_length_length = 3;
    slice certificate_list_length = slice_end(message);
    
    slice certificate = slice_bump(
        certificate_list_length,
        certificate_list_length_length
    );

    certificate = append_item(certificate, 0);
    certificate = append_u16_be(certificate, (u16) tls_certificate.length);

    certificate = append(certificate, tls_certificate);

    slice certificate_extensions_length = slice_literal(0, 0);
    certificate = append(certificate, certificate_extensions_length);

    certificate_list_length = copy_item(certificate_list_length, 0);
    certificate_list_length = append_u16_be(certificate_list_length, (u16) certificate.length);

    message = slice_up(
        message,
        certificate.length +
        certificate_list_length_length
    );

    message_length = copy_item(message_length, 0);
    message_length = append_u16_be(message_length, (u16) message.length);

    fragment = slice_up(
        fragment,
        message.length +
        message_length_length
    );

    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, fragment);

    u8 content_type_handshake = 22;
    fragment = append_item(fragment, content_type_handshake);

    fragment_length = copy_u16_be(fragment_length, (u16) (fragment.length + poly1305_auth_tag_length));

    client.encryption_count = 1;
    u8 nonce[chacha20_nonce_length];
    tls_xor_nonce(
        nonce, 
        client.encryption_nonce, 
        client.encryption_count
    );

    fragment = chacha20_poly1305_encrypt(
        fragment,
        client.encryption_key, 
        nonce,
        header
    );

    cargo = slice_up(
        cargo,
        header.length +
        fragment.length
    );

    return cargo;
}

slice tls_append_certificate_verify(
    slice cargo, 
    tls_ctx client, 
    sha256_ctx* transcript_hash_ctx
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-51

    slice header = slice_end(cargo);

    u8 content_type_app_data = 23;
    header = append_item(header, content_type_app_data);

    slice legacy_record_version = slice_literal(0x03, 0x03);
    header = append(header, legacy_record_version);

    size_t fragment_length_length = 2;
    slice fragment_length = slice_end(header);

    header = slice_up(header, fragment_length_length);

    slice fragment = slice_end(header);

    u8 handshake_type_certificate_verify = 15;
    fragment = append_item(fragment, handshake_type_certificate_verify);

    size_t message_length_length = 3;
    slice message_length = slice_end(fragment);

    slice message = slice_bump(
        message_length,
        message_length_length
    );

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-27
    slice signature_algorithm = slice_literal(0x04, 0x03);
    message = append(message, signature_algorithm);

    slice ecdsa_message = slice_alloc(130);

    for (size_t i = 0; i < 64; i += 1) {
        ecdsa_message = append_item(ecdsa_message, ' ');
    }

    slice context = string_to_slice("TLS 1.3, server CertificateVerify");
    ecdsa_message = append(ecdsa_message, context);

    u8 separator = 0;
    ecdsa_message = append_item(ecdsa_message, separator);

    sha256_end(*transcript_hash_ctx, client.transcript_hash);
    ecdsa_message = append_length(ecdsa_message, client.transcript_hash, sha256_hash_length);

    size_t signature_length_length = 2;
    slice signature_length = slice_end(message);

    slice signature = slice_bump(
        signature_length,
        signature_length_length
    );

    signature = ecdsa_secp256r1_sha256(
        signature,
        tls_certificate_key,
        ecdsa_message
    );

    signature_length = copy_u16_be(signature_length, (u16) signature.length);

    message = slice_up(
        message,
        signature.length +
        signature_length_length
    );

    message_length = copy_item(message_length, 0);
    message_length = append_u16_be(message_length, (u16) message.length);

    fragment = slice_up(
        fragment,
        message.length +
        message_length_length
    );

    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, fragment);

    u8 content_type_handshake = 22;
    fragment = append_item(fragment, content_type_handshake);

    fragment_length = copy_u16_be(fragment_length, (u16) (fragment.length + poly1305_auth_tag_length));

    client.encryption_count = 2;
    u8 nonce[chacha20_nonce_length];
    tls_xor_nonce(
        nonce, 
        client.encryption_nonce, 
        client.encryption_count
    );

    fragment = chacha20_poly1305_encrypt(
        fragment,
        client.encryption_key,
        nonce,
        header
    );

    cargo = slice_up(
        cargo,
        header.length +
        fragment.length
    );

    return cargo;
}

slice tls_append_handshake_finished(
    slice cargo, 
    tls_ctx* client, 
    sha256_ctx transcript_hash_ctx 
) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-52

    slice header = slice_end(cargo);

    u8 content_type_app_data = 23;
    header = append_item(header, content_type_app_data);

    slice legacy_record_version = slice_literal(0x03, 0x03);
    header = append(header, legacy_record_version);

    size_t fragment_length_length = 2;
    slice fragment_length = slice_end(header);

    header = slice_up(header, fragment_length_length);

    slice fragment = slice_end(header);

    u8 handshake_type_finished = 20;
    fragment = append_item(fragment, handshake_type_finished);

    size_t message_length_length = 3;
    slice message_length = slice_end(fragment);

    slice message = slice_bump(
        message_length,
        message_length_length
    );

    u8 finished_key[sha256_hash_length];
    hkdf_expand_sha256(
        finished_key,
        sha256_hash_length,
        array_to_slice(client->encryption_secret),
        tls_finished_info
    );

    sha256_end(transcript_hash_ctx, client->transcript_hash);

    u8 verify_data[sha256_hash_length];
    hmac_sha256(
        verify_data,
        array_to_slice(finished_key),
        array_to_slice(client->transcript_hash)
    );

    message = append_length(message, verify_data, sha256_hash_length);

    message_length = copy_item(message_length, 0);
    message_length = append_u16_be(message_length, (u16) message.length);

    fragment = slice_up(
        fragment,
        message.length +
        message_length_length
    );

    transcript_hash_ctx = sha256_run(transcript_hash_ctx, fragment);
    sha256_end(transcript_hash_ctx, client->transcript_hash);

    u8 content_type_handshake = 22;
    fragment = append_item(fragment, content_type_handshake);

    fragment_length = copy_u16_be(fragment_length, (u16) (fragment.length + poly1305_auth_tag_length));

    client->encryption_count = 3;
    u8 nonce[chacha20_nonce_length];
    tls_xor_nonce(
        nonce, 
        client->encryption_nonce, 
        client->encryption_count
    );

    fragment = chacha20_poly1305_encrypt(
        fragment,
        client->encryption_key,
        nonce,
        header
    );

    cargo = slice_up(
        cargo,
        header.length +
        fragment.length
    );

    return cargo;
}

u8 tls_process_handshake(tls_ctx* ctx, slice* cargo) {
    sha256_ctx transcript_hash_ctx = sha256_begin();

    u8 public_key[curve25519_key_length];
    u8 error = tls_decode_client_hello(
        *cargo,
        &transcript_hash_ctx,
        public_key
    );

    if (error) {
        return error;
    }

    u8 private_key[curve25519_key_length];
    *cargo = slice_clear(*cargo);
    *cargo = tls_append_server_hello(
        *cargo,
        &transcript_hash_ctx,
        private_key
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
        *ctx,
        &transcript_hash_ctx
    );

    *cargo = tls_append_certificate_verify(
        *cargo,
        *ctx,
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
}