#include "https_server.h"
process_client_ctx process_handshake(client_ctx, slice);

slice slice_around(slice* in, slice separator) {
    slice out = slice_clear(*in);

    while (true) {
        if (separator.length > in->length) {
            out = slice_up(out, in->length);
            *in = slice_end(*in);
            return out;
        }

        slice token = slice_cut(*in, 0, separator.length);

        if (slices_equal(token, separator)) {
            *in = slice_cut(*in, separator.length, in->length);
            return out;
        }

        out = slice_up(out, 1);
        *in = slice_cut(*in, 1, in->length);
    }
}

typedef struct record_ctx record_ctx;

struct record_ctx {
    slice header;
    slice type;
    slice fragment;
};

typedef struct handshake_ctx handshake_ctx;

struct handshake_ctx {
    slice type;
    slice message;
};

slice decode_handshake_finished(slice, client_ctx);

handshake_ctx decode_handshake(slice*, slice*);
record_ctx decode_record(slice*, slice*);

client_ctx cipher_keys(client_ctx);
void xor_nonce(u8[chacha20_nonce_length], u8[chacha20_nonce_length], u64);

server_ctx start() {
    tls_key_schedule_info();

    static char* port = "443";
    server_ctx ctx = {
        .client_capacity = 10,
        .cargo_capacity = 8192,
        .port = port
    };
    return ctx;
}

u32 tls_finished = 1 << 0;
u32 tls_application = 1 << 2;

process_client_ctx process_client(client_ctx client, slice cargo, u32 flags) {

    assert(flags != file_not_found);

    if (flags == file_found) {
        return (process_client_ctx) {
            .client = client,
            .flags = file_read,
            .cargo = cargo,
        };
    }

    if (client.flags == tls_application) {
        slice sub_cargo = cargo;
        cargo = slice_clear(cargo);

        client = cipher_keys(client);

        record_ctx record = decode_record(&sub_cargo, &cargo);
        if (cargo.length) {
            assert(false);
        }

        if (record.fragment.length < 16) {
            assert(false);
        }

        slice auth_tag = slice_cut(
            record.fragment, 
            record.fragment.length - 16, 
            record.fragment.length
        );

        record.fragment = slice_cut(
            record.fragment,
            0,
            record.fragment.length - 16
        );

        int error = chacha20_poly1305_decrypt(
            record.fragment,
            client.decryption_key,
            client.decryption_nonce,
            record.header,
            auth_tag.items 
        );

        if (error) {
            assert(false);
        }
        
        // http_request decode_http_request
        slice space = string_to_slice(" ");
        slice http_get = string_to_slice("GET");

        slice method = slice_around(&record.fragment, space);
        if (!slices_equal(method, http_get)) {
            assert(false);
        }

        //slice url = slice_around(&record.fragment, space);
        static char name[] = "main.html";
        slice url = string_to_slice(name);

        return (process_client_ctx) {
            .client = client,
            .flags = file_open,
            .cargo = cargo,
            .filename = url
        };

    }

    // process_finished();
    if (client.flags == tls_finished) {
        cargo = decode_handshake_finished(cargo, client);

        if (cargo.length) {
            client.flags = 0;
            return (process_client_ctx) {
                .client = client,
                .flags = tcp_write | tcp_disconnect,
                .cargo = cargo
            };
        }
        
        process_client_ctx ctx;
        ctx.client = client;
        ctx.client.flags = tls_application;
        ctx.flags = tcp_read;
        ctx.cargo = cargo;
        ctx.cargo.length = 8192;
        return ctx;
    }


    // if client->flags = tls_handshake;
    return process_handshake(client, cargo);
}

process_client_ctx process_handshake(client_ctx client, slice cargo) {
    sha256_ctx transcript_hash_ctx = sha256_begin();

    u8 public_key[curve25519_key_length];
    cargo = decode_client_hello(
        cargo, 
        &transcript_hash_ctx, 
        public_key
    );

    if (cargo.length) {
        return (process_client_ctx) {
            .client = client,
            .flags = tcp_write | tcp_disconnect,
            .cargo = cargo
        };
    }

    u8 private_key[curve25519_key_length];
    cargo = append_server_hello(
        cargo, 
        &transcript_hash_ctx, 
        private_key
    );
    
    client = handshake_cipher_keys(
        client,
        transcript_hash_ctx,
        public_key,
        private_key
    );

    cargo = append_change_cipher_spec(cargo);

    cargo = append_encrypted_extensions(
        cargo,
        client,
        &transcript_hash_ctx
    );

    cargo = append_certificate(
        cargo,
        client,
        &transcript_hash_ctx
    );

    cargo = append_certificate_verify(
        cargo,
        client,
        &transcript_hash_ctx
    );

    cargo = append_handshake_finished(
        cargo,
        &client,
        transcript_hash_ctx
    );

    client.flags = tls_finished;
    return (process_client_ctx) {
        .client = client,
        .flags = tcp_write | tcp_read,
        .cargo = cargo
    };
}

extension_ctx decode_extension(slice* extensions) {
    extension_ctx ctx;
    ctx.extension = (slice) slice_make(0, 0, 0);

    size_t type_length = 2;
    slice type = next(extensions, type_length);
    if (type.length != type_length) {
        return ctx;
    }
    ctx.type = type;

    size_t extension_length_length = 2;
    slice extension_length = next(extensions, extension_length_length);
    if (extension_length.length != extension_length_length) {
        return ctx;
    } 
    size_t decoded_length = be_to_u16(extension_length.items);
    slice extension = next(extensions, decoded_length);
    if (extension.length != decoded_length) {
        return ctx;
    }

    ctx.extension = extension;
    return ctx;
}

key_ctx decode_key(slice* keys) {
    key_ctx ctx;
    ctx.key = (slice) slice_make(0, 0, 0);

    size_t group_length = 2;
    slice group = next(keys, group_length);
    if (group.length != group_length) {
        return ctx;
    }
    ctx.group = group;

    size_t key_length_length = 2;
    slice key_length = next(keys, key_length_length);
    if (key_length.length != key_length_length) {
        return ctx;
    }
    size_t decoded_length = be_to_u16(key_length.items);
    slice key = next(keys, decoded_length);
    if (key.length != decoded_length) {
        return ctx;
    }

    ctx.key = key;
    return ctx;
}

slice decode_client_hello(slice cargo, sha256_ctx* transcript_hash_ctx, u8 public_key[curve25519_key_length]) {
    slice sub_cargo = cargo;
    cargo = slice_clear(cargo);

    record_ctx record = decode_record(&sub_cargo, &cargo);
    if (cargo.length) {
        return cargo;
    }

    slice fragment = record.fragment;

    handshake_ctx handshake = decode_handshake(&fragment, &cargo);
    if (cargo.length) {
        return cargo;
    }

    slice message = handshake.message;

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-21

    size_t version_length = 2;
    slice version = next(&message, version_length);
    if (version.length != version_length) {
        return copy_decode_error(cargo);
    }

    size_t random_length = 32;
    slice random = next(&message, random_length);
    if (random.length != random_length) {
        return copy_decode_error(cargo);
    }

    size_t session_id_length_length = 1;
    slice session_id_length = next(&message, session_id_length_length); 
    if (session_id_length.length != session_id_length_length) {
        return copy_decode_error(cargo);
    } 
    size_t decoded_length = session_id_length.items[0];
    slice session_id = next(&message, decoded_length); 
    if (session_id.length != decoded_length) {
        return copy_decode_error(cargo);
    }

    size_t ciphers_length_length = 2;
    slice ciphers_length = next(&message, ciphers_length_length);
    if (ciphers_length.length != ciphers_length_length) {
        return copy_decode_error(cargo);
    }
    decoded_length = be_to_u16(ciphers_length.items);
    slice ciphers = next(&message, decoded_length);
    if (ciphers.length != decoded_length) {
        return copy_decode_error(cargo);
    }

    size_t compression_length_length = 1;
    slice compression_length = next(&message, compression_length_length);
    if (compression_length.length != compression_length_length) {
        return copy_decode_error(cargo);
    }
    decoded_length = compression_length.items[0];
    slice compression = next(&message, decoded_length);
    if (compression.length != decoded_length) {
        return copy_decode_error(cargo);
    }

    size_t extensions_length_length = 2;
    slice extensions_length = next(&message, extensions_length_length);
    if (extensions_length.length != extensions_length_length) {
        return copy_decode_error(cargo);
    }
    decoded_length = be_to_u16(extensions_length.items);
    slice extensions = next(&message, decoded_length);
    if (extensions.length != decoded_length) {
        return copy_decode_error(cargo);
    }

    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-24
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-32

    while (extensions.length) {
        extension_ctx ctx = decode_extension(&extensions);
        if (!ctx.extension.items) {
            return copy_decode_error(cargo);
        }

        slice extension_type_key_share = slice_literal(0, 51);
        if (slices_equal(ctx.type, extension_type_key_share)) {
            size_t keys_length_length = 2;
            slice keys_length = next(&ctx.extension, keys_length_length);
            if (keys_length.length != keys_length_length) {
                return copy_decode_error(cargo);
            } 
            size_t decoded_length = be_to_u16(keys_length.items);
            slice keys = next(&ctx.extension, decoded_length);
            if (keys.length != decoded_length) {
                return copy_decode_error(cargo);
            }

            int key_found = false;
            while (keys.length) {
                key_ctx key = decode_key(&keys);
                if (!key.key.items) {
                    return copy_decode_error(cargo);
                }
                slice curve25519 = slice_literal(0x00, 0x1d);
                if (slices_equal(key.group, curve25519)) {
                    if (key.key.length != curve25519_key_length) {
                        return copy_handshake_failure(cargo);
                    }
                    else {
                        key_found = true;
                        for (size_t i = 0; i < key.key.length; i += 1) {
                            public_key[i] = key.key.items[i];
                        }
                    }
                    break;
                }
            }

            if (!key_found) {
                return copy_handshake_failure(cargo);
            }
        }
    }

    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, record.fragment);

    return cargo;
}

slice decode_handshake_finished(slice cargo, client_ctx client) {
    slice sub_cargo = cargo;
    cargo = slice_clear(cargo);

    record_ctx record = decode_record(&sub_cargo, &cargo);
    if (cargo.length) {
        return cargo;
    }

    slice content_type_change_cipher_spec = slice_literal(20);
    slice change_cipher_spec = slice_literal(1);
    if (slices_equal(record.type, content_type_change_cipher_spec)) {
        if (!slices_equal(record.fragment, change_cipher_spec)) {
            return copy_unexpected_message(cargo);
        }
        record = decode_record(&sub_cargo, &cargo);
        if (cargo.length) {
            return cargo;
        }
    }

    if (record.fragment.length < 16) {
        return copy_bad_record_mac(cargo);
    }

    slice auth_tag = slice_cut(
        record.fragment, 
        record.fragment.length - 16, 
        record.fragment.length
    );

    record.fragment = slice_cut(
        record.fragment,
        0,
        record.fragment.length - 16
    );

    int error = chacha20_poly1305_decrypt(
        record.fragment,
        client.decryption_key,
        client.decryption_nonce,
        record.header,
        auth_tag.items 
    );

    if (error) {
        return copy_bad_record_mac(cargo);
    }

    slice fragment = record.fragment;

    handshake_ctx handshake = decode_handshake(&fragment, &cargo);
    if (cargo.length) {
        return cargo;
    }

    u8 finished_key[sha256_hash_length];
    hkdf_expand_sha256(
        finished_key,
        sha256_hash_length,
        array_to_slice(client.decryption_secret),
        tls_finished_info
    );

    u8 verify_data[sha256_hash_length];
    hmac_sha256(
        verify_data,
        array_to_slice(finished_key),
        array_to_slice(client.transcript_hash)
    );

    if (!slices_equal(handshake.message, array_to_slice(verify_data))) {
        return copy_decrypt_error(cargo);
    }

    return cargo;
}

record_ctx decode_record(slice* in, slice* error) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-59
    record_ctx ctx = { 0 };

    size_t header_length = 5;
    ctx.header = next(in, header_length);
    if (ctx.header.length != header_length) {
        *error = copy_decode_error(*error);
        return ctx;
    }

    slice sub_header = ctx.header;

    size_t type_length = 1;
    ctx.type = next(&sub_header, type_length);

    size_t legacy_version_length = 2;
    slice legacy_version = next(&sub_header, legacy_version_length);

    size_t fragment_length_length = 2;
    slice fragment_length = next(&sub_header, fragment_length_length);
    size_t decoded_length = be_to_u16(fragment_length.items);

    ctx.fragment = next(in, decoded_length);
    if (ctx.fragment.length != decoded_length) {
        *error = copy_decode_error(*error);
        return ctx;
    }

    return ctx;
}

handshake_ctx decode_handshake(slice* in, slice* error) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-18
    handshake_ctx ctx = { 0 };

    size_t type_length = 1;
    ctx.type = next(in, type_length);
    if (ctx.type.length != type_length) {
        *error = copy_decode_error(*error);
        return ctx;
    }

    size_t length_length = 3;
    slice length = next(in, length_length);
    if (length.length != length_length) {
        *error = copy_decode_error(*error);
        return ctx;
    }
    if (length.items[0]) {
        *error = copy_decode_error(*error);
        return ctx;
    }
    length = slice_bump(length, 1);
    size_t decoded_length = be_to_u16(length.items);

    ctx.message = next(in, decoded_length);
    if (ctx.message.length != decoded_length) {
        *error = copy_decode_error(*error);
        return ctx;
    }

    return ctx;
}

slice append_server_hello(slice cargo, sha256_ctx* transcript_hash_ctx, u8 private_key[curve25519_key_length]) {
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

slice append_change_cipher_spec(slice cargo) {
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

slice append_encrypted_extensions(slice cargo, client_ctx client, sha256_ctx* transcript_hash_ctx) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-42

    slice header = slice_end(cargo);

    u8 content_type_app_data = 23;
    header = append_item(header, content_type_app_data);

    slice legacy_record_version = slice_literal(0x03, 0x03);
    header = append(header, legacy_record_version);

    size_t fragment_length_length = 2;
    slice fragment_length = slice_end(header);

    header = slice_up(header, fragment_length_length);

    slice fragment = slice_end(header);

    u8 handshake_type_encrypted_extensions = 8;
    fragment = append_item(
        fragment, 
        handshake_type_encrypted_extensions
    );

    slice message_length = slice_literal(0, 0, 2);
    fragment = append(fragment, message_length);

    slice message = slice_literal(0, 0);
    fragment = append(fragment, message);

    *transcript_hash_ctx = sha256_run(*transcript_hash_ctx, fragment);

    u8 content_type_handshake = 22;
    fragment = append_item(fragment, content_type_handshake);

    fragment_length = copy_u16_be(
        fragment_length, 
        (u16) (fragment.length + poly1305_auth_tag_length)
    );

    fragment = chacha20_poly1305_encrypt(
        fragment,
        client.encryption_key, 
        client.encryption_nonce,
        header
    );

    cargo = slice_up(
        cargo,
        header.length +
        fragment.length
    );

    return cargo;
}

slice append_certificate(slice cargo, client_ctx client, sha256_ctx* transcript_hash_ctx) {
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
    xor_nonce(
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

slice append_certificate_verify(slice cargo, client_ctx client, sha256_ctx* transcript_hash_ctx) {
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
    xor_nonce(
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

slice append_handshake_finished(
    slice cargo, 
    client_ctx* client, 
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
    xor_nonce(
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

client_ctx handshake_cipher_keys(
    client_ctx client, 
    sha256_ctx transcript_hash_ctx, 
    u8 public_key[curve25519_key_length],
    u8 private_key[curve25519_key_length]
) {
    sha256_end(transcript_hash_ctx, client.transcript_hash);

    u8 shared_secret[curve25519_key_length];
    curve25519_scale(shared_secret, private_key, public_key);

    hkdf_extract_sha256(
        client.handshake_secret,
        array_to_slice(shared_secret),
        array_to_slice(tls_derived_secret)
    );

    slice encryption_secret_info = append_length(
        tls_handshake_encryption_secret_info,
        client.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        client.encryption_secret,
        sha256_hash_length,
        array_to_slice(client.handshake_secret),
        encryption_secret_info
    );

    hkdf_expand_sha256(
        client.encryption_key,
        chacha20_key_length,
        array_to_slice(client.encryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        client.encryption_nonce,
        chacha20_nonce_length,
        array_to_slice(client.encryption_secret),
        tls_iv_info
    );

    slice decryption_secret_info = append_length(
        tls_handshake_decryption_secret_info,
        client.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        client.decryption_secret,
        sha256_hash_length,
        array_to_slice(client.handshake_secret),
        decryption_secret_info
    );

    hkdf_expand_sha256(
        client.decryption_key,
        chacha20_key_length,
        array_to_slice(client.decryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        client.decryption_nonce,
        chacha20_nonce_length,
        array_to_slice(client.decryption_secret),
        tls_iv_info
    );

    return client;
}

client_ctx cipher_keys(client_ctx client) {

    u8 derived_secret[sha256_hash_length];
    hkdf_expand_sha256(
        derived_secret,
        sha256_hash_length,
        array_to_slice(client.handshake_secret),
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
        client.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        client.encryption_secret,
        sha256_hash_length,
        array_to_slice(master_secret),
        encryption_secret_info
    );

    hkdf_expand_sha256(
        client.encryption_key,
        chacha20_key_length,
        array_to_slice(client.encryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        client.encryption_nonce,
        chacha20_nonce_length,
        array_to_slice(client.encryption_secret),
        tls_iv_info
    );

    slice decryption_secret_info = append_length(
        tls_decryption_secret_info,
        client.transcript_hash,
        sha256_hash_length
    );

    hkdf_expand_sha256(
        client.decryption_secret,
        sha256_hash_length,
        array_to_slice(master_secret),
        decryption_secret_info
    );

    hkdf_expand_sha256(
        client.decryption_key,
        chacha20_key_length,
        array_to_slice(client.decryption_secret),
        tls_key_info
    );

    hkdf_expand_sha256(
        client.decryption_nonce,
        chacha20_nonce_length,
        array_to_slice(client.decryption_secret),
        tls_iv_info
    );

    return client;
}

void xor_nonce(u8 out[chacha20_nonce_length], u8 nonce[chacha20_nonce_length], u64 record_count) {
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

void tls_key_schedule_info() {
    tls_derived_secret_info
    = make_tls_derived_secret_info(tls_derived_secret_info);

    make_tls_derived_secret(tls_derived_secret);

    tls_handshake_encryption_secret_info 
    = make_tls_handshake_encryption_secret_info(tls_handshake_encryption_secret_info);

    tls_handshake_decryption_secret_info 
    = make_tls_handshake_decryption_secret_info(tls_handshake_decryption_secret_info); 

    tls_encryption_secret_info 
    = make_tls_encryption_secret_info(tls_encryption_secret_info);

    tls_decryption_secret_info 
    = make_tls_decryption_secret_info(tls_decryption_secret_info);

    tls_key_info = make_tls_key_info(tls_key_info);
    tls_iv_info = make_tls_iv_info(tls_iv_info);
    tls_finished_info = make_tls_finished_info(tls_finished_info);
}

slice make_tls_derived_secret_info(slice info) {
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

void make_tls_derived_secret(u8 tls_derived_secret[sha256_hash_length]) {
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

slice make_tls_handshake_encryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 s hs traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice make_tls_handshake_decryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 c hs traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice make_tls_encryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 s ap traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice make_tls_decryption_secret_info(slice info) {
    // https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

    info = copy_u16_be(info, sha256_hash_length);
    slice label = string_to_slice("tls13 c ap traffic");
    info = append_item(info, (u8) label.length);
    info = append(info, label);
    info = append_item(info, sha256_hash_length);
    assert(info.length == info.capacity - sha256_hash_length);

    return info;
}

slice make_tls_key_info(slice info) {
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

slice make_tls_iv_info(slice info) {
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

slice make_tls_finished_info(slice info) {
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

slice copy_decode_error(slice cargo) {
    u8 content_type_alert = 21;
    cargo = copy_item(cargo, content_type_alert);

    slice record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, record_version);

    slice length = slice_literal(0, 2);
    cargo = append(cargo, length);

    u8 alert_level_fatal = 2;
    u8 alert_decode_error = 50;
    cargo = append_item(cargo, alert_level_fatal);
    cargo = append_item(cargo, alert_decode_error);

    return cargo;
}

slice copy_handshake_failure(slice cargo) {
    u8 content_type_alert = 21;
    cargo = copy_item(cargo, content_type_alert);

    slice record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, record_version);

    slice length = slice_literal(0, 2);
    cargo = append(cargo, length);

    u8 alert_level_fatal = 2;
    u8 alert_handshake_failure = 40;
    cargo = append_item(cargo, alert_level_fatal);
    cargo = append_item(cargo, alert_handshake_failure);

    return cargo;
}

slice copy_unexpected_message(slice cargo) {
    u8 content_type_alert = 21;
    cargo = copy_item(cargo, content_type_alert);

    slice record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, record_version);

    slice length = slice_literal(0, 2);
    cargo = append(cargo, length);

    u8 alert_level_fatal = 2;
    u8 alert_unexpected_message = 10;
    cargo = append_item(cargo, alert_level_fatal);
    cargo = append_item(cargo, alert_unexpected_message);

    return cargo;
}

slice copy_bad_record_mac(slice cargo) {
    u8 content_type_alert = 21;
    cargo = copy_item(cargo, content_type_alert);

    slice record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, record_version);

    slice length = slice_literal(0, 2);
    cargo = append(cargo, length);

    u8 alert_level_fatal = 2;
    u8 alert_bad_record_mac = 20;
    cargo = append_item(cargo, alert_level_fatal);
    cargo = append_item(cargo, alert_bad_record_mac);

    return cargo;
}

slice copy_decrypt_error(slice cargo) {
    u8 content_type_alert = 21;
    cargo = copy_item(cargo, content_type_alert);

    slice record_version = slice_literal(0x03, 0x03);
    cargo = append(cargo, record_version);

    slice length = slice_literal(0, 2);
    cargo = append(cargo, length);

    u8 alert_level_fatal = 2;
    u8 alert_decrypt_error = 51;
    cargo = append_item(cargo, alert_level_fatal);
    cargo = append_item(cargo, alert_decrypt_error);

    return cargo;
}

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