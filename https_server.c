#include "https_server.h"

server_ctx start() {
    tls_key_schedule_info();

    server_ctx ctx = {
        client_capacity,
        cargo_capacity,
        port
    };
    return ctx;
}

#define tls_state_handshake 1 << 9
#define tls_state_handshake_finished 1 << 10

tcp_client_ctx process_tcp_client(tcp_client_ctx client) {

    assert(client.flags != file_not_found);

    slice cargo = slice_make(
        cargo_capacity,
        client.cargo.length,
        client.cargo.items
    );

    switch (client.flags) {
        case tcp_accept: {
            cargo = slice_cut(cargo, 0, cargo_capacity);
            client.flags = tcp_read | tls_state_handshake;
            break;
        }
        case tcp_read | tls_state_handshake: {
            u8 error = tls_process_handshake(&client.ctx.tls, &cargo);
            if (error) {
                assert(false);
                client.flags = tcp_disconnect;
            }
            else {
                client.flags = tcp_write | tls_state_handshake;
            }
            break;
        }
        case tcp_write | tls_state_handshake: {
            cargo = slice_cut(cargo, 0, cargo_capacity);
            client.flags = tcp_read | tls_state_handshake_finished;
            break;
        }
        case tcp_read | tls_state_handshake_finished: {
            u8 error = tls_decode_handshake_finished(cargo, client.ctx.tls);
            if (error) {
                assert(false);
                client.flags = tcp_disconnect;
            }
            else {
                cargo = slice_cut(cargo, 0, cargo_capacity);
                client.flags = tcp_read;
            }
            break;
            //
            tls_record_ctx record = tls_decode_record(cargo);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }

            u8 content_type_change_cipher_spec = 20;
            if (record.type == content_type_change_cipher_spec)) {
                if (record.fragment.length != 1) {
                    client.flags = tcp_disconnect; // unexpected_message
                    break;
                }

                if (!record.after.length) {
                    cargo = slice_cut(cargo, 0, cargo_capacity);
                    client.flags = tcp_read | tls_state_handshake_finished;
                    break;
                }

                record = tls_decode_record(record.after);
                if (record.error) {
                    client.flags = tcp_disconnect;
                    break;
                }
            }

            client.cts.tls.decryption_count = 0;
            record = tls_decrypt_record(record, &client.ctx.tls);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }

            tls_handshake_ctx handshake = tls_decode_handshake(record.fragment);
            if (handshake.error) {
                client.flags = tcp_disconnect;
                break;
            }

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
                client.flags = tcp_disconnect; // decrypt_error
                break;
            }

            client.ctx.tls = tls_cipher_keys(client.ctx.tls);
            tls.decryption_count = 0;

            if (!record.after.length) {
                cargo = slice_cut(cargo, 0, cargo_capacity);
                client.flags = tcp_read;
                break;
            }

            record = tls_decode_encrypted_record(record.after);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }

            slice space = string_to_slice(" ");
            slice http_get = string_to_slice("GET");

            slice method = slice_around(&record.fragment, space);
            if (!slices_equal(method, http_get)) {
                assert(false);
            }

            // ...
            break;
        }
        case tcp_read: {
            if (!cargo.length) {
                assert(false);
                // disconnect;
            }

            record = tls_decode_encrypted_record(cargo);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }
            
            slice space = string_to_slice(" ");
            slice http_get = string_to_slice("GET");

            slice method = slice_around(&record.fragment, space);
            if (!slices_equal(method, http_get)) {
                assert(false);
            }

            client.flags = file_open;
            //slice url = slice_around(&record.fragment, space);
            static char name[] = "main.html";
            slice url = string_to_slice(name);
            client.file_data.items = url.items;
            client.file_data.length = (u32) url.length;

            break;
        }
        case file_found: {
            client.flags = file_read;
            trigger_breakpoint();
            // ...
        }
    }

    client.cargo.items = cargo.items;
    client.cargo.length = (u32) cargo.length;
    return client;
}