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
    slice cargo = slice_make(
        cargo_capacity,
        client.cargo.length,
        client.cargo.items
    );

    slice file_data = slice_make(
        cargo_capacity,
        client.file_data.length,
        client.file_data.items
    );

    switch (client.flags) {
        case tcp_accept: {
            cargo = slice_cut(cargo, 0, cargo_capacity);
            client.flags = tcp_read | tls_state_handshake;
            break;
        }
        case tcp_disconnect: {
            client.flags = 0;
            break;
        }
        case tcp_write | tcp_disconnect: {
            client.flags = tcp_disconnect;
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
            tls_record_ctx record = tls_decode_record(cargo);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }

            slice type_change_cipher_spec = slice_literal(20);
            if (slices_equal(record.type, type_change_cipher_spec)) {
                if (!record.after.length) {
                    cargo = slice_cut(cargo, 0, cargo_capacity);
                    client.flags = tcp_read | tls_state_handshake_finished; // todo: ehh
                    break;
                }

                record = tls_decode_record(record.after);
                if (record.error) {
                    client.flags = tcp_disconnect;
                    break;
                }
            }

            client.ctx.tls.decryption_count = 0;
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

            u8 error = tls_verify_handshake_finished(handshake, client.ctx.tls);
            if (error) {
                client.flags = tcp_disconnect;
                break;
            }

            client.ctx.tls = tls_cipher_keys(client.ctx.tls);
            client.ctx.tls.decryption_count = 0;
            client.ctx.tls.encryption_count = 0;

            if (!record.after.length) {
                cargo = slice_cut(cargo, 0, cargo_capacity);
                client.flags = tcp_read;
                break;
            }

            record = tls_decode_encrypted_record(record.after, &client.ctx.tls);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }

            slice separator = string_to_slice(" /");
            slice method = slice_around(&record.fragment, separator);

            slice http_method_get = string_to_slice("GET");
            if (!slices_equal(method, http_method_get)) {
                assert(false);
            }

            separator = string_to_slice(" ");
            slice url = slice_around(&record.fragment, separator);
            if (!url.length) {
                url = string_to_slice("main.html");
            }

            file_data = url;
            client.flags = file_open;
            break;
        }
        case tcp_read: {
            if (!cargo.length) {
                client.flags = tcp_disconnect;
                break;
            }

            tls_record_ctx record = tls_decode_encrypted_record(cargo, &client.ctx.tls);
            if (record.error) {
                client.flags = tcp_disconnect;
                break;
            }
            
            slice separator = string_to_slice(" /");
            slice method = slice_around(&record.fragment, separator);

            slice http_method_get = string_to_slice("GET");
            if (!slices_equal(method, http_method_get)) {
                assert(false);
            }

            separator = string_to_slice(" ");
            slice url = slice_around(&record.fragment, separator);
            if (!url.length) {
                url = string_to_slice("main.html");
            }

            file_data = url;
            client.flags = file_open;
            break;
        }
        case file_found: {
            cargo = slice_clear(cargo);
            cargo = tls_encrypted_record_start(cargo);

            slice http_header = string_to_slice(
                "HTTP/1.1 200 OK \r\nContent-Length:"
            );
            cargo = append(cargo, http_header);
            cargo = append_ascii_decimal(cargo, client.file_length);
            cargo = append(cargo, string_to_slice("\r\n\r\n"));

            size_t tls_record_footer_length = poly1305_auth_tag_length + 1;
            file_data = slice_cut(
                cargo, 
                cargo.length, 
                cargo_capacity -
                tls_record_footer_length
            );

            client.file_offset = 0;
            client.flags = file_read;
            break;
        }
        case file_not_found: {
            cargo = slice_clear(cargo);
            cargo = tls_encrypted_record_start(cargo);
            slice status_line = string_to_slice("HTTP/1.1 404 Not Found\r\n\r\n");
            cargo = append(cargo, status_line);
            cargo = tls_encrypted_record_end(cargo, 23, &client.ctx.tls);
            client.flags = tcp_write | tcp_disconnect;
            break;
        }
        case file_read: {
            cargo = slice_up(cargo, file_data.length);
            cargo = tls_encrypted_record_end(cargo, 23, &client.ctx.tls);

            client.file_offset += file_data.length;
            client.flags = tcp_write | file_read;
            break;
        }
        case tcp_write | file_read: {
            if (client.file_offset == client.file_length) {
                cargo = slice_cut(cargo, 0, cargo_capacity);
                client.flags = tcp_read | file_close;
            }
            else {
                cargo = slice_clear(cargo);
                cargo = tls_encrypted_record_start(cargo);

                size_t tls_record_footer_length = poly1305_auth_tag_length + 1;
                file_data = slice_cut(
                    cargo, 
                    cargo.length, 
                    cargo_capacity -
                    tls_record_footer_length
                );

                client.flags = file_read;
            }
            break;
        }
        default: {
            assert(false);
        }
    }

    client.cargo.items = cargo.items;
    client.cargo.length = (u32) cargo.length;
    client.file_data.items = file_data.items;
    client.file_data.length = (u32) file_data.length;
    return client;
}