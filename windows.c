#include "windows.h"

int WinMain(
  HINSTANCE hInstance,
  HINSTANCE hPrevInstance,
  LPSTR lpCmdLine,
  int nShowCmd
) {

    server_ctx config = start();
    windows_server_ctx server = windows_init(config);

    server.pending_client = server.free_client;
    if (server.pending_client) {
        server.free_client = server.pending_client->next;
        server.pending_client->external.flags = tcp_accept;
    }

    while (true) {

        if (server.pending_client) {
            if (server.pending_client->external.flags == tcp_accept) {
                windows_tcp_accept(server.pending_client, server.listener);
            }
            if (server.pending_client->external.flags == tcp_disconnect) {
                server.pending_client->external.flags = tcp_accept;
                windows_tcp_disconnect(server.pending_client);
            }
        }

        windows_client_ctx* client = windows_io_port_read(&server);

        if (!client || client == server.pending_client) {
            continue;
        }

        client->external = process_tcp_client(client->external);

        if (flag_is_set(client->external.flags, file_open)) {
            windows_file_open(client, &server);
            client->external = process_tcp_client(client->external);
        }

        if (flag_is_set(client->external.flags, file_close)) {
            flag_clear(client->external.flags, file_close);
            BOOL success = CloseHandle(client->file);
            assert(success);
        }

        if (flag_is_set(client->external.flags, tcp_write)) {
            windows_tcp_write(client);
        }
        else if (flag_is_set(client->external.flags, tcp_read)) {
            windows_tcp_read(client);
        }
        else if (flag_is_set(client->external.flags, file_read)) {
            windows_file_read(client);
        }

        if (client->external.flags == tcp_disconnect) {
            windows_tcp_disconnect(client);
        }

        if (!client->external.flags) {
            if (!server.pending_client) {
                server.pending_client = client;
                server.pending_client->external.flags = tcp_accept;
            }
            else {
                client->next = server.free_client;
                server.free_client = client;
            }
        }
    }
}

windows_server_ctx windows_init(server_ctx server) {
    HANDLE io_port = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, 
        NULL, 
        0,
        1
    );
    assert(io_port);

    {
        WSADATA data;
        int error = WSAStartup(MAKEWORD(2,2), &data);
        assert(!error);
    }

    SOCKET listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    assert(listener != INVALID_SOCKET);

    {
        DWORD option = 0;
        int error = setsockopt(
            listener,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (char*) &option,
            sizeof(option)
        );
        assert(!error);
    }

    {
        struct addrinfo* result;
        struct addrinfo hints = {
            .ai_family = AF_INET6,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
            .ai_flags = AI_PASSIVE
        };
        INT error = getaddrinfo(
            NULL,
            server.port,
            &hints,
            &result
        );
        assert(!error);

        int bind_error = bind(
            listener,
            result->ai_addr,
            (int) result->ai_addrlen
        );
        assert(!bind_error);

        freeaddrinfo(result);
    }

    {
        int error = listen(listener, SOMAXCONN);
        assert(!error);
    }

    io_port = CreateIoCompletionPort(
        (HANDLE) listener,
        io_port,
        (ULONG_PTR) listener,
        0
    );
    assert(io_port);

    {
        int error = WSAIoctl(
            listener,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &(GUID) WSAID_ACCEPTEX,
            sizeof(GUID),
            &fn_AcceptEx,
            sizeof(fn_AcceptEx),
            &(DWORD) { 0 },
            NULL,
            NULL
        );
        assert(!error);
    }

    {
        int error = WSAIoctl(
            listener,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &(GUID) WSAID_DISCONNECTEX,
            sizeof(GUID),
            &fn_DisconnectEx,
            sizeof(fn_DisconnectEx),
            &(DWORD) { 0 },
            NULL,
            NULL
        );
        assert(!error);
    }

    size_t client_size = sizeof(windows_client_ctx) + server.cargo_capacity;
    size_t client_arena_size = client_size * server.client_capacity;
    u8* client_arena = VirtualAlloc(
        NULL,
        client_arena_size,
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_READWRITE
    );
    assert(client_arena);

    windows_client_ctx* free_client = 0;

    for (size_t i = 0; i < server.client_capacity; i += 1) {
        windows_client_ctx* client = (void*) client_arena;
        client_arena += sizeof(windows_client_ctx);

        client->external.cargo.items = (void*) client_arena;
        client_arena += server.cargo_capacity;

        client->next = free_client;
        free_client = client;

        client->socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        assert(client->socket != INVALID_SOCKET);
        
        DWORD option = 0;
        int error = setsockopt(
            client->socket,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (char*) &option,
            sizeof(option)
        );
        assert(!error);

        io_port = CreateIoCompletionPort(
            (HANDLE) client->socket, 
            io_port, 
            (ULONG_PTR) client, 
            0
        );
        assert(io_port);
    }

    windows_server_ctx windows_server;
    windows_server.io_port = io_port;
    windows_server.listener = listener;
    windows_server.free_client = free_client;
    return windows_server;
}

windows_client_ctx* windows_io_port_read(windows_server_ctx* server) {
    windows_client_ctx* client;

    DWORD io_length;
    ULONG_PTR io_key;
    LPOVERLAPPED io_data;
    BOOL success = GetQueuedCompletionStatus(
        server->io_port,
        &io_length,
        &io_key,
        &io_data,
        INFINITE 
    );

    if (!success) {
        DWORD code = GetLastError();
        assert(code == ERROR_NETNAME_DELETED);

        if (io_key == server->listener) {
            client = server->pending_client;
            client->external.flags = tcp_disconnect;
            return client;
        }
        else {
            client = (windows_client_ctx*) io_key;
            client->external.flags = tcp_disconnect;
            windows_tcp_disconnect(client);
            return 0;
        }
    }

    if (io_key == server->listener) {
        client = server->pending_client;
        client->external.flags = tcp_accept;

        server->pending_client = server->free_client;
        if (server->pending_client) {
            server->free_client = server->pending_client->next;
            server->pending_client->external.flags = tcp_accept;
        }

        return client;
    }

    client = (windows_client_ctx*) io_key;
    
    if (client->external.flags == file_read) {
        client->external.file_data.length = io_length;
    } 
    else if (flag_is_set(client->external.flags, tcp_read)) {
        client->external.cargo.length = io_length;
    } 

    return client;
}

void windows_tcp_accept(windows_client_ctx* client, SOCKET listener) {
    client->external.flags = 0;
    client->io_data = (OVERLAPPED) { 0 };
    static u8 address[2 * (sizeof(SOCKADDR_STORAGE) + 16)]; // unused
    DWORD length; // unused
    BOOL success = fn_AcceptEx(
        listener,
        client->socket,
        address,
        0,  
        sizeof(SOCKADDR_STORAGE) + 16,
        sizeof(SOCKADDR_STORAGE) + 16,
        &length, 
        &client->io_data
    );
    if (!success) {
        DWORD code = GetLastError();
        assert(
            code == ERROR_IO_PENDING ||
            code == WSAECONNRESET
        );
        if (code != ERROR_IO_PENDING) {
            client->external.flags = tcp_disconnect;
        }
    }
}

void windows_tcp_disconnect(windows_client_ctx* client) {
    client->io_data = (OVERLAPPED) { 0 };
    BOOL success = fn_DisconnectEx(
        client->socket,
        &client->io_data,
        TF_REUSE_SOCKET,
        0
    );
    DWORD code = GetLastError();
    assert(success || code == ERROR_IO_PENDING);
}

void windows_tcp_read(windows_client_ctx* client) {
    // The reason I'm making this static is because I'm worried that writing
    // the memory after the scope exits might cause a bug with this API
    // as a result of WSARecv possibly reading the pointer's value asynchronously.
    static DWORD flags = 0;
    client->io_data = (OVERLAPPED) { 0 };
    int error = WSARecv(
        client->socket,
        (LPWSABUF) &client->external.cargo,
        1,
        NULL,
        &flags, 
        &client->io_data,
        NULL
    );
    if (error) {
        DWORD code = GetLastError();
        assert(
            code == WSA_IO_PENDING  ||
            code == WSAECONNABORTED ||
            code == WSAECONNRESET   ||
            code == WSAENETRESET    ||
            code == WSAETIMEDOUT
        );
        if (code != WSA_IO_PENDING) {
            client->external.flags = tcp_disconnect;
        }
    }
}

void windows_tcp_write(windows_client_ctx* client) {
    client->io_data = (OVERLAPPED) { 0 };
    int error = WSASend(
        client->socket,
        (LPWSABUF) &client->external.cargo,
        1,
        NULL,
        0,
        &client->io_data,
        NULL
    );
    if (error) {
        DWORD code = GetLastError();
        assert(
            code == WSA_IO_PENDING  ||
            code == WSAECONNABORTED ||
            code == WSAECONNRESET   ||
            code == WSAENETRESET
        );
        if (code != WSA_IO_PENDING) {
            client->external.flags = tcp_disconnect;
        }
    }
}

void windows_file_open(windows_client_ctx* client, windows_server_ctx* server) {
    char path[MAX_PATH];

    WIN32_FIND_DATA item;
    HANDLE handle = FindFirstFile("assets/*", &item);
    assert(handle != INVALID_HANDLE_VALUE);

    int found = 0;
    while (true) {
        if (!(item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            slice filename = string_to_slice(item.cFileName);
            slice given_filename = slice_make(
                client->external.file_data.length,
                client->external.file_data.length,
                client->external.file_data.items
            );
            found = slices_equal(filename, given_filename);
        }

        if (found) {
            break;
        }

        BOOL success = FindNextFile(handle, &item);
        if (!success) {
            DWORD code = GetLastError();
            assert(code == ERROR_NO_MORE_FILES);
            break;
        }
    }

    BOOL success = FindClose(handle);
    assert(success);

    flag_clear(client->external.flags, file_open);
    if (found) {
        client->external.flags |= file_found;

        string_copy(path, "assets/");
        string_append(path, item.cFileName);
        client->file = CreateFile(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL
        );
        assert(client->file != INVALID_HANDLE_VALUE);

        LARGE_INTEGER file_length;
        BOOL success = GetFileSizeEx(client->file, &file_length);
        client->external.file_length = (u64) file_length.QuadPart;

        server->io_port = CreateIoCompletionPort(
            client->file, 
            server->io_port, 
            (ULONG_PTR) client, 
            0
        );
        assert(server->io_port);
    }
    else {
        client->external.flags |= file_not_found;
    }
}

void windows_file_read(windows_client_ctx* client) {
    client->io_data = (OVERLAPPED) { 0 };
    client->io_data.OffsetHigh = (DWORD) (client->external.file_offset >> 32);
    client->io_data.Offset = (DWORD) client->external.file_offset;
    static DWORD length;
    BOOL success = ReadFile(
        client->file,
        (LPVOID) client->external.file_data.items,
        client->external.file_data.length,
        &length, 
        &client->io_data
    );
    DWORD code = GetLastError();
    assert(success || code == ERROR_IO_PENDING);
}

void crypto_random(u8* out, u32 length) {
    NTSTATUS status = BCryptGenRandom(
        NULL,
        out,
        length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    assert(status == STATUS_SUCCESS);
}

void trigger_breakpoint() {
    DebugBreak();
}