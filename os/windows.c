#include "windows.h"

#define flag_is_set(a, b) (a & b)
#define flag_clear(a, b) { a = a ^ b; }

windows_client_ctx* client_allocate(windows_client_ctx** head) {
    if (!*head) return *head;
    windows_client_ctx* client = *head;
    *head = client->next;
    return client;
} 

void client_free(windows_client_ctx** head, windows_client_ctx* client) {
    client->next = *head;
    *head = client;
}

LPFN_ACCEPTEX fn_AcceptEx;
LPFN_DISCONNECTEX fn_DisconnectEx;

u32 tcp_read = 1 << 0;
u32 tcp_write = 1 << 1;  
u32 tcp_disconnect = 1 << 2;

//
u32 file_open = 1 << 8;
u32 file_read = 1 << 5;
u32 file_not_found = 1 << 6;
u32 file_found = 1 << 7;

int WinMain(
  HINSTANCE hInstance,
  HINSTANCE hPrevInstance,
  LPSTR lpCmdLine,
  int nShowCmd
) {

    server_ctx ctx = start();
    size_t client_capacity = ctx.client_capacity;
    u32 cargo_capacity = ctx.cargo_capacity;
    char* port = ctx.port;

    u32 tcp_accept = 1 << 3;
    u32 tcp_free = 1 << 4;

    HANDLE io_port = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, 
        NULL, 
        0,
        1 // todo: change when multithreading
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
            port,
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

    size_t size = (sizeof(windows_client_ctx) + cargo_capacity) * client_capacity;
    u8* base_address = VirtualAlloc(
        NULL,
        size,
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_READWRITE
    );
    assert(base_address);

    arena client_arena = arena_make(base_address, size);

    windows_client_ctx* client_pool = 0;

    for (size_t i = 0; i < client_capacity; i += 1) {
        windows_client_ctx* client = arena_allocate(&client_arena, sizeof(windows_client_ctx));
        client->cargo.buf = arena_allocate(&client_arena, cargo_capacity);

        // todo: client_free?
        client->next = client_pool;
        client_pool = client;

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

    windows_client_ctx* new_client = client_allocate(&client_pool);
    if (new_client) {
        new_client->flags = tcp_accept;
    }

    #define address_length (sizeof(SOCKADDR_STORAGE) + 16)
    u8 address[2 * address_length];

    while (true) {

        if (new_client) {
            if (new_client->flags == tcp_accept) {
                new_client->flags = 0;
                DWORD length;
                new_client->io_data = (OVERLAPPED) { 0 };
                BOOL success = fn_AcceptEx(
                    listener,
                    new_client->socket,
                    address,
                    0,  
                    address_length,
                    address_length,
                    &length, 
                    &new_client->io_data
                );
                if (!success) {
                    DWORD code = GetLastError();
                    assert(
                        code == ERROR_IO_PENDING ||
                        code == WSAECONNRESET
                    );
                    if (code != ERROR_IO_PENDING) {
                        new_client->flags = tcp_disconnect;
                    }
                }
            }

            if (new_client->flags == tcp_disconnect) {
                new_client->flags = tcp_accept;
                new_client->io_data = (OVERLAPPED) { 0 };
                BOOL success = fn_DisconnectEx(
                    new_client->socket,
                    &new_client->io_data,
                    TF_REUSE_SOCKET,
                    0
                );
                DWORD code = GetLastError();
                assert(success || code == ERROR_IO_PENDING);
            }
        }

        LPOVERLAPPED io_data;
        DWORD io_length;
        ULONG_PTR io_key;
        BOOL success = GetQueuedCompletionStatus(
            io_port,
            &io_length,
            &io_key,
            &io_data,
            INFINITE 
        );

        windows_client_ctx* client;

        if (!success) {
            DWORD code = GetLastError();
            assert(code == ERROR_NETNAME_DELETED);
            if (io_key == listener) {
                client = new_client;
                client->flags = tcp_disconnect;
            }
            else {
                client = (windows_client_ctx*) io_key;
                client->flags = tcp_disconnect;
            }
        }
        else if (io_key == listener) {
            client = new_client;
            client->flags = tcp_accept;
            new_client = client_allocate(&client_pool);
            if (new_client) {
                new_client->flags = tcp_accept;
            }
        }
        else {
            client = (windows_client_ctx*) io_key;
        }

        if (client == new_client) {
            continue;
        }

        if (client->flags == tcp_accept) {
            client->flags = tcp_read;
        }
        else if (flag_is_set(client->flags, tcp_write)) {
            flag_clear(client->flags, tcp_write);
        }
        else if (flag_is_set(client->flags, tcp_read)) {
            flag_clear(client->flags, tcp_read);
        }

        if (client->flags == tcp_read) {
            client->cargo.len = cargo_capacity;
        }
        else {
            client->cargo.len = io_length;
        }
        
        if (client->flags == file_read) {
            windows_client_ctx* test = client;
        }

        process_client_ctx ctx;
        if (!client->flags) {
            slice cargo = slice_make(
                cargo_capacity,
                client->cargo.len,
                (u8*) client->cargo.buf
            );
            ctx = process_client(
                client->client,
                cargo,
                client->flags
            );
            client->client = ctx.client;
            client->flags = ctx.flags;
            client->cargo.len = (ULONG) ctx.cargo.length;
            client->cargo.buf = (CHAR*) ctx.cargo.items;
            assert(
                client->flags == tcp_write ||
                client->flags == tcp_read ||
                client->flags == (tcp_write | tcp_read) ||
                client->flags == (tcp_write | tcp_disconnect) ||
                client->flags == tcp_disconnect ||
                client->flags == file_read ||
                client->flags == file_open
            );
        }

        if (flag_is_set(client->flags, file_open)) {
            char path[MAX_PATH];

            WIN32_FIND_DATA item;
            HANDLE handle = FindFirstFile("assets/*", &item);
            assert(handle != INVALID_HANDLE_VALUE);

            client->flags = file_not_found;
            while (true) {

                if (!(item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    slice filename = string_to_slice(item.cFileName);
                    if (slices_equal(filename, ctx.filename)) {
                        client->flags = file_found;
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
                        io_port = CreateIoCompletionPort(
                            client->file, 
                            io_port, 
                            (ULONG_PTR) client, 
                            0
                        );
                        assert(io_port);
                        break;
                    }
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


            slice cargo = slice_make(
                cargo_capacity,
                client->cargo.len,
                (u8*) client->cargo.buf
            );
            ctx = process_client(
                client->client,
                cargo,
                client->flags
            );
            client->client = ctx.client;
            client->flags = ctx.flags;
            client->cargo.len = (ULONG) ctx.cargo.length;
            client->cargo.buf = (CHAR*) ctx.cargo.items;
        }

        if (flag_is_set(client->flags, file_read)) {
            client->file_index = 0;
            client->io_data = (OVERLAPPED) { 0 };
            client->io_data.OffsetHigh = (DWORD) (client->file_index >> 32);
            client->io_data.Offset = (DWORD) client->file_index;
            BOOL success = ReadFile(
                client->file,
                client->cargo.buf,
                cargo_capacity,
                (LPDWORD) &client->cargo, // todo: probably change this to a static dummy
                &client->io_data
            );
            DWORD code = GetLastError();
            assert(success || code == ERROR_IO_PENDING);
        }
        else if (client->flags == tcp_free) {
            client_free(&client_pool, client);
        }
        else if (flag_is_set(client->flags, tcp_write)) {
            client->io_data = (OVERLAPPED) { 0 };
            int error = WSASend(
                client->socket,
                &client->cargo,
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
                    client->flags = tcp_disconnect;
                }
            }
        }
        else if (flag_is_set(client->flags, tcp_read)) {
            static DWORD flags = 0; // see WSARecv comment
            client->io_data = (OVERLAPPED) { 0 };
            int error = WSARecv(
                client->socket,
                &client->cargo,
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
                    client->flags = tcp_disconnect;
                }
            }
        }

        if (client->flags == tcp_disconnect) {
            if (!new_client) {
                new_client = client;
                new_client->flags = tcp_accept;
            }
            else {
                client->flags = tcp_free;
            }
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

    }
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

// WSARecv comment
// The reason I'm making this static is because I'm worried that writing
// the memory after the scope exits might cause a bug with this API
// as a result of WSARecv possibly reading the pointer's value asynchronously.