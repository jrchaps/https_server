#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include "ntstatus.h"
#include <bcrypt.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Bcrypt.lib")

#include <basic/basic.c>

#define flag_is_set(a, b) (a & b)
#define flag_clear(a, b) { a = a ^ b; }

#define tcp_accept     1 << 0
#define tcp_disconnect 1 << 1
#define tcp_read       1 << 2
#define tcp_write      1 << 3
#define file_open      1 << 4
#define file_close     1 << 5
#define file_found     1 << 6
#define file_not_found 1 << 7
#define file_read      1 << 8

typedef struct server_ctx server_ctx;
typedef struct windows_server_ctx windows_server_ctx;
typedef struct tcp_client_buffer tcp_client_buffer;
typedef struct client_ctx client_ctx;
typedef struct tcp_client_ctx tcp_client_ctx;
typedef struct windows_client_ctx windows_client_ctx;

LPFN_ACCEPTEX fn_AcceptEx;
LPFN_DISCONNECTEX fn_DisconnectEx;

server_ctx start(void);
tcp_client_ctx process_tcp_client(tcp_client_ctx);

windows_server_ctx windows_init(server_ctx);
windows_client_ctx* windows_io_port_read(windows_server_ctx* server);
void windows_tcp_accept(windows_client_ctx* client, SOCKET listener);
void windows_tcp_disconnect(windows_client_ctx* client);
void windows_tcp_write(windows_client_ctx* client);
void windows_tcp_read(windows_client_ctx* client);
void windows_file_open(windows_client_ctx* client, windows_server_ctx* server);
void windows_file_read(windows_client_ctx* client);

struct server_ctx {
    size_t client_capacity;
    u32 cargo_capacity;
    char* port;
};

struct windows_server_ctx {
    HANDLE io_port;
    SOCKET listener;
    windows_client_ctx* free_client;
    windows_client_ctx* pending_client;
};

struct tcp_client_buffer {
    u32 length;
    u8* items;
};

struct tcp_client_ctx {
    client_ctx ctx;
    u32 flags;
    u64 file_offset;
    u64 file_length;
    tcp_client_buffer file_data;
    tcp_client_buffer cargo;
};

struct windows_client_ctx {
    windows_client_ctx* next;
    OVERLAPPED io_data;
    SOCKET socket;
    HANDLE file;
    tcp_client_ctx external;
};