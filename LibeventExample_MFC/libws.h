#pragma once

#include <functional>
using std::function;

struct ws_msg 
{
	uint8_t flags;
	size_t headerSize;
	size_t dataSize;
};

#ifdef WIN32
#define libws_strcasecmp strcmp
#else
#define libws_strcasecmp strcasecmp
#endif

#define LIBWS_OP_CONTINUE 0
#define LIBWS_OP_TEXT 1
#define LIBWS_OP_BINARY 2
#define LIBWS_OP_CLOSE 8
#define LIBWS_OP_PING 9
#define LIBWS_OP_PONG 10

#define LIBWS_FLAGS_MASK_OP 15

struct ssl_ctx_st;
struct ssl_st;
struct evhttp_connection;
struct evhttp_request;

struct libws_t
{
    evhttp_connection *conn = nullptr;
    bool is_active = false;
    bool is_client = false;
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;

	function<int(libws_t*)> conn_cb = nullptr;
	function<int(libws_t*)> disconn_cb = nullptr;
	function<int(libws_t*, uint8_t*, size_t)> rd_cb = nullptr;
	function<int(libws_t*)> wr_cb = nullptr;
};

libws_t* libws_upgrade(
	evhttp_request* req, 
	void* arg,
	function<int(libws_t*)> conn_cb,
	function<int(libws_t*)> disconn_cb,
	function<int(libws_t*, uint8_t*, size_t)> rd_cb,
	function<int(libws_t*)> wr_cb
	);

libws_t* libws_connect(struct event_base* eventBase,
	const char* url,
	function<int(libws_t*)> conn_cb,
	function<int(libws_t*)> disconn_cb,
	function<int(libws_t*, uint8_t*, size_t)> rd_cb,
	function<int(libws_t*)> wr_cb,
	bool useSSL = false, 
	const char* localIP = "0.0.0.0",
	int localPort = 0
	);

int libws_send(libws_t* pws, uint8_t* pdata, size_t size, uint8_t op);
