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

#define WS_OP_CONTINUE 0
#define WS_OP_TEXT 1
#define WS_OP_BINARY 2
#define WS_OP_CLOSE 8
#define WS_OP_PING 9
#define WS_OP_PONG 10

#define WS_FLAGS_MASK_OP 15

struct ssl_ctx_st;
struct ssl_st;
struct evhttp_connection;
struct evhttp_request;

class libeventWS
{
public:
	~libeventWS();
	void close();

    bool is_active = false;
    bool is_client = false;
	evhttp_connection* evConn = nullptr;
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;

	function<int(libeventWS*)> conn_cb = nullptr;
	function<int(libeventWS*)> disconn_cb = nullptr;
	function<int(libeventWS*, uint8_t*, size_t)> rd_cb = nullptr;
	function<int(libeventWS*)> wr_cb = nullptr;
};

// 服务端
libeventWS* handleWebsocketRequest(
	evhttp_request* req, 
	void* arg,
	function<int(libeventWS*)> conn_cb,
	function<int(libeventWS*)> disconn_cb,
	function<int(libeventWS*, uint8_t*, size_t)> rd_cb,
	function<int(libeventWS*)> wr_cb
	);

// 客户端
libeventWS* websocketConnect(struct event_base* eventBase,
	const char* url,
	function<int(libeventWS*)> conn_cb,
	function<int(libeventWS*)> disconn_cb,
	function<int(libeventWS*, uint8_t*, size_t)> rd_cb,
	function<int(libeventWS*)> wr_cb,
	bool useSSL = false, 
	const char* localIP = "0.0.0.0",
	int localPort = 0
	);

// 发送数据
int websocketSend(libeventWS* ws, uint8_t* pdata, size_t size, uint8_t op = WS_OP_BINARY);
