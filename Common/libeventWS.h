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

class LibeventWS
{
public:
	LibeventWS();
	~LibeventWS();

    bool is_active = false;
    bool is_client = false;
	struct evhttp_connection* evConn = nullptr;
	struct bufferevent* bev = nullptr;
	struct ssl_ctx_st* ssl_ctx = nullptr;
	struct ssl_st* ssl = nullptr;
	struct evbuffer* recvBuf = nullptr;
	void* arg = nullptr;

	function<int(LibeventWS*)> conn_cb = nullptr;
	function<int(LibeventWS*)> disconn_cb = nullptr;
	function<int(LibeventWS*, uint8_t*, size_t)> rd_cb = nullptr;
	function<int(LibeventWS*)> wr_cb = nullptr;

	// 发送数据
	int Send(uint8_t* pdata, size_t size, uint8_t op = WS_OP_BINARY);

	// 关闭连接
	void Close();
};

// 服务端
LibeventWS* handleWebsocketRequest(
	struct evhttp_request* req,
	void* arg,
	function<int(LibeventWS*)> conn_cb,
	function<int(LibeventWS*)> disconn_cb,
	function<int(LibeventWS*, uint8_t*, size_t)> rd_cb,
	function<int(LibeventWS*)> wr_cb
	);

// 客户端
LibeventWS* websocketConnect(struct event_base* eventBase,
	const char* url,
	function<int(LibeventWS*)> conn_cb,
	function<int(LibeventWS*)> disconn_cb,
	function<int(LibeventWS*, uint8_t*, size_t)> rd_cb,
	function<int(LibeventWS*)> wr_cb,
	bool useSSL = false, 
	const char* localIP = "0.0.0.0",
	int localPort = 0
	);
