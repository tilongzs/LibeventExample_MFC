#pragma once

#include <inttypes.h>
#include <functional>

#include "event2/event.h"
#include "event2/thread.h"
#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_ssl.h"
#include "event2/buffer.h"
#include "event2/listener.h"
#include "event2/http.h"
#include "event2/keyvalq_struct.h"
#include "event2/http_struct.h"

using std::function;

class CLibeventExample_MFCDlg;

struct ws_msg {
	uint8_t flags;
	size_t header_len;
	size_t data_len;
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

#define LIBWS_FLAGS_MASK_FIN 128
#define LIBWS_FLAGS_MASK_OP 15

struct ssl_ctx_st;
struct ssl_st;

struct libws_t
{
    CLibeventExample_MFCDlg* dlg = nullptr;
    struct evhttp_connection *conn = nullptr;
    uint64_t ms = 0;
    bool is_active = false;     // 是否可用
    bool is_client = false;     // 是不是客户端，用来发送MASK位
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;

	function<int(libws_t*)> conn_cb = nullptr;
	function<int(libws_t*)> disconn_cb = nullptr;
	function<int(libws_t*, uint8_t*, size_t)> rd_cb = nullptr;
	function<int(libws_t*)> wr_cb = nullptr;
};

int libws_send(libws_t* pws, uint8_t* pdata, size_t size, uint8_t op);
struct libws_t *libws_connect(struct event_base *eventBase,
                            const char *url,
                            function<int(libws_t*)> conn_cb,
                            function<int(libws_t*)> disconn_cb,
	                        function<int(libws_t*, uint8_t*, size_t)> rd_cb,
	                        function<int(libws_t*)> wr_cb,
                            CLibeventExample_MFCDlg* dlg);

struct libws_t* libws_connect(struct event_base* eventBase,
	const char* url,
	const char* localIP,
	int localPort,
	bool useSSL,
	function<int(libws_t*)> conn_cb,
	function<int(libws_t*)> disconn_cb,
	function<int(libws_t*, uint8_t*, size_t)> rd_cb,
	function<int(libws_t*)> wr_cb,
	CLibeventExample_MFCDlg* dlg);

