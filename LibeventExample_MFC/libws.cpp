#include "pch.h"
#include "libws.h"
#include "Common/sha1.h"
#include "Common/base64.h"
#include "Common/Common.h"
#include <queue>
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
#include "event2/bufferevent_struct.h"

using namespace std;

// OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define SINGLE_PACKAGE_SIZE 1024 * 64 // 默认16384

static void libws_close_cb(struct evhttp_connection *conn, void *arg)
{
    libws_t* pws = (libws_t*)arg;

    if (pws->disconn_cb)
    {
        pws->disconn_cb(pws);
    }

    delete pws;
}

static size_t libws_process(uint8_t* buf, size_t len, struct ws_msg* msg)
{
	if (NULL == msg)
		return 0;
	if (NULL == buf)
		return 0;
	memset(msg, 0, sizeof(ws_msg));
	size_t mask_len = 0;
	if (len >= 2)
	{
		msg->flags = buf[0];
		size_t n = buf[1] & 0x7f;
		mask_len = buf[1] & 0x80 ? 4 : 0;
		if (n < 126 && len >= mask_len)
		{
			msg->headerSize = 2 + mask_len;
			msg->dataSize = n;
		}
		else if (n == 126 && len >= 4 + mask_len)
		{
			msg->headerSize = 4 + mask_len;
			msg->dataSize = buf[2];
			msg->dataSize <<= 8;
			msg->dataSize |= buf[3];
		}
		else if (len >= 10 + mask_len)
		{
			msg->headerSize = 10 + mask_len;
			uint64_t tmp = buf[2];
			tmp <<= 8;
			tmp |= buf[3];
			tmp <<= 8;
			tmp |= buf[4];
			tmp <<= 8;
			tmp |= buf[5];
			tmp <<= 8;
			tmp |= buf[6];
			tmp <<= 8;
			tmp |= buf[7];
			tmp <<= 8;
			tmp |= buf[8];
			tmp <<= 8;
			tmp |= buf[9];
			msg->dataSize = (size_t)tmp;
		}
	}
	if (msg->headerSize + msg->dataSize > len)
		return 0;
	if (mask_len > 0)
	{
		uint8_t* p = buf + msg->headerSize, * m = p - mask_len;
		for (size_t i = 0; i < msg->dataSize; i++)
			p[i] ^= m[i & 3];
	}
	return msg->headerSize + msg->dataSize;
}

static void libws_rdcb(struct bufferevent *bev, void *ctx)
{
    libws_t* pws = (libws_t*)ctx;
    if(!pws->is_active)
        return;

	if (NULL == pws->conn)
		return;

	struct ws_msg msg;
	uint8_t* buf;
	size_t res;
	ev_ssize_t size;
	for (size = 1, res = 1; res && size;)
	{
		size = (ev_ssize_t)evbuffer_get_length(bev->input);
		buf = evbuffer_pullup(bev->input, size);
		res = libws_process(buf, (size_t)size, &msg);
		if (res)
		{
			switch (msg.flags & LIBWS_FLAGS_MASK_OP)
            {
			    case LIBWS_OP_CONTINUE:
			    	break;
			    case LIBWS_OP_PING:
			    	libws_send(pws, (uint8_t*)&buf[msg.headerSize], msg.dataSize, LIBWS_OP_PONG);
			    	break;
			    case LIBWS_OP_PONG:
			    	break;
			    case LIBWS_OP_TEXT:
			    case LIBWS_OP_BINARY:
			    	if (pws->rd_cb)
			    		pws->rd_cb(pws, &buf[msg.headerSize], msg.dataSize);
			    	break;
			    case LIBWS_OP_CLOSE:
			    	evhttp_connection_free(pws->conn);
			    	return;
			    default:
			    	evhttp_connection_free(pws->conn); // 收到未知数据时关闭连接
					return;
			}
			evbuffer_drain(bev->input, msg.headerSize + msg.dataSize);
		}
	}
}

static void libws_wrcb(struct bufferevent *bev, void *ctx)
{
    libws_t* p = (libws_t*)ctx;
    if(!p->is_active)
        return;
    if(p->wr_cb)
        p->wr_cb(p);
}

static void libws_evcb(struct bufferevent *bev, short what, void *ctx)
{
    if(what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT))    // 结束、错误、超时，都关闭websocket
    {
		libws_t* pws = (libws_t*)ctx;
        evhttp_connection_free(pws->conn);
    }
    return;
}

static void libws_connect_cb(struct evhttp_request *req, void *arg)
{
    if(NULL == req || NULL == arg)
        return;
	libws_t* pws = (libws_t*)arg;

    if(evbuffer_get_length(req->input_buffer))
        evbuffer_drain(req->input_buffer, evbuffer_get_length(req->input_buffer));
    if(evhttp_request_get_response_code(req)==101)     // 服务器同意升级websocket
    {
        const char* ws_u = evhttp_find_header(req->input_headers,"Upgrade");
        const char* ws_k = evhttp_find_header(req->input_headers,"Sec-WebSocket-Accept");
        if(ws_u && ws_k)
        {
            if(libws_strcasecmp(ws_u,"websocket")==0)
            {
                pws->is_active = true;
                struct bufferevent* bev = evhttp_connection_get_bufferevent(pws->conn);

                // 修改读写上限
                int ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
                if (ret != 0)
                {
                    evhttp_connection_free(pws->conn);
                    return;
                }
                ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
                if (ret != 0)
                {
					evhttp_connection_free(pws->conn);
					return;
                }

                bufferevent_enable(bev, EV_PERSIST | EV_READ | EV_WRITE);
                evhttp_connection_set_timeout(pws->conn, -1);
				bufferevent_setcb(bev, libws_rdcb, libws_wrcb, libws_evcb, pws);
                bufferevent_set_timeouts(bev, NULL, NULL);
#ifdef WIN32
                {
                    int opt = 1;
                    evutil_socket_t fd = bufferevent_getfd(bev);
                    setsockopt((SOCKET)fd, SOL_SOCKET, TCP_NODELAY, (const char*)&opt, sizeof(opt));
                }
#endif
                if(pws->conn_cb)
                    pws->conn_cb(pws);
            }
        }
    }
    else
    {
		// 服务器不正常返回，断开连接
		evhttp_connection_free(pws->conn);
    }
}

static void makeRandom(void* buf, size_t len)
{
    srand(NULL);
    unsigned char* p = (unsigned char*)buf;
    while (len--) *p++ = (unsigned char)(rand() & 255);
}

static size_t makeHeader(size_t len, int op, bool is_client, uint8_t* buf) 
{
	size_t n = 0;
	buf[0] = (uint8_t)(op | 128);
	if (len < 126) {
		buf[1] = (unsigned char)len;
		n = 2;
	}
	else if (len < 65536) 
    {
		uint16_t tmp = htons((uint16_t)len);
		buf[1] = 126;
		memcpy(&buf[2], &tmp, sizeof(tmp));
		n = 4;
	}
	else
    {
		uint32_t tmp;
		buf[1] = 127;
		tmp = htonl((uint32_t)((uint64_t)len >> 32));
		memcpy(&buf[2], &tmp, sizeof(tmp));
		tmp = htonl((uint32_t)(len & 0xffffffff));
		memcpy(&buf[6], &tmp, sizeof(tmp));
		n = 10;
	}

	if (is_client) 
    {
        buf[1] |= 0x80;
        makeRandom(&buf[n], 4);
		n += 4;
	}
	return n;
}

int libws_send(libws_t* pws, uint8_t* pdata, size_t dataSize, uint8_t op)
{
    if(nullptr == pws)
        return -1;
    if(!pdata)
        return -2;
    if(0 == dataSize)
        return -3;
    if(nullptr == pws->conn)   // 未连接成功
        return -4;
    if(!pws->is_active) // 连接无效
        return -5;
    struct bufferevent* bev = evhttp_connection_get_bufferevent(pws->conn);

    struct evbuffer* evBuf = evbuffer_new();

	uint8_t header[14] = {0};
	size_t headerSize = makeHeader(dataSize, op, pws->is_client, header);
    if (0 != evbuffer_add(evBuf, header, headerSize))
    {
        evbuffer_free(evBuf);
        return -6;
    }

	if (0 != evbuffer_add(evBuf, pdata, dataSize))
	{
		evbuffer_free(evBuf);
		return -6;
	}

    // 客户端采用掩码发送
    if (pws->is_client)
    {
		size_t evBufSize = evbuffer_get_length(evBuf);
		uint8_t* buf = evbuffer_pullup(evBuf, evBufSize);
		size_t i;
        uint8_t* p = buf + evBufSize - dataSize;
        uint8_t* mask = p - 4;
		for (i = 0; i < dataSize; i++) 
            p[i] ^= mask[i & 3];
    }

	if (0 != bufferevent_write_buffer(bev, evBuf))
	{
        evbuffer_free(evBuf);
		return -7;
	}
	else
	{
		return (int)(headerSize + dataSize);
	}
}

libws_t* libws_upgrade(evhttp_request* req, void* arg,
	function<int(libws_t*)> conn_cb, 
	function<int(libws_t*)> disconn_cb, 
	function<int(libws_t*, uint8_t*, size_t)> rd_cb, 
	function<int(libws_t*)> wr_cb)
{
	if (NULL == req)
		return nullptr;

	const char* p;
	int ret;
	const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	(void)arg;
	p = evhttp_find_header(req->input_headers, "Upgrade");
	if (p && libws_strcasecmp(p, "websocket"))
	{
		evhttp_send_reply(req, HTTP_BADMETHOD, "", NULL);
		return nullptr;
	}
	p = evhttp_find_header(req->input_headers, "Sec-WebSocket-Version");
	if (p && libws_strcasecmp(p, "13"))
	{
		evhttp_send_reply(req, HTTP_BADMETHOD, "", NULL);
		return nullptr;
	}
	p = evhttp_find_header(req->input_headers, "Sec-WebSocket-Key");
	if (p == NULL)
	{
		evhttp_send_reply(req, HTTP_BADMETHOD, "", NULL);
		return nullptr;
	}

	char buf[256];
	memset(buf, 0, sizeof(buf));
	strcpy(buf, p);
	memcpy(&buf[strlen(buf)], magic, strlen(magic));

	char strSHA1[20];
	ret = mbedtls_sha1_ret((const uint8_t*)buf, (int)strlen(buf), (uint8_t*)strSHA1);
	if (ret != 0)
	{
		evhttp_send_reply(req, HTTP_INTERNAL, "", NULL);
		return nullptr;
	}

	libws_t* pws = new libws_t;
	pws->conn = req->evcon;
	pws->is_active = true;
	pws->conn_cb = conn_cb;
	pws->disconn_cb = disconn_cb;
	pws->rd_cb = rd_cb;
	pws->wr_cb = wr_cb;

	char strBase64[256];
	memset(strBase64, 0, sizeof(strBase64));
	base64_encode((const uint8_t*)strSHA1, 20, strBase64);
	sprintf(buf, "HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"\r\n", strBase64);
	struct bufferevent* bev = evhttp_connection_get_bufferevent(req->evcon);
	bufferevent_enable(bev, EV_PERSIST | EV_READ | EV_WRITE);

	// 修改读写上限（可选）
	ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		return nullptr;
	}
	ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		return nullptr;
	}

	bufferevent_write(bev, buf, strlen(buf));
	evhttp_remove_header(req->output_headers, "Connection");
	evhttp_remove_header(req->input_headers, "Connection");
	evhttp_remove_header(req->output_headers, "Proxy-Connection");
	evhttp_remove_header(req->input_headers, "Proxy-Connection");
	evhttp_add_header(req->output_headers, "Connection", "keep-alive");
	evhttp_add_header(req->input_headers, "Connection", "keep-alive");
	evhttp_add_header(req->output_headers, "Proxy-Connection", "keep-alive");
	evhttp_add_header(req->input_headers, "Proxy-Connection", "keep-alive");
	evhttp_connection_set_timeout(req->evcon, -1);
	evhttp_connection_set_closecb(req->evcon, libws_close_cb, pws);
	bufferevent_setcb(bev, libws_rdcb, libws_wrcb, libws_evcb, pws);
	bufferevent_set_timeouts(bev, NULL, NULL);

	if (conn_cb)
	{
		conn_cb(pws);
	}

	return pws;
}

struct libws_t *libws_connect(struct event_base *eventBase,
    const char *url,
	function<int(libws_t*)> conn_cb,
	function<int(libws_t*)> disconn_cb,
	function<int(libws_t*, uint8_t*, size_t)> rd_cb,
	function<int(libws_t*)> wr_cb,
	bool useSSL,
	const char* localIP,
	int localPort)
{
    if(nullptr == url)
        return nullptr;
    if(nullptr == eventBase)
        return nullptr;
    struct evhttp_uri* uri = evhttp_uri_parse(url);
    if(!uri)
    {
        return nullptr;
    }
    const char* host = evhttp_uri_get_host(uri);
    int port = evhttp_uri_get_port(uri);
    if (port < 0) port = 80;
    const char* query = evhttp_uri_get_query(uri);
    const char* path = evhttp_uri_get_path(uri);
    size_t nlen = (query ? strlen(query) : 0) + (path ? strlen(path) : 0) + 8;
    char* request_url = new char[nlen];
    if(!path)
        sprintf(request_url, "/");
    else if(strlen(path)==0)
        sprintf(request_url, "/");
    else if(query)
        sprintf(request_url, "%s?%s", path, query);
    else
        sprintf(request_url, "%s", path);

	libws_t* pws = new struct libws_t;
	memset(pws, 0, sizeof(libws_t));
	pws->conn_cb = conn_cb;
	pws->disconn_cb = disconn_cb;
	pws->rd_cb = rd_cb;
	pws->wr_cb = wr_cb;
	pws->is_client = true;
	if (useSSL)
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
        pws->ssl_ctx = SSL_CTX_new(TLS_client_method());
        pws->ssl = SSL_new(pws->ssl_ctx);
	}

    bufferevent* bev = nullptr;
    if (0 != strcmp(localIP, "0.0.0.0")
        || 0 != localPort)
    {
		evutil_socket_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
		// 修改socket属性（可选）
		int bufLen = SINGLE_PACKAGE_SIZE;
		if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int)) < 0)
		{
			return nullptr;
		}
		if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) < 0)
		{
			return nullptr;
		}
		linger l;
		l.l_onoff = 1;
		l.l_linger = 0;
		if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l)) < 0)
		{
			return nullptr;
		}
		if (evutil_make_socket_nonblocking(sockfd) < 0)
		{
			return nullptr;
		}

		sockaddr_in localAddr = { 0 };
		if (!ConvertIPPort(localIP, localPort, localAddr))
		{
			return nullptr;
		}
		if (::bind(sockfd, (sockaddr*)&localAddr, sizeof(localAddr)) != 0)
		{
			return nullptr;
		}

		if (useSSL)
		{
			bev = bufferevent_openssl_socket_new(eventBase, sockfd, pws->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
		}
		else
		{
			bev = bufferevent_socket_new(eventBase, sockfd, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
		}
    }
    else
    {
		if (useSSL)
		{
			bev = bufferevent_openssl_socket_new(eventBase, -1, pws->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
		}
		else
		{
			bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
		}
    }	

    if(NULL == bev)
    {
        delete[] request_url;
        delete pws;
        return nullptr;
    }

    struct evhttp_connection* evcon = evhttp_connection_base_bufferevent_new(eventBase, NULL, bev, host, (uint16_t)(port));
    if(NULL == evcon)
    {
		delete[] request_url;
		delete pws;
        return nullptr;
    }
    pws->conn = evcon;

    struct evhttp_request* req = evhttp_request_new(libws_connect_cb, pws);
    evhttp_add_header(req->output_headers, "Host", host);
    evhttp_add_header(req->output_headers, "Upgrade", "websocket");
    evhttp_add_header(req->output_headers, "Connection", "Upgrade");
    evhttp_remove_header(req->output_headers, "Proxy-Connection");
    evhttp_add_header(req->output_headers, "Proxy-Connection", "keep-alive");
    evhttp_add_header(req->output_headers, "Sec-WebSocket-Version", "13");

	char nonce[16];
	char key[256];
    for(size_t i=0;i<sizeof(nonce)/sizeof(nonce[0]);i++)
        nonce[i]=(char)(rand()&0xff);
    memset(key, 0, sizeof(key));
    base64_encode((const uint8_t*)nonce, sizeof(nonce),key);
    evhttp_add_header(req->output_headers, "Sec-WebSocket-Key", key);

	struct evkeyvalq headers;
	evhttp_parse_query(url, &headers);
	struct evkeyval* kv = headers.tqh_first;
	while (kv) 
    {
        evhttp_add_header(req->output_headers, kv->key, kv->value);
		kv = kv->next.tqe_next;
	}

    evhttp_make_request(evcon, req, EVHTTP_REQ_GET, request_url);
    evhttp_connection_set_closecb(evcon, libws_close_cb, pws);

    delete request_url;
    evhttp_uri_free(uri);
    return pws;
}
