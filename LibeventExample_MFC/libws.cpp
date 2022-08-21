/*
    libws主文件
    作者：刘兵
    联系方式：272903152@qq.com
    日期：2022-08-05
    在windows的mingw下面编译通过，使用良好，编译器是64位的GCC，在linux的32位嵌入式系统上编译通过，运行良好，编译器是gcc
    本库完全在libevent的http协议基础上实现，对websocket文档里面的定义和标准90%的全都支持。
    服务器端工作原理：
    接收全客户端的http请求之后，在回调里面判断http头，对：
    1. Connection的Upgrade进行判断，
    2.webwocket升级请求进行判断，
    3.对websocket版本进行判断，
    全部通过则进行回调用户的conn函数，该函数会产生一个libws_t的结构体，应用层的初始化可以在这个回调进行初始化。如果返回空，则会断开客户端连接，认为服务器拒绝接入
    新的libws_t则可以调用libws_send发送数据，收到数据会产生接收回调，在创建libws_t结构体时的接收回调里面进行处理
    客户端工作原理：
    libws_connect链接服务器并指定接收、发送、接入、关闭4个回调函数，在相应的地方进行调用。
    该函数调用了标准的libevent的http客户端进行通讯。

    libevent默认的http服务器和客户端都是有默认超时设定，websocket在成功接入后，则自动屏蔽超时和其他回调，将产生的http connection数据处理和回调全部屏蔽，将connection设置为keep-alive状态，使用该connection的bufferevent进行通讯。
    libws的客户端发送数据采用掩码发送，服务器发送数据不掩码，客户端和服务器的接收都可以识别是否掩码。
    如果编译不通过，将日志打印改为用户项目中自己的打印，将get_fms函数定义为获取毫秒的函数即可。
    注意get_fms函数，一定要采用相对时间，不能采用系统时间，因为系统时间一旦调整，会影响libws的超时判断。
    本人在使用时采用了CLOCK_MONOTONIC进行获取相对时间，该时间一般是从系统启动开始计数，无论何种情况都不会清零和修改，只会按时间增量增加，用于软件的超时判断最合适不过。

    sha1和base64是websocket在握手时的必须库，直接添加到工程即可。
*/

#include "pch.h"
#include "libws.h"
#include "Common/sha1.h"
#include "Common/base64.h"
#include <queue>
#include "LibeventExample_MFCDlg.h"

#define SINGLE_PACKAGE_SIZE 1024 * 64 // 默认16384

static void libws_proc(struct libws_t *);

static void libws_close_cb(struct evhttp_connection *conn, void *arg)
{
    struct libws_t* pws = (struct libws_t*)arg;

    if (pws->disconn_cb)
    {
        pws->disconn_cb(pws);
    }

    delete pws;
}

static void libws_rdcb(struct bufferevent *bev, void *ctx)
{
    struct libws_t* p = (struct libws_t*)ctx;

    if(p->is_active == false)
        return;
    libws_proc(p);     // 解析数据
}

static void libws_wrcb(struct bufferevent *bev, void *ctx)
{
    struct libws_t* p = (struct libws_t*)ctx;
    if(p->is_active == false)
        return;
    if(p->wr_cb)
        p->wr_cb(p);
}

static void libws_evcb(struct bufferevent *bev, short what, void *ctx)
{
    if(what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT))    // 结束、错误、超时，都关闭websocket
    {
		struct libws_t* pws = (struct libws_t*)ctx;
        evhttp_connection_free(pws->conn);
    }
    return;
}

static void libws_connect_cb(struct evhttp_request *req, void *arg)
{
    if(NULL == req || NULL == arg)
        return;
	struct libws_t* pws = (struct libws_t*)arg;

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
                    pws->dlg->AppendMsg(L"bufferevent_set_max_single_read失败");
                }
                ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
                if (ret != 0)
                {
                    pws->dlg->AppendMsg(L"bufferevent_set_max_single_write失败");
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

static void libws_error_cb(enum evhttp_request_error error, void* arg)
{
    if(NULL == arg)
        return;
    libws_close_cb(NULL, arg); //  (struct libws_t*)arg
}

static size_t libws_process(uint8_t *buf, size_t len, struct ws_msg *msg)
{
    if(NULL == msg)
        return 0;
    if(NULL == buf)
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
            msg->header_len = 2 + mask_len;
            msg->data_len = n;
        }
        else if (n == 126 && len >= 4 + mask_len)
        {
            msg->header_len = 4 + mask_len;
            msg->data_len = buf[2];
            msg->data_len <<= 8;
            msg->data_len |= buf[3];
        }
        else if (len >= 10 + mask_len)
        {
            msg->header_len = 10 + mask_len;
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
            msg->data_len = (size_t)tmp;
        }
    }
    if (msg->header_len + msg->data_len > len)
        return 0;
    if (mask_len > 0)
    {
        uint8_t *p = buf + msg->header_len, *m = p - mask_len;
        for (size_t i = 0; i < msg->data_len; i++)
            p[i] ^= m[i & 3];
    }
    return msg->header_len + msg->data_len;
}

void libws_proc(struct libws_t *pws)
{
    if(NULL == pws)
        return;
    if(NULL == pws->conn)
        return;

    struct bufferevent* bev = evhttp_connection_get_bufferevent(pws->conn);
	struct ws_msg msg;
	uint8_t* p;
	size_t res;
	ev_ssize_t size;
    for(size=1,res=1; res&&size;)
    {
        size = (ev_ssize_t)evbuffer_get_length(bev->input);
        p=evbuffer_pullup(bev->input, size);
        res = libws_process(p, (size_t)size, &msg);
        if(res)
        {
            pws->ms = pws->dlg->GetRunningTime();
            switch (msg.flags & LIBWS_FLAGS_MASK_OP) {
              case LIBWS_OP_CONTINUE:
                break;
              case LIBWS_OP_PING:
                libws_send(pws, (uint8_t*)&p[msg.header_len], msg.data_len,LIBWS_OP_PONG);
                break;
              case LIBWS_OP_PONG:
                break;
              case LIBWS_OP_TEXT:
              case LIBWS_OP_BINARY:
                if(pws->rd_cb)
                    pws->rd_cb(pws, &p[msg.header_len], msg.data_len);
                break;
              case LIBWS_OP_CLOSE:
                evhttp_connection_free(pws->conn);
                return;
              default:
                // Per RFC6455, close conn when an unknown op is recvd
                evhttp_connection_free(pws->conn);
                return;
            }
            evbuffer_drain(bev->input, msg.header_len + msg.data_len);
        }
    }
}

static void mkrandom(void* buf, size_t len)
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
        mkrandom(&buf[n], 4);
		n += 4;
	}
	return n;
}

int libws_send(struct libws_t* pws, uint8_t* pdata, size_t dataSize, uint8_t op)
{
    if(NULL == pws)
        return -1;
    if(pdata==NULL)
        return -2;
    if(dataSize==0)
        return -3;
    if(NULL == pws->conn)   // 未连接成功
        return -4;
    if(pws->is_active==0) // 连接无效
        return -5;
    pws->ms = pws->dlg->GetRunningTime();
    struct bufferevent* bev = evhttp_connection_get_bufferevent(pws->conn);

    struct evbuffer* evBuf = evbuffer_new();

	uint8_t header[14] = {0};
	size_t headerSize = makeHeader(dataSize, op, pws->is_client, header);
    if (0 != evbuffer_add(evBuf, header, headerSize))
    {
        evbuffer_free(evBuf);
        return -6;
    }

   // uint8_t* buf = (uint8_t*)malloc(dataSize);
   // memcpy(buf, pdata, dataSize);
	if (0 != evbuffer_add(evBuf, pdata, dataSize))
	{
		evbuffer_free(evBuf);
		return -6;
	}

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



// 	uint8_t mask[4];
//     if(pws->is_client)
// 	{
//         srand(NULL);
// 		mask[0] = rand() & 0xff;
// 		mask[1] = rand() & 0xff;
// 		mask[2] = rand() & 0xff;
// 		mask[3] = rand() & 0xff;
// 
// 		if (0 != evbuffer_add(evBuf, mask, 4))
// 		{
// 			evbuffer_free(evBuf);
// 			return -6;
// 		}
// 
// //        header_len += sizeof(mask);
//         for(size_t i=0; i<dataSize; i++)
//             buf[i] ^= mask[i&3];
//     }

// 	if (0 != evbuffer_add(evBuf, buf, dataSize))
// 	{
// 		evbuffer_free(evBuf);
// 		return -6;
// 	}

	if (0 != bufferevent_write_buffer(bev, evBuf))
	{
    //    free(buf);
        evbuffer_free(evBuf);
		return -7;
	}
	else
	{
	//	free(buf);
		return (int)(headerSize + dataSize);
	}
}

struct libws_t *libws_connect(struct event_base *base,
    const char *url,
	function<int(struct libws_t*)> conn_cb,
	function<int(struct libws_t*)> disconn_cb,
	function<int(struct libws_t*, uint8_t*, size_t)> rd_cb,
	function<int(struct libws_t*)> wr_cb,
    CLibeventExample_MFCDlg* dlg)
{
    if(url==NULL)
        return NULL;
    if(base==NULL)
        return NULL;
    struct evhttp_uri* uri = evhttp_uri_parse(url);
    if(!uri)
    {
        return NULL;
    }
    const char* host = evhttp_uri_get_host(uri);
    int port = evhttp_uri_get_port(uri);
    if (port < 0) port = 80;
    const char* query = evhttp_uri_get_query(uri);
    const char* path = evhttp_uri_get_path(uri);
    size_t nlen = (query ? strlen(query) : 0) + (path ? strlen(path) : 0) + 8;

    char* request_url = (char*)calloc(nlen, 1);
    if(!path)
        sprintf(request_url, "/");
    else if(strlen(path)==0)
        sprintf(request_url, "/");
    else if(query)
        sprintf(request_url, "%s?%s", path, query);
    else
        sprintf(request_url, "%s", path);

    struct bufferevent* bev = bufferevent_socket_new(base, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
    if(NULL == bev)
    {
        free(request_url);
        return NULL;
    }

    struct evhttp_connection* evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev, host, (uint16_t)(port));
    if(NULL == evcon)
    {
        free(request_url);
        return NULL;
    }

    struct libws_t* pws = new struct libws_t;
    memset(pws, 0, sizeof(libws_t));
    pws->dlg = dlg;
	pws->conn = evcon;
	pws->conn_cb = conn_cb;
	pws->disconn_cb = disconn_cb;
    pws->rd_cb = rd_cb;
    pws->wr_cb = wr_cb;
    pws->ms = dlg->GetRunningTime();
    pws->is_client = true;

    struct evhttp_request* req = evhttp_request_new(libws_connect_cb, pws);
    evhttp_request_set_error_cb(req, libws_error_cb);
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
    if(request_url)
        free(request_url);
    evhttp_uri_free(uri);
    return pws;
}

