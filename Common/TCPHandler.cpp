#include "TCPHandler.h"
#include "common/common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <thread>

using namespace std;

#define SINGLE_PACKAGE_SIZE 1024 * 64 // 默认16384

template<typename ... Args>
std::string static str_format(const std::string& format, Args ... args)
{
	auto size_buf = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1;
	std::unique_ptr<char[]> buf(new char[size_buf]);

	if (!buf)
		return std::string("");

	std::snprintf(buf.get(), size_buf, format.c_str(), args ...);
	return std::string(buf.get(), buf.get() + size_buf - 1);
}

static void onServerWrite(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;
	((TCPHandler*)eventData->callback)->onSend();
}

static void onServerRead(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;

	evbuffer* buffer = evbuffer_new();
	if (0 == bufferevent_read_buffer(bev, buffer))
	{
		size_t bufferLength = evbuffer_get_length(buffer);
		if (bufferLength)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(buffer, bufferLength);
			if (data)
			{
				// 处理数据
				((TCPHandler*)eventData->callback)->onRecv(data, bufferLength);

				// 清空数据
				evbuffer_drain(buffer, bufferLength);
			}
		}

		string tmpStr = str_format("threadID:%d recv %ubytes", this_thread::get_id(), bufferLength);
		info(tmpStr);
	}
	else
	{
		warn("TCPHandler::OnServerRead bufferevent_read_buffer failed");
	}

	evbuffer_free(buffer);
}

static void onServerEvent(bufferevent* bev, short events, void* param)
{
	EventData* eventData = (EventData*)param;

	if (events & BEV_EVENT_EOF)
	{
		//info(L"BEV_EVENT_EOF 连接关闭");
		delete eventData;
	}
	else if (events & BEV_EVENT_ERROR)
	{
// 		CString tmpStr;
// 		if (events & BEV_EVENT_READING)
// 		{
// 			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_READING错误errno:%d", errno);
// 		}
// 		else if (events & BEV_EVENT_WRITING)
// 		{
// 			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_WRITING错误errno:%d", errno);
// 		}
// 
// 		info(tmpStr);
		delete eventData;
	}
}

static void OnServerEventAccept(evconnlistener* listener, evutil_socket_t sockfd, sockaddr* remoteAddr, int remoteAddrLen, void* param)
{
	EventData* listenEventData = (EventData*)param;
	event_base* eventBase = evconnlistener_get_base(listener);

	// 修改socket属性
	int bufLen = SINGLE_PACKAGE_SIZE;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int)) != 0)
	{
		error("TCPHandler::connect setsockopt SO_RCVBUF failed");
		return;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) != 0)
	{
		error("TCPHandler::connect setsockopt SO_SNDBUF failed");
		return;
	}

	linger optLinger;
	optLinger.l_onoff = 1;
	optLinger.l_linger = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&optLinger, sizeof(optLinger)) != 0)
	{
		error("TCPHandler::connect setsockopt SO_LINGER failed");
		return;
	}

	if (evutil_make_socket_nonblocking(sockfd) < 0)
	{
		return;
	}

	// 构造一个bufferevent
	EventData* eventData = new EventData(listenEventData->callback);
	bufferevent* bev = nullptr;
	if (listenEventData->ssl_ctx)
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		eventData->ssl = SSL_new(listenEventData->ssl_ctx);
		SSL_set_fd(eventData->ssl, sockfd);
		bev = bufferevent_openssl_socket_new(eventBase, sockfd, eventData->ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	else
	{
		bev = bufferevent_socket_new(eventBase, sockfd, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	
	if (!bev)
	{
		error("TCPHandler::OnServerEventAccept bufferevent_socket_new failed");
		event_base_loopbreak(eventBase);
		delete eventData;
		return;
	}
	eventData->bev = bev;
	((TCPHandler*)eventData->callback)->onAccept(eventData, remoteAddr);

	// 修改读写上限
	int ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		warn("TCPHandler::OnServerEventAccept bufferevent_set_max_single_read failed");
	}
	ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		warn("TCPHandler::OnServerEventAccept bufferevent_set_max_single_write failed");
	}

	//绑定读事件回调函数、写事件回调函数、错误事件回调函数
	bufferevent_setcb(bev, onServerRead, onServerWrite, onServerEvent, eventData);

	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

bool TCPHandler::listen(int port, bool isUseSSL,
	function<void(EventData*, const sockaddr* remoteAdd)> cbOnAccept, function<void(const EventData* eventData)> cbOnDisconnect, function<void(const unsigned char*, size_t)> cbOnRecv, function<void()> cbOnSend)
{
	_isUseSSL = isUseSSL;
	_onAccept = cbOnAccept;
	_onDisconnect = cbOnDisconnect;
	_onRecv = cbOnRecv;
	_onSend = cbOnSend;

	event_config* cfg = event_config_new();
	evthread_use_windows_threads();
	event_config_set_num_cpus_hint(cfg, 8);
	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);

	event_base* eventBase = event_base_new_with_config(cfg);
	if (!eventBase)
	{
		event_config_free(cfg);
		error("TCPHandler::listen create eventBase failed");
		return false;
	}
	event_config_free(cfg);
	cfg = nullptr;

	//创建、绑定、监听socket
	sockaddr_in localAddr = { 0 };
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(port);

	EventData* eventData = new EventData(this);
		
	if (isUseSSL)
	{
		bool hasError = true;
		do
		{
			/*
			生成x.509证书
			首选在安装好openssl的机器上创建私钥文件：server.key
			> openssl genrsa -out server.key 2048

			得到私钥文件后我们需要一个证书请求文件（Certificate Signing Request）：server.csr，将来你可以拿这个证书请求向正规的证书管理机构申请证书
			> openssl req -new -key server.key -out server.csr

			最后我们生成有效期365天的自签名的x.509证书（Certificate）：server.crt
			> openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
			*/
			string exeDir = CurentDirectory();
			string serverCrtPath = ConcatPathFileName(exeDir, "config/server.crt");
			string serverKeyPath = ConcatPathFileName(exeDir, "config/server.key");

			// 引入之前生成好的私钥文件和证书文件
			ssl_ctx_st* ssl_ctx = SSL_CTX_new(TLS_server_method());
			if (!ssl_ctx)
			{
				error("TCPHandler::ssl_ctx new failed");
				break;
			}
			int res = SSL_CTX_use_certificate_file(ssl_ctx, serverCrtPath.c_str(), SSL_FILETYPE_PEM);
			if (res != 1)
			{
				error("TCPHandler::SSL_CTX_use_certificate_file failed");
				break;
			}
			res = SSL_CTX_use_PrivateKey_file(ssl_ctx, serverKeyPath.c_str(), SSL_FILETYPE_PEM);
			if (res != 1)
			{
				error("TCPHandler::SSL_CTX_use_PrivateKey_file failed");
				break;
			}
			res = SSL_CTX_check_private_key(ssl_ctx);
			if (res != 1)
			{
				error("TCPHandler::SSL_CTX_check_private_key failed");
				break;
			}
			eventData->ssl_ctx = ssl_ctx;

			hasError = false;
		} while (false);
		
		if (hasError)
		{
			delete eventData;
			event_base_free(eventBase);			
			return false;
		}
	}

	_listener = evconnlistener_new_bind(eventBase, OnServerEventAccept, eventData,
		LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
		(sockaddr*)&localAddr, sizeof(localAddr));
	if (!_listener)
	{
		error("TCPHandler::listen create evconnlistener failed");

		delete eventData;
		event_base_free(eventBase);	
		return false;
	}
	_listenEventData = eventData;

	thread([&, eventBase]
		{
			event_base_dispatch(eventBase); // 阻塞
			info("TCPHandler::Server event_base_dispatch thread end");

			evconnlistener_free(_listener);
			delete _listenEventData;
			_listenEventData = nullptr;
			event_base_free(eventBase);
		}).detach();

	info("TCPHandler::TCP Server listen begin");
	return true;
}

void TCPHandler::stopListen()
{
	if (_listener)
	{
		evconnlistener_disable(_listener);
		_listener = nullptr;
	}
}

static void OnClientWrite(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;
	((TCPHandler*)eventData->callback)->onSend();
}

static void OnClientRead(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;

	evbuffer* buffer = evbuffer_new();
	if (0 == bufferevent_read_buffer(bev, buffer))
	{
		size_t bufferLength = evbuffer_get_length(buffer);
		if (bufferLength)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(buffer, bufferLength);
			if (data)
			{
				// 处理数据
				((TCPHandler*)eventData->callback)->onRecv(data, bufferLength);

				// 清空数据
				evbuffer_drain(buffer, bufferLength);
			}
		}
	}
	else
	{
		warn("TCPHandler::OnClientRead bufferevent_read_buffer failed");
	}

	evbuffer_free(buffer);
}

static void OnClientEvent(bufferevent* bev, short events, void* param)
{
	EventData* eventData = (EventData*)param;

	if (events & BEV_EVENT_CONNECTED)
	{
		info("TCPHandler::OnClientEvent connected");
		((TCPHandler*)eventData->callback)->onConnected(eventData);
	}
	else if (events & BEV_EVENT_EOF)
	{
		info("TCPHandler::OnClientEvent BEV_EVENT_EOF");
		delete eventData;
	}
	else if (events & BEV_EVENT_ERROR)
	{
		if (events & BEV_EVENT_READING)
		{
			info("TCPHandler::OnClientEvent BEV_EVENT_ERROR BEV_EVENT_READING");
		}
		else if (events & BEV_EVENT_WRITING)
		{
			info("TCPHandler::OnClientEvent BEV_EVENT_ERROR BEV_EVENT_WRITING");
		}
		else
		{
			info(str_format("TCPHandler::OnClientEvent BEV_EVENT_ERROR %d", events));
		}

		delete eventData;
	}
}

bool TCPHandler::connect(const char* remoteIP, int remotePort, int localPort, bool isUseSSL, function<void(EventData* eventData)> cbOnConnected, function<void(const EventData* eventData)> cbOnDisconnect, function<void(const unsigned char*, size_t)> cbOnRecv, function<void()> cbOnSend)
{
	_isUseSSL = isUseSSL;
	_onConnected = cbOnConnected;
	_onDisconnect = cbOnDisconnect;
	_onRecv = cbOnRecv;
	_onSend = cbOnSend;

	event_config* cfg = event_config_new();
	evthread_use_windows_threads();
	event_config_set_num_cpus_hint(cfg, 8);
	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);

	event_base* eventBase = event_base_new_with_config(cfg);
	if (!eventBase)
	{
		error("TCPHandler::connect create eventBase failed");
		return false;
	}
	event_config_free(cfg);
	cfg = nullptr;

	EventData* eventData = new EventData(this);
	if (isUseSSL)
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		eventData->ssl_ctx = SSL_CTX_new(TLS_client_method());
		eventData->ssl = SSL_new(eventData->ssl_ctx);
	}

	bufferevent* bev = nullptr;
	if (0 == localPort)
	{
		// 使用随机的本地端口
		if (isUseSSL)
		{
			bev = bufferevent_openssl_socket_new(eventBase, -1, eventData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
		}
		else
		{
			bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
		}
	}
	else
	{
		bool hasError = true;
		do
		{
			// 使用指定的本地IP、端口		
			sockaddr_in localAddr = { 0 };
			if (!ConvertIPPort("0.0.0.0", localPort, localAddr))
			{
				error("TCPHandler::connect ConvertIPPort failed");
				break;
			}

			evutil_socket_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
			// 修改socket属性
			int bufLen = SINGLE_PACKAGE_SIZE;
			if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int)) != 0)
			{
				error("TCPHandler::connect setsockopt SO_RCVBUF failed");
				break;
			}
			if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) != 0)
			{
				error("TCPHandler::connect setsockopt SO_SNDBUF failed");
				break;
			}

			linger optLinger;
			optLinger.l_onoff = 1;
			optLinger.l_linger = 0;
			if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&optLinger, sizeof(optLinger)) != 0)
			{
				error("TCPHandler::connect setsockopt SO_LINGER failed");
				break;
			}
			if (evutil_make_socket_nonblocking(sockfd) < 0)
			{
				error("TCPHandler::connect evutil_make_socket_nonblocking failed");
				break;
			}

			if (::bind(sockfd, (sockaddr*)&localAddr, sizeof(localAddr)) != 0)
			{
				error("TCPHandler::connect bind failed");
				break;
			}

			if (isUseSSL)
			{
				bev = bufferevent_openssl_socket_new(eventBase, sockfd, eventData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
			}
			else
			{
				bev = bufferevent_socket_new(eventBase, sockfd, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
			}

			hasError = false;
		} while (false);

		if (hasError)
		{
			delete eventData;
			event_base_free(eventBase);
		}
	}

	if (nullptr == bev)
	{
		error("TCPHandler::connect bufferevent_socket_new failed");
		delete eventData;
		event_base_free(eventBase);
		return false;
	}
	eventData->bev = bev;

	bufferevent_setcb(bev, OnClientRead, OnClientWrite, OnClientEvent, eventData);

	//连接服务端
	sockaddr_in serverAddr = { 0 };
	ConvertIPPort(remoteIP, remotePort, serverAddr);

	int flag = bufferevent_socket_connect(bev, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (-1 == flag)
	{
		warn("TCPHandler::connect bufferevent_socket_connect failed");
		delete eventData;
		event_base_free(eventBase);
		return false;
	}

	// 修改读写上限
	int ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		warn("bufferevent_socket_connect bufferevent_set_max_single_read failed");
	}
	ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		warn("bufferevent_socket_connect bufferevent_set_max_single_write failed");
	}

	bufferevent_enable(bev, EV_READ | EV_WRITE);

	thread([&, eventBase]
		{
			event_base_dispatch(eventBase); // 阻塞
			info("TCPHandler::Client event_base_dispatch thread end");

			event_base_free(eventBase);
		}).detach();

	info("TCPHandler::TCP Client connect begin");
	return true;
}

void TCPHandler::onEventDataDeleted(EventData* eventData)
{
	if (_onDisconnect)
	{
		_onDisconnect(eventData);
	}
}

void TCPHandler::onAccept(EventData* eventData, const sockaddr* remoteAddr)
{
	string remoteIP = "0";
	int remotePort = 0;

	if (_onAccept)
	{
		_onAccept(eventData, remoteAddr);
	}
}

void TCPHandler::onConnected(EventData* eventData)
{
	if (_onConnected)
	{
		_onConnected(eventData);
	}
}

void TCPHandler::onRecv(const unsigned char* data, size_t dataSize)
{
	if (_onRecv)
	{
		_onRecv(data, dataSize);
	}
}

void TCPHandler::onSend()
{
	if (_onSend)
	{
		_onSend();
	}
}

bool TCPHandler::send(const EventData* eventData, const unsigned char* data, size_t dataSize)
{
	int ret = bufferevent_write(eventData->bev, data, dataSize);
	if (ret != 0)
	{
		warn(str_format("TCPHandler::send failed ret:%d", ret));
		return false;
	}

	return true;
}
