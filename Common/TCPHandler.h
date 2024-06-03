#pragma once

#include <functional>
#include <future>
#include <chrono>

#include "event2/event.h"
#include "event2/thread.h"
#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_ssl.h"
#include "event2/buffer.h"
#include "event2/listener.h"
#include "event2/keyvalq_struct.h"
#include "event2/bufferevent_struct.h"
#include "openssl/ssl.h"

#include "NetFrame.h"

using std::mutex;
using std::chrono::steady_clock;
using std::function;
using std::unique_ptr;
using std::string_view;

class EventData;
interface NetHandler
{
public:
	virtual void onEventDataDeleted(EventData* eventData) = 0;

	bool isUseSSL() { return _isUseSSL; }
protected:
	bool _isUseSSL = false;
};

class TCPHandler : public NetHandler
{
public:
	bool listen(int port, bool isUseSSL, 
		function<void(EventData*, const sockaddr* remoteAdd)> cbOnAccept, 
		function<void(const EventData* eventData)> cbOnDisconnect, 
		function<void(const EventData*, const LocalPackage*)> cbOnRecv, 
		function<void(const EventData*, const LocalPackage*)> cbOnSend);
	bool connect(const char* remoteIP, int remotePort, int localPort/*0表示随机本地端口*/, bool isUseSSL,
		function<void(EventData* eventData)> cbOnConnected, 
		function<void(const EventData* eventData)> cbOnDisconnect, 
		function<void(const EventData*, const LocalPackage*)> cbOnRecv, 
		function<void(const EventData*, const LocalPackage*)> cbOnSend);
	void stop();
	bool sendList(IOData* ioData, bool priority = false); // 加入发送队列	
	bool sendList(EventData* eventData, char* data, size_t dataSize);
	bool sendList(EventData* eventData, const string& filePath);

	virtual void onEventDataDeleted(EventData* eventData);
	void onAccept(EventData* eventData, const sockaddr* remoteAddr);
	void onConnected(EventData* eventData);
	void onRecv(SocketData* socketData, const char* data, size_t dataSize);
	void onSend(SocketData* socketData);

private:
	evconnlistener* _listener = nullptr;
	EventData* _listenEventData = nullptr;
	list<EventData*>	_connectedEventDataList;

	function<void(EventData*, const sockaddr* /*remoteAddr*/)> _onAccept;
	function<void(EventData*)> _onConnected;
	function<void(const EventData* )> _onDisconnect;
	function<void(const EventData*, const LocalPackage*)> _onRecv;
	function<void(const EventData*, const LocalPackage*)> _onSend;

	bool send(const EventData* eventData, const char* data, size_t dataSize); // 立即发送
	void send(IOData* ioData); // 立即发送
	void onReadySend(SocketData* socketData, IOData* ioData);
	void replyConfirm(SocketData* socketData, ULONG ioNum);
};

class EventData : public SocketData
{
public:
	EventData(NetHandler* parent)
	{
		callback = parent;
	}

	EventData() {}

	~EventData()
	{
		if (ssl_ctx)
		{
			SSL_CTX_free(ssl_ctx);
		}

		if (ssl)
		{
			SSL_shutdown(ssl);
		}

		if (bev)
		{
			evutil_socket_t fd = bufferevent_getfd(bev);
			if (-1 != fd)
			{
				closesocket(fd);
			}
			bufferevent_replacefd(bev, -1);
			bufferevent_free(bev);
		}

		if (callback)
		{
			callback->onEventDataDeleted(this);
		}
	}

	virtual void close()
	{
		__super::close();

		if (bev)
		{
			evutil_socket_t fd = bufferevent_getfd(bev);
			if (-1 != fd)
			{
				closesocket(fd);
				fd = -1;
			}
		}
	}

	NetHandler* callback = nullptr;
	bufferevent* bev = nullptr;
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;
};
