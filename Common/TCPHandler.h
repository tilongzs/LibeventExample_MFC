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
class TCPHandler
{
public:
	bool listen(uint16_t port, bool isUseSSL,
		function<void(EventData*, const sockaddr* remoteAdd)> cbOnAccept, 
		function<void(const EventData* eventData)> cbOnDisconnect, 
		function<void(const EventData*, const LocalPackage*)> cbOnRecv, 
		function<void(const EventData*, const LocalPackage*)> cbOnSend);
	bool connect(const char* remoteIP, uint32_t remotePort, uint32_t localPort/*0表示随机本地端口*/, bool isUseSSL,
		function<void(EventData* eventData)> cbOnConnected, 
		function<void(const EventData* eventData)> cbOnDisconnect, 
		function<void(const EventData*, const LocalPackage*)> cbOnRecv, 
		function<void(const EventData*, const LocalPackage*)> cbOnSend);
	void stop();
	bool sendList(IOData* ioData, bool priority = false); // 加入发送队列	
	bool sendList(EventData* eventData, char* data, size_t dataSize, bool isNeedConfirm = false);
	bool sendList(EventData* eventData, const string& filePath);

	virtual void onEventDataDeleted(EventData* eventData);
	void onAccept(EventData* eventData, const sockaddr* remoteAddr);
	void onConnected(EventData* eventData);
	void onRecv(SocketData* socketData, const char* data, size_t dataSize);
	void onSend(SocketData* socketData);
	inline bool isUseSSL() { return _isUseSSL; }
private:
	evconnlistener* _listener = nullptr;
	EventData* _listenEventData = nullptr;
	list<EventData*>	_connectedEventDataList;
	bool		_isUseSSL = false;
	bool		_isBegin = false;

	function<void(EventData*, const sockaddr* /*remoteAddr*/)> _cbOnAccept;
	function<void(EventData*)> _cbOnConnected;
	function<void(const EventData* )> _cbOnDisconnect;
	function<void(const EventData*, const LocalPackage*)> _cbOnRecv;
	function<void(const EventData*, const LocalPackage*)> _cbOnSend;

	bool send(const EventData* eventData, const char* data, size_t dataSize); // 立即发送
	void send(IOData* ioData); // 立即发送
	void onReadySend(SocketData* socketData, IOData* ioData, bool isSending);
	void replyConfirm(SocketData* socketData, ULONG ioNum);
};

class EventData : public SocketData
{
public:
	EventData(TCPHandler* parent)
	{
		callback = parent;
	}

	EventData() {}

	~EventData()
	{
		if (callback)
		{
			callback->onEventDataDeleted(this);
		}
	}

	virtual void close()
	{
		if (isConnected())
		{
			setConnected(false);
		}
		else
		{
			return;
		}

		if (bev)
		{
			bufferevent_free(bev);
		}
	}

	TCPHandler* callback = nullptr;
	bufferevent* bev = nullptr;
	event_base* eventBase = nullptr;
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;
};
