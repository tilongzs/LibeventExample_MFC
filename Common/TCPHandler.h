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

using std::mutex;
using std::chrono::steady_clock;
using std::function;
using std::unique_ptr;
using std::string_view;

// 网络数据类型
enum class NetDataType
{
	NetDataType_NULL,
	HelloCenter,	// 连接大厅
	RoomServerInfo,	// 房间服务器信息
	HelloRoom,	// 连接房间
	WordsVersionRq, // 词库版本请求
	WordsVersionRp, // 词库版本回复
	WordsPairRq, // 词库请求
	WordsPairRp, // 词库回复
	Login,		// 用户登录

	NetDataTypeEnd
};

// 网络包基本信息
#pragma pack(push)
#pragma pack(1) // 1字节内存对齐
struct PackageBase
{
	uint16_t	ioNum = 0;	// 通信流水号
	bool		needConfirm = false;	// 需要回复确认（只有收到回复确认的消息，才会继续发送下一个）
	uint16_t	dataType = 0; // 网络数据类型(DataType)
	uint32_t	dataSize = 0; // 数据大小
};
#pragma pack(pop) // #pragma pack(1)

class LocalPackage
{
public:
	~LocalPackage()
	{
		delete[] package;
	}

	PackageBase	head;

	uint8_t* package = nullptr; // 已接收的数据
	uint64_t receivedBytes;	// 已接收字节数
	unique_ptr<steady_clock::time_point> startTime = nullptr;	// 传输的开始时间

	uint64_t PackageSize() { return sizeof(PackageBase) + head.dataSize; } // 包总大小
};

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
	bool listen(int port, bool isUseSSL, function<void(EventData*, const sockaddr* remoteAdd)> cbOnAccept, function<void(const EventData* eventData)> cbOnDisconnect, function<void(const unsigned char*, size_t)> cbOnRecv, function<void()> cbOnSend);
	void stopListen();
	bool connect(const char* remoteIP, int remotePort, int localPort, bool isUseSSL, function<void(EventData* eventData)> cbOnConnected, function<void(const EventData* eventData)> cbOnDisconnect, function<void(const unsigned char*, size_t)> cbOnRecv, function<void()> cbOnSend); // localPort为0表示随机本地端口
	bool send(const EventData* eventData, const unsigned char* data, size_t dataSize);

	virtual void onEventDataDeleted(EventData* eventData);
	void onAccept(EventData* eventData, const sockaddr* remoteAddr);
	void onConnected(EventData* eventData);
	void onRecv(const unsigned char* data, size_t dataSize);	
	void onSend();

private:
	evconnlistener* _listener = nullptr;
	EventData* _listenEventData = nullptr;
	function<void(EventData*, const sockaddr* remoteAddr)> _onAccept;
	function<void(EventData* eventData)> _onConnected;
	function<void(const EventData* eventData)> _onDisconnect;
	function<void(const unsigned char*, size_t)> _onRecv;
	function<void()> _onSend;
};

class EventData
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

	void close()
	{
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



