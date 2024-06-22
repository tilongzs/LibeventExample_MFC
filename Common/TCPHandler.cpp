#include "TCPHandler.h"
#include "common/common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <thread>
#include <fstream>

using namespace std;

#define SINGLE_PACKAGE_SIZE 65000 // 默认16384
#define TL_MAX_NET_PACKAGE_SIZE 10485760 // 单次传输非文件类型的最大大小（10M）

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
	((TCPHandler*)eventData->callback)->onSend(eventData);
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
				((TCPHandler*)eventData->callback)->onRecv(eventData, (const char*)data, bufferLength);

				// 清空数据
				evbuffer_drain(buffer, bufferLength);
			}
		}

//		string tmpStr = str_format("threadID:%d recv %ubytes", this_thread::get_id(), bufferLength);
//		info(tmpStr);
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
		bufferevent_free(bev);
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
		bufferevent_free(bev);
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
	eventData->eventBase = eventBase;
	ConvertIPPort(*(sockaddr_in*)remoteAddr, eventData->remoteIP, eventData->remotePort);
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

bool TCPHandler::listen(uint16_t port, bool isUseSSL,
	function<void(EventData*, const sockaddr*)> cbOnAccept, function<void(const EventData*)> cbOnDisconnect, function<void(const EventData*, const LocalPackage*)> cbOnRecv, function<void(const EventData*, const LocalPackage*)> cbOnSend)
{
	_isUseSSL = isUseSSL;
	_cbOnAccept = cbOnAccept;
	_cbOnDisconnect = cbOnDisconnect;
	_cbOnRecv = cbOnRecv;
	_cbOnSend = cbOnSend;

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
	_listenEventData->eventBase = eventBase;

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
	_isBegin = true;
	return true;
}

void TCPHandler::stop()
{
	_isBegin = false;
	if (_listener)
	{
		evconnlistener_disable(_listener);
	}

	for (auto connectedEventData : _connectedEventDataList)
	{
		connectedEventData->asyncDelete();
	}
	_connectedEventDataList.clear();
}

static void OnClientWrite(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;
	((TCPHandler*)eventData->callback)->onSend(eventData);
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
				((TCPHandler*)eventData->callback)->onRecv(eventData, (const char*)data, bufferLength);

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
		bufferevent_free(bev);
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

		bufferevent_free(bev);
		delete eventData;
	}
}

bool TCPHandler::connect(const char* remoteIP, uint32_t remotePort, uint32_t localPort, bool isUseSSL, function<void(EventData*)> cbOnConnected, function<void(const EventData*)> cbOnDisconnect, function<void(const EventData*, const LocalPackage*)> cbOnRecv, function<void(const EventData*, const LocalPackage*)> cbOnSend)
{
	_isUseSSL = isUseSSL;
	_cbOnConnected = cbOnConnected;
	_cbOnDisconnect = cbOnDisconnect;
	_cbOnRecv = cbOnRecv;
	_cbOnSend = cbOnSend;

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
	eventData->eventBase = eventBase;
	eventData->remoteIP = remoteIP;
	eventData->remotePort = remotePort;
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
			return false;
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
	_isBegin = true;
	return true;
}

void TCPHandler::onEventDataDeleted(EventData* eventData)
{
	if (_cbOnDisconnect)
	{
		_cbOnDisconnect(eventData);
	}

	if (_isBegin)
	{
		// 从已连接EventData列表中移除
		for (auto iter = _connectedEventDataList.begin(); iter != _connectedEventDataList.end(); ++iter)
		{
			if (*iter == eventData)
			{
				_connectedEventDataList.erase(iter);
				break;
			}
		}
	}	
}

void TCPHandler::onAccept(EventData* eventData, const sockaddr* remoteAddr)
{
	string remoteIP = "0";
	int remotePort = 0;

	_connectedEventDataList.emplace_back(eventData);

	if (_cbOnAccept)
	{
		_cbOnAccept(eventData, remoteAddr);
	}
}

void TCPHandler::onConnected(EventData* eventData)
{
	_connectedEventDataList.emplace_back(eventData);

	if (_cbOnConnected)
	{
		_cbOnConnected(eventData);
	}
}

void TCPHandler::onRecv(SocketData* socketData, const char* data, size_t dataSize)
{
	auto onError([=](NetDisconnectCode code, string_view errMsg)
		{
			socketData->asyncDelete();
			error(errMsg);
		});

	if (!socketData->isConnected())
	{
		return;
	}

	IOData* recvIOData = socketData->getRecvIOData();
	// 重置接收心跳时间
	socketData->resetHeartbeatRecv(steady_clock::now());

	// 处理数据
	uint64_t nodeNeedRcvBytes = 0;
	uint64_t nodeHasRcvBytes = 0;
	uint64_t nodeRemainWaitBytes = 0;
	uint64_t bufRemainSize = dataSize;
	while (bufRemainSize != 0)
	{
		// 处理头部数据（PackageBase）
		if (recvIOData->localPackage.tpStartTime == (steady_clock::time_point::min)())
		{
			recvIOData->localPackage.tpStartTime = steady_clock::now();
		}

		if (recvIOData->localPackage.receivedBytes < sizeof(PackageBase)) // 第一次传输
		{
			nodeNeedRcvBytes = sizeof(PackageBase);
			nodeHasRcvBytes = recvIOData->localPackage.receivedBytes;	// TCP只发送一次头部数据，而且由于存在粘包，所以头部数据可能不会一次就接收完毕

			// 计算节点剩余待读取字节数
			nodeRemainWaitBytes = nodeNeedRcvBytes - nodeHasRcvBytes;
			if (nodeRemainWaitBytes > bufRemainSize)
			{
				nodeRemainWaitBytes = bufRemainSize;
			}

			// 读取数据
			memcpy_s(&recvIOData->localPackage.headInfo + nodeHasRcvBytes, nodeRemainWaitBytes, data + (dataSize - bufRemainSize), nodeRemainWaitBytes);

			nodeHasRcvBytes += nodeRemainWaitBytes;
			recvIOData->localPackage.receivedBytes += nodeRemainWaitBytes;
			bufRemainSize -= nodeRemainWaitBytes;

			if (nodeHasRcvBytes == nodeNeedRcvBytes)
			{
				// 检查头部数据
				if (0 == recvIOData->localPackage.headInfo.size)
				{
					onError(NetDisconnectCode::HeadinfoError, "TCPHandler::onRecv headInfo.size==0");
					return;
				}

				if (NetInfoType::NIT_NULL == recvIOData->localPackage.headInfo.netInfoType)
				{
					onError(NetDisconnectCode::HeadinfoError, "TCPHandler::onRecv NIT_NULL");
					return;
				}

				if ((recvIOData->localPackage.headInfo.size > TL_MAX_NET_PACKAGE_SIZE) && (NetDataType::NDT_Memory == recvIOData->localPackage.headInfo.dataType))// 数据包过大（非文件）
				{
					onError(NetDisconnectCode::HeadinfoError, "TCPHandler::onRecv too big");
					return;
				}
			}
			else
			{
				// 头部数据未接收完成
				return;
			}
		}
		/*************************************************************************************************************************************************/

		// 处理内容
		switch (recvIOData->localPackage.headInfo.dataType)
		{
		case NetDataType::NDT_File:
		case NetDataType::NDT_MemoryAndFile:
		{
			if (bufRemainSize == 0)
			{
				return;
			}

			// 文件类型
			// 接收文件基本信息(FileInfo)
			if (recvIOData->localPackage.receivedBytes < sizeof(PackageBase) + sizeof(FileInfo))
			{
				nodeNeedRcvBytes = sizeof(FileInfo);
				nodeHasRcvBytes = recvIOData->localPackage.receivedBytes - sizeof(PackageBase);

				if (!recvIOData->localPackage.package1)
				{
					recvIOData->localPackage.package1Size = sizeof(FileInfo);
					recvIOData->localPackage.package1 = (char*)new FileInfo;
				}

				// 计算节点剩余待读取字节数
				nodeRemainWaitBytes = nodeNeedRcvBytes - nodeHasRcvBytes;
				if (nodeRemainWaitBytes > bufRemainSize)
				{
					nodeRemainWaitBytes = bufRemainSize;
				}

				// 读取数据
				memcpy_s(recvIOData->localPackage.package1 + nodeHasRcvBytes, nodeRemainWaitBytes, data + (dataSize - bufRemainSize), nodeRemainWaitBytes);

				nodeHasRcvBytes += nodeRemainWaitBytes;
				recvIOData->localPackage.receivedBytes += nodeRemainWaitBytes;
				bufRemainSize -= nodeRemainWaitBytes;

				if (nodeHasRcvBytes == nodeNeedRcvBytes)
				{
					// 生成本地文件路径
					string dirPath = ConcatPathFileName(CurentDirectory(), "download");
					MakeDirRecursively(dirPath.c_str()); // 创建本地保存文件夹
					FileInfo* fileInfo = (FileInfo*)recvIOData->localPackage.package1;
					recvIOData->localPackage.filePath = ConcatPathFileName(dirPath, fileInfo->fileName);
					info("TCPHandler::onRecv start recv file...");
				}
				else
				{
					break;
				}
			}

			if (0 == bufRemainSize)
			{
				break;
			}
			/*************************************************************************************************************************************************/

			// 接收附加内存数据
			FileInfo* fileInfo = (FileInfo*)recvIOData->localPackage.package1;
			if (NetDataType::NDT_MemoryAndFile == recvIOData->localPackage.headInfo.dataType)
			{
				if (recvIOData->localPackage.receivedBytes < recvIOData->localPackage.headInfo.size - fileInfo->fileLength)
				{
					nodeNeedRcvBytes = recvIOData->localPackage.headInfo.size - sizeof(PackageBase) - sizeof(FileInfo) - fileInfo->fileLength;
					nodeHasRcvBytes = recvIOData->localPackage.receivedBytes - sizeof(PackageBase) - sizeof(FileInfo);

					if (!recvIOData->localPackage.package2)
					{
						recvIOData->localPackage.package2Size = nodeNeedRcvBytes;
						recvIOData->localPackage.package2 = new char[nodeNeedRcvBytes];
						ZeroMemory(recvIOData->localPackage.package2, nodeNeedRcvBytes);
					}

					// 计算节点剩余待读取字节数
					nodeRemainWaitBytes = nodeNeedRcvBytes - nodeHasRcvBytes;
					if (nodeRemainWaitBytes > bufRemainSize)
					{
						nodeRemainWaitBytes = bufRemainSize;
					}

					// 读取数据
					memcpy_s(recvIOData->localPackage.package2 + nodeHasRcvBytes, nodeRemainWaitBytes, data + (dataSize - bufRemainSize), nodeRemainWaitBytes);

					nodeHasRcvBytes += nodeRemainWaitBytes;
					recvIOData->localPackage.receivedBytes += nodeRemainWaitBytes;
					bufRemainSize -= nodeRemainWaitBytes;

					if (nodeHasRcvBytes != nodeNeedRcvBytes)
					{
						break;
					}
				}
			}

			if (0 == bufRemainSize)
			{
				return;
			}
			/*************************************************************************************************************************************************/

			// 接收文件
			nodeNeedRcvBytes = fileInfo->fileLength;
			if (NetDataType::NDT_MemoryAndFile == recvIOData->localPackage.headInfo.dataType)
			{
				nodeHasRcvBytes = recvIOData->localPackage.receivedBytes - sizeof(PackageBase) - sizeof(FileInfo) - recvIOData->localPackage.package2Size;
			}
			else
			{
				nodeHasRcvBytes = recvIOData->localPackage.receivedBytes - sizeof(PackageBase) - sizeof(FileInfo);
			}
		
			// 计算节点剩余待读取字节数
			nodeRemainWaitBytes = nodeNeedRcvBytes - nodeHasRcvBytes;
			if (nodeRemainWaitBytes > bufRemainSize)
			{
				nodeRemainWaitBytes = bufRemainSize;
			}

			// 读取数据
#ifdef _WIN32
			std::wstring wsFilePath = UTF8ToUnicode(recvIOData->localPackage.filePath.c_str());
			ofstream writeFile(wsFilePath.c_str(), ios::binary | ios::app);
#else
			ofstream writeFile(recvIOData->localPackage.filePath.c_str(), ios::binary);
#endif
			if (!writeFile.is_open())
			{
				// todo 删除已接收文件
				onError(NetDisconnectCode::CreateWriteFileError, "TCPHandler::onRecv ofstream open failed");
				return;
			}
			writeFile.seekp(ios::end);
			writeFile.write(data + (dataSize - bufRemainSize), nodeRemainWaitBytes);
			writeFile.close();

			nodeHasRcvBytes += nodeRemainWaitBytes;
			recvIOData->localPackage.receivedBytes += nodeRemainWaitBytes;
			bufRemainSize -= nodeRemainWaitBytes;

			if (nodeHasRcvBytes == nodeNeedRcvBytes)
			{
				// 保存结束时间
				recvIOData->localPackage.tpEndTime = steady_clock::now();

				// 保存最新IO序号
				socketData->recvIONumber = recvIOData->localPackage.headInfo.ioNum;			

				// 通知接收完成
				if (_cbOnRecv)
				{
					_cbOnRecv((const EventData*)socketData, &recvIOData->localPackage);
				}

				// 回复确认
				if (recvIOData->localPackage.headInfo.isNeedConfirm)
				{
					replyConfirm(socketData, recvIOData->localPackage.headInfo.ioNum);
				}

				socketData->resetRecvIOData();
				continue;
			}
			else
			{
				break;
			}
		}
		break;
		case NetDataType::NDT_Memory:
		{
			nodeNeedRcvBytes = recvIOData->localPackage.headInfo.size - sizeof(PackageBase);
			nodeHasRcvBytes = recvIOData->localPackage.receivedBytes - sizeof(PackageBase);

			// 有Package数据
			if (0 != nodeNeedRcvBytes)
			{
				if (bufRemainSize == 0)
				{
					return;
				}

				if (!recvIOData->localPackage.package1)
				{
					recvIOData->localPackage.package1Size = recvIOData->localPackage.headInfo.size - sizeof(PackageBase);
					recvIOData->localPackage.package1 = new char[recvIOData->localPackage.package1Size];
					ZeroMemory(recvIOData->localPackage.package1, recvIOData->localPackage.package1Size);
				}

				// 计算节点剩余待读取字节数
				nodeRemainWaitBytes = nodeNeedRcvBytes - nodeHasRcvBytes;
				if (nodeRemainWaitBytes > bufRemainSize)
				{
					nodeRemainWaitBytes = bufRemainSize;
				}

				// 读取数据
				memcpy_s(recvIOData->localPackage.package1 + nodeHasRcvBytes, nodeRemainWaitBytes, data + (dataSize - bufRemainSize), nodeRemainWaitBytes);

				nodeHasRcvBytes += nodeRemainWaitBytes;
				recvIOData->localPackage.receivedBytes += nodeRemainWaitBytes;
				bufRemainSize -= nodeRemainWaitBytes;

				if (nodeHasRcvBytes != nodeNeedRcvBytes)
				{
					return;
				}
			}
			/**************************************************************************************************************************/

			if (nodeHasRcvBytes == nodeNeedRcvBytes)
			{
				// 全部Package接收完毕
				// 保存结束时间
				recvIOData->localPackage.tpEndTime = steady_clock::now();

				// 保存最新IO序号
				socketData->recvIONumber = recvIOData->localPackage.headInfo.ioNum;

				switch (recvIOData->localPackage.headInfo.netInfoType)
				{
					case NetInfoType::NIT_Heartbeat:
					{
						socketData->resetRecvIOData();
						continue;
					}
					case NetInfoType::NIT_AutoConfirm:
					{
						// 清理SendIOData
						IOData* sendIOData = socketData->getWaitSendIOData();
						if (sendIOData && sendIOData->localPackage.headInfo.ioNum == recvIOData->localPackage.headInfo.ioNum)
						{
							// 从发送列表中移除头部ioDatareplyConfirm
							socketData->onSendComplete();
						}

						socketData->resetRecvIOData();

						// 继续发送
						sendIOData = socketData->getWaitSendIOData();
						if (sendIOData)
						{
							send(sendIOData);
						}
						continue;
					}
					default:
					{
						// 通知接收完成
						if (_cbOnRecv)
						{
							_cbOnRecv((const EventData*)socketData, &recvIOData->localPackage);
						}
					}
				}

				// 回复确认
				if (recvIOData->localPackage.headInfo.isNeedConfirm)
				{
					replyConfirm(socketData, recvIOData->localPackage.headInfo.ioNum);
				}

				socketData->resetRecvIOData();
				continue;
			}
			else
			{
				break;
			}
		}
		break;
		default:
			ASSERT(0);
		}
	}
}

void TCPHandler::onSend(SocketData* socketData)
{
	if (!socketData->isConnected())
	{
		return;
	}

	IOData* ioData = socketData->getWaitSendIOData();
	if (ioData)
	{
		onReadySend(socketData, ioData, false);
	}
}

bool TCPHandler::send(const EventData* eventData, const char* data, size_t dataSize)
{
	if (!eventData->isConnected())
	{
		return false;
	}

	int ret = bufferevent_write(eventData->bev, data, dataSize);
	if (ret != 0)
	{
		warn(str_format("TCPHandler::send failed ret:%d", ret));
		return false;
	}
	
	return true;
}

void TCPHandler::send(IOData* ioData)
{
	if (nullptr == ioData->socketData) 
	{
		return;
	}

	bool isSucceed = true;
	int nodeSendBytes = 0; // 当前节点已发送字节数
	int nodeRemainSendBytes = 0; // 当前节点剩余待发送字节数
	int currentSendBytes = SINGLE_PACKAGE_SIZE; // 当前将要发送字节数

	// 重置发送心跳时间
	ioData->socketData->tpSendHeartbeat = steady_clock::now();	

	do
	{
		// 发送headInfo
		if (ioData->localPackage.sendBytes < sizeof(PackageBase))
		{
			ioData->localPackage.tpStartTime = ioData->socketData->tpSendHeartbeat;
			isSucceed = send((EventData*)ioData->socketData, (const char*)&ioData->localPackage.headInfo, sizeof(PackageBase));
			if (!isSucceed)
			{
				warn("TCPHandler::send headInfo faild");
				break;
			}

			ioData->localPackage.sendBytes += sizeof(PackageBase);
		}

		// 发送package1
		if (ioData->localPackage.package1Size > 0 && ioData->localPackage.sendBytes < sizeof(PackageBase) + ioData->localPackage.package1Size)
		{
			do
			{
				nodeSendBytes = ioData->localPackage.sendBytes - sizeof(PackageBase);
				nodeRemainSendBytes = ioData->localPackage.package1Size - nodeSendBytes;
				if (0 == nodeRemainSendBytes)
				{
					break;
				}

				currentSendBytes = nodeRemainSendBytes;
				if (currentSendBytes > SINGLE_PACKAGE_SIZE)
				{
					currentSendBytes = SINGLE_PACKAGE_SIZE;
				}

				isSucceed = send((EventData*)ioData->socketData, ioData->localPackage.package1 + nodeSendBytes, currentSendBytes);
				if (isSucceed)
				{
					ioData->localPackage.sendBytes += currentSendBytes;
				}
				else
				{
					break;
				}
			} while (true);

			if (!isSucceed)
			{
				break;
			}
		}

		// 发送package2
		if (ioData->localPackage.package2Size > 0 && ioData->localPackage.sendBytes < sizeof(PackageBase) + ioData->localPackage.package1Size + ioData->localPackage.package2Size)
		{
			do
			{
				nodeSendBytes = ioData->localPackage.sendBytes - (sizeof(PackageBase) + ioData->localPackage.package1Size);
				nodeRemainSendBytes = ioData->localPackage.package2Size - nodeSendBytes;
				if (0 == nodeRemainSendBytes)
				{
					break;
				}

				currentSendBytes = nodeRemainSendBytes;
				if (currentSendBytes > SINGLE_PACKAGE_SIZE)
				{
					currentSendBytes = SINGLE_PACKAGE_SIZE;
				}

				isSucceed = send((EventData*)ioData->socketData, ioData->localPackage.package2 + nodeSendBytes, currentSendBytes);
				if (isSucceed)
				{
					ioData->localPackage.sendBytes += currentSendBytes;
				}
				else
				{
					break;
				}
			} while (true);

			if (!isSucceed)
			{
				break;
			}
		}

		// 发送文件
		if (NetDataType::NDT_File == ioData->localPackage.headInfo.dataType
			|| NetDataType::NDT_MemoryAndFile == ioData->localPackage.headInfo.dataType)
		{
#ifdef _WIN32
			std::wstring wsFilePath = UTF8ToUnicode(ioData->localPackage.filePath.c_str());
			ifstream readFile(wsFilePath.c_str(), ios::binary);
#else
			ifstream readFile(ioData->localPackage.filePath.c_str(), ios::in | ios::binary);
#endif
			if (!readFile)
			{
				warn("TCPHandler::send readFile faild");
				break;
			}

			FileInfo* fileInfo = (FileInfo*)ioData->localPackage.package1;
			readFile.seekg(fileInfo->fileLength - (ioData->localPackage.headInfo.size - ioData->localPackage.sendBytes), ios::beg);
			char* tmpBufer = new char[SINGLE_PACKAGE_SIZE];
			auto onReadFile = [&]
			{
				isSucceed = send((EventData*)ioData->socketData, tmpBufer, readFile.gcount());
				if (!isSucceed)
				{
					return;
				}

				ioData->localPackage.sendBytes += readFile.gcount();
			};
			while (readFile.read(tmpBufer, SINGLE_PACKAGE_SIZE))
			{ 
				onReadFile();
			}

			if (readFile.eof() && readFile.gcount() > 0)
			{
				onReadFile();
			}
		
			readFile.close();
			delete[] tmpBufer;
		}
	} while (false);

	onReadySend(ioData->socketData, ioData, true);
}

void TCPHandler::onReadySend(SocketData* socketData, IOData* ioData, bool isSending)
{
	if (!socketData->isConnected())
	{
		return;
	}

	socketData->isSending = true;

	// 检查数据是否全部发送完成
	if (ioData->localPackage.headInfo.size == ioData->localPackage.sendBytes)
	{
		ioData->localPackage.tpEndTime = steady_clock::now();

		if (!ioData->isSendNotify && ioData->localPackage.headInfo.netInfoType > NetInfoType::NIT_InternalMsg)
		{
			if (_cbOnSend)
			{
				_cbOnSend((const EventData*)ioData->socketData, &ioData->localPackage);
			}
			ioData->isSendNotify = true;
		}

		if (ioData->isNeedConfirmRecv())
		{
			// 不再继续发送列表，清理数据、发送下一个的操作将在收到确认信息后进行
			return;
		}

		// 从发送列表中移除头部ioData
		socketData->onSendComplete();

		// 检查发送列表是否有待发送的对象
		IOData* waitSendIOData = socketData->getWaitSendIOData();
		if (waitSendIOData)
		{
			send(waitSendIOData);
		}
	}
	else
	{
		// 继续发送
		send(ioData);
	}

	socketData->isSending = isSending;
}

void TCPHandler::replyConfirm(SocketData* socketData, ULONG ioNum)
{
	auto* ioData = socketData->getIOData(NetAction::ACTION_SEND, NetInfoType::NIT_AutoConfirm);
	ioData->localPackage.headInfo.ioNum = ioNum;

	sendList(ioData, true);
}

bool TCPHandler::sendList(IOData* ioData, bool priority)
{
	if (!ioData)
	{
		return false;
	}

	if (!ioData->socketData->isConnected())
	{
		return false;
	}

	// 检查是否正在发送数据
	bool isSendListEmpty = ioData->socketData->isSendListEmpty();

	// 添加进发送列表
	if (!ioData->socketData->addSendList(ioData, priority))
	{
		ioData->reset();
		return false;
	}

	if (isSendListEmpty)
	{
		// 激活发送列表
		auto onEventActive = [](evutil_socket_t fd, short event, void* arg)
			{
				CommonEvent* commonEvent = (CommonEvent*)arg;
				commonEvent->tcpHandler->onSend(commonEvent->socketData);
				delete commonEvent;
			};

		// 激活发送列表
		CommonEvent* commonEvent = new CommonEvent;
		commonEvent->tcpHandler = this;
		commonEvent->socketData = ioData->socketData;
		timeval timeout = { 0, 0 };
		if (0 != event_base_once(((EventData*)ioData->socketData)->eventBase, -1, EV_TIMEOUT, onEventActive, commonEvent, &timeout))
		{
			error("TCPHandler::_sendList event_base_once failed");
		}
	}

	return true;
}

bool TCPHandler::sendList(EventData* eventData, char* data, size_t dataSize, bool isNeedConfirm)
{
	IOData* ioData = eventData->getIOData(NetAction::ACTION_SEND, NetInfoType::NIT_Message, data, dataSize, isNeedConfirm);
	return sendList(ioData);
}

bool TCPHandler::sendList(EventData* eventData, const string& filePath)
{
	FileInfo* fileInfo = new FileInfo;
	string fileName = StripPath(filePath);
	strncpy_s(fileInfo->fileName, fileName.c_str(), fileName.length());
	memset(fileInfo->fileName + fileName.length(), 0, sizeof(fileInfo->fileName) - fileName.length());
	fileInfo->fileLength = getFileSize(filePath.c_str());

	IOData* ioData = eventData->getIOData(NetAction::ACTION_SEND, NetInfoType::NIT_File, fileInfo, filePath);
	return sendList(ioData);
}
