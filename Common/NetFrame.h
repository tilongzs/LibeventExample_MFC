#pragma once
#include <string>
#include <list>
#include <mutex>
#include <chrono>

using std::string;
using std::list;
using std::mutex;
using std::recursive_mutex;
using namespace std::chrono;

// 网络数据类型
enum class NetDataType
{
	NDT_Memory,	// 内存数据
	NDT_File,	// 文件数据
	NDT_MemoryAndFile	// 内存+文件数据
};

// 自定义业务网络信息类型
enum class NetInfoType
{
	NIT_NULL,
	NIT_Heartbeat,		// 心跳
	NIT_AutoConfirm,	// 自动回复确认

	NIT_InternalMsg,
	// 上面的内部程序数据一般不与通知
	/***********************************************/

	NIT_Message,
	NIT_File,
};

// 网络断开连接原因代码
enum class NetDisconnectCode
{
	Unknown,		// 未知
	Exception,		// 异常
	ExistingConnection,		// 连接已存在
	HeadinfoError,		// 头信息错误
	CreateWriteFileError,		// 创建写文件句柄错误
};

enum class NetAction
{
	ACTION_NULL,		// 用于初始化

	ACTION_DISCONNECT,
	ACTION_ACCEPT,
	ACTION_CONNECT,
	ACTION_SEND,
	ACTION_RECV,
};

// socket用途
enum class SocketPurpose
{
	SP_Msg,		// 传递消息
	SP_File		// 传递文件
};

// 网络包基本信息
#pragma pack(push)
#pragma pack(1) // 1字节内存对齐
class PackageBase
{
public:
	uint32_t		ioNum;	// 通信流水号
	NetDataType		dataType;		// 网络数据类型（int）
	bool			needConfirm;	// 是否需要对方回复收到确认；默认文件数据需要，其它不需要
	NetInfoType		netInfoType;	// 自定义业务网络信息类型（int）
	uint64_t		size;	// 长度（字节、包含自身）

	PackageBase()
	{
		reset();
	}

	void reset() 
	{
		ioNum = 0;
		dataType = NetDataType::NDT_Memory;
		needConfirm = false;
		netInfoType = NetInfoType::NIT_NULL;
		size = sizeof(PackageBase);
	}
};

// 文件信息
struct FileInfo
{
	uint64_t fileLength = 0; // unsigned long long
	char fileName[260]{ 0 };
};
#pragma pack(pop) // #pragma pack(1)

struct PackageLocalFile
{
	FileInfo fileinfo;
	string	path;
};

class PackageInfo
{
public:
	PackageBase headInfo;
	char* package1 = nullptr;
	char* package2 = nullptr;

	void deletePackage();
};

class LocalPackage : public PackageInfo
{
public:
	void clear()
	{
		deletePackage();

		headInfo.reset();
		sendBytes = 0;
		receivedBytes = 0;
		tpStartTime = (steady_clock::time_point::min)();
		tpEndTime = (steady_clock::time_point::min)();
		filePath = "";
		package1Size = 0;
		package2Size = 0;
	}

	uint64_t sendBytes = 0; // 已发送字节数
	uint64_t receivedBytes = 0;	// 已接收字节数
	steady_clock::time_point  tpStartTime = (steady_clock::time_point::min)();		// 传输的开始时间
	steady_clock::time_point  tpEndTime = (steady_clock::time_point::min)();		// 传输的结束时间

	string filePath;
	uint64_t package1Size = 0;
	uint64_t package2Size = 0;
};

class SocketData;
class IOData
{
public:
	IOData(SocketData* socketData);

	NetAction	action = NetAction::ACTION_NULL;
	SocketData* socketData;

	int			    confirmTimeout = 1000;	// 自动确认的超时时长（毫秒）
	LocalPackage	localPackage;

	inline void setNeedConfirmRecv() { localPackage.headInfo.needConfirm = true; }
	inline bool isNeedConfirmRecv() { return localPackage.headInfo.needConfirm; }
	inline int getIONumber() { return localPackage.headInfo.ioNum; }

	void reset(NetAction newAction = NetAction::ACTION_NULL);
	void deleteBuf(); 
	bool isConfirmRecvTimeout(steady_clock::time_point& tp);
};

class SocketData
{
public:
	virtual ~SocketData();

	string    remoteIP;			// 远程地址
	int       remotePort = 0;     // 远程端口
	SocketPurpose	purpose = SocketPurpose::SP_Msg; // 用途：0、消息 1、文件

	bool		isSending = false;		// 是否正在发送数据
	int			sameTypeCount = 0;	// 相同数据类型的计数
	recursive_mutex		mtxSend; // 发送锁

	int			recvIONumber = 0;	// 最新的已接收IO序号
	int			sendIONumDistributor = 0;	// 数字标记分配器（发送IO数据）
	steady_clock::time_point 	tpSendHeartbeat;	// 心跳时间（发送）
	steady_clock::time_point 	tpSendReceivedBytes;	// 上次发送“已接收字节数”的时间

	IOData* getRecvIOData(); // 获取当前负责接收数据的IOData
	void resetRecvIOData();

	IOData* getIOData(NetAction action);
	IOData* getIOData(NetAction action, NetInfoType netInfoType); // ACTION_SEND
	IOData* getIOData(NetAction action, NetInfoType netInfoType, char* attachment, uint64_t attachmentSize); // ACTION_SEND 附带数据
	IOData* getIOData(NetAction action, NetInfoType netInfoType, FileInfo* fileInfo, const string& attachmentFilePath); // ACTION_SEND 附带文件
	IOData* getIOData(NetAction action, NetInfoType netInfoType, FileInfo* fileInfo, const string& attachmentFilePath, char* attachment, uint64_t attachmentSize); // ACTION_SEND 附带额外数据的文件
	void removeIOData(IOData* ioData);

	IOData* checkConfirmTimeout(); 	// 检查回复确认超时
	bool isHeartbeatTimeout(steady_clock::time_point currentTime, int heartbeatTimeoutMilliseconds); 	// 检查接收对方的心跳超时
	bool addSendList(IOData* ioData, bool priority = false);	// 增加至发送列表
	IOData* getWaitSendIOData();	// 获取下一个待发送IOData
	void onSendComplete();
	void setConnected(bool isConn);
	bool isConnected() const;
	void resetHeartbeatRecv(const steady_clock::time_point& tp);
	
	virtual void close() = 0;

private:
	bool		_isConnected = true;
	steady_clock::time_point 			_tpHeartbeatRecv;	// 心跳时间（接收）

	IOData* _recvIOData = nullptr;	// 当前负责接收数据的IOData；同时最多只存在一个。

	mutex			_mtxWaitSendIOList;
	list<IOData*>	_waitSendIOs;	// 待发送IO数据列表
	bool			_isFilterSameTypeIO = false;	// 自动排除超过 5 个重复类型的数据

	mutex			_mtxIOList;
	list<IOData*>	_ioList;		// 所有IO数据列表

	IOData* getFreeIOData(NetAction action);
	IOData* createNewIOData(NetAction action);
};