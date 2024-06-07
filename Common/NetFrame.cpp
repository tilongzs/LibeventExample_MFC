#include "NetFrame.h"

using namespace std;

#define MaxWaitSendIOs	100	// 最大数据发送队列数量

void PackageInfo::deletePackage()
{
	if (package1)
	{
		if (NetDataType::NDT_File == headInfo.dataType
			|| NetDataType::NDT_MemoryAndFile == headInfo.dataType)
		{
			FileInfo* ptr = reinterpret_cast<FileInfo*>(package1);
			if (nullptr != ptr)
			{
				delete ptr;
			}
		}
		else
		{
			delete[] package1;
		}
		package1 = nullptr;
	}

	if (package2)
	{
		delete[] package2;
		package2 = nullptr;
	}
}

IOData::IOData(SocketData* socketData)
{
	this->socketData = socketData;
}

void IOData::reset(NetAction newAction)
{
	if (action == NetAction::ACTION_RECV && !localPackage.filePath.empty() && (localPackage.tpEndTime != steady_clock::time_point::min())) {
		// todo
		// DeleteFile(localPackage.filePath); // 删除未接收完成的临时文件
	}

	localPackage.clear();
	action = newAction;
}

void IOData::deleteBuf()
{
	if (action == NetAction::ACTION_RECV && !localPackage.filePath.empty() && (localPackage.tpEndTime != steady_clock::time_point::min())) {
		// todo
		// DeleteFile(localPackage.filePath); // 删除未接收完成的临时文件
	}

	localPackage.clear();
	action = NetAction::ACTION_NULL;
}

bool IOData::isConfirmRecvTimeout(steady_clock::time_point& tp)
{
	if (!localPackage.headInfo.needConfirm)
	{
		return false;
	}

	if (localPackage.headInfo.dataType != NetDataType::NDT_Memory)
	{
		return false;
	}

	if (localPackage.tpStartTime == steady_clock::time_point::min())
	{
		return false;
	}

	milliseconds timeDuration = chrono::duration_cast<milliseconds>(tp - localPackage.tpStartTime);
	return timeDuration.count() > confirmTimeout;
}

SocketData::~SocketData()
{
	close();

	{
		lock_guard<mutex> lock(_mtxWaitSendIOList);
		_waitSendIOs.clear();
	}
	
	{
		lock_guard<mutex> lock(_mtxIOList);
		for (auto iter = _ioList.begin(); iter != _ioList.end(); ++iter)
		{
			delete* iter;
		}
		_ioList.clear();
	}
}

IOData* SocketData::getFreeIOData(NetAction action)
{
	{
		lock_guard<mutex> lock(_mtxIOList);
		for (auto iter : _ioList)
		{
			if (iter->action == NetAction::ACTION_NULL)
			{
				iter->action = action;

				if (action == NetAction::ACTION_SEND)
				{
					sendIONumDistributor++;
					iter->localPackage.headInfo.ioNum = sendIONumDistributor;
					return iter;
				}
			}
		}
	}	

	return createNewIOData(action);
}

IOData* SocketData::createNewIOData(NetAction action)
{
	auto ioData = new IOData(this);
	ioData->action = action;

	if (action == NetAction::ACTION_SEND)
	{
		sendIONumDistributor++;
		ioData->localPackage.headInfo.ioNum = sendIONumDistributor;
	}

	lock_guard<mutex> lock(_mtxIOList);
	_ioList.emplace_back(ioData);
	return ioData;
}

IOData* SocketData::getRecvIOData()
{
	if (nullptr == _recvIOData)
	{
		_recvIOData = createNewIOData(NetAction::ACTION_RECV);
	}

	return _recvIOData;
}

void SocketData::resetRecvIOData()
{
	_recvIOData->reset(NetAction::ACTION_RECV);
}

IOData* SocketData::getIOData(NetAction action)
{
	return getIOData(action, NetInfoType::NIT_NULL, nullptr, 0);
}

IOData* SocketData::getIOData(NetAction action, NetInfoType netInfoType)
{
	return getIOData(action, netInfoType, nullptr, 0);
}

IOData* SocketData::getIOData(NetAction action, NetInfoType netInfoType, char* attachment, uint64_t attachmentSize)
{
	IOData* ioData = getFreeIOData(action);
	ioData->localPackage.headInfo.dataType = NetDataType::NDT_Memory;
	ioData->localPackage.headInfo.netInfoType = netInfoType;
	ioData->localPackage.headInfo.size = sizeof(PackageBase) + attachmentSize;
	ioData->localPackage.package1 = attachment;
	ioData->localPackage.package1Size = attachmentSize;

	return ioData;
}

IOData* SocketData::getIOData(NetAction action, NetInfoType netInfoType, FileInfo* fileInfo, const string& attachmentFilePath)
{
	IOData* ioData = getFreeIOData(action);
	ioData->localPackage.headInfo.dataType = NetDataType::NDT_File;
	ioData->localPackage.headInfo.netInfoType = netInfoType;
	ioData->localPackage.headInfo.size = sizeof(PackageBase) + sizeof(FileInfo) + fileInfo->fileLength;
	ioData->localPackage.package1 = (char*)fileInfo;
	ioData->localPackage.package1Size = sizeof(FileInfo);
	ioData->localPackage.filePath = attachmentFilePath;

	return ioData;
}

IOData* SocketData::getIOData(NetAction action, NetInfoType netInfoType, FileInfo* fileInfo, const string& attachmentFilePath, char* attachment, uint64_t attachmentSize)
{
	IOData* ioData = getFreeIOData(action);
	ioData->localPackage.headInfo.dataType = NetDataType::NDT_MemoryAndFile;
	ioData->localPackage.headInfo.netInfoType = netInfoType;
	ioData->localPackage.package1 = (char*)fileInfo;
	ioData->localPackage.package1Size = sizeof(FileInfo);
	ioData->localPackage.package2 = attachment;
	ioData->localPackage.package2Size = attachmentSize;
	ioData->localPackage.filePath = attachmentFilePath;
	ioData->localPackage.headInfo.size = sizeof(PackageBase) + ioData->localPackage.package1Size + ioData->localPackage.package2Size + fileInfo->fileLength;

	return ioData;
}

void SocketData::removeIOData(IOData* ioData)
{
	{
		lock_guard<mutex> lock(_mtxIOList);
		for (auto iter = _ioList.begin(); iter != _ioList.end(); ++iter)
		{
			if (*iter == ioData)
			{
				_ioList.erase(iter);
				break;
			}
		}
	}	

	delete ioData;
}

IOData* SocketData::checkConfirmTimeout()
{
	if (!_isConnected)
	{
		return nullptr;
	}

	IOData* timeoutIOData = nullptr;
	{
		lock_guard<mutex> lock(_mtxWaitSendIOList);
		steady_clock::time_point currentTime = steady_clock::now();
		if (!_waitSendIOs.empty())
		{
			if (_waitSendIOs.front()->isConfirmRecvTimeout(currentTime))
			{
				// 重发
				timeoutIOData = _waitSendIOs.front();
			}
		}
	}
	
	return timeoutIOData;
}

bool SocketData::isHeartbeatTimeout(steady_clock::time_point currentTime, int heartbeatTimeoutMilliseconds)
{
	if (!_isConnected)
	{
		return false;
	}

	if (0 == heartbeatTimeoutMilliseconds)
	{
		return false;
	}

	milliseconds timeDuration = chrono::duration_cast<milliseconds>(currentTime - _tpHeartbeatRecv);
	return timeDuration.count() > heartbeatTimeoutMilliseconds;
}

bool SocketData::addSendList(IOData* ioData, bool priority)
{
	if (purpose != SocketPurpose::SP_File)
	{
		if (_waitSendIOs.size() > MaxWaitSendIOs)
		{
			return false; // 检查等待发送的列表长度，防止非文件类型的列表过长
		}
	}

	lock_guard<mutex> lock(_mtxWaitSendIOList);
	if (priority)
	{
		_waitSendIOs.emplace_front(ioData);
	}
	else
	{
		_waitSendIOs.emplace_back(ioData);
	}

	return true;
}


IOData* SocketData::getWaitSendIOData()
{
	IOData* ioData = nullptr;
	lock_guard<mutex> lock(_mtxWaitSendIOList);
	if (!_waitSendIOs.empty())
	{
		ioData = _waitSendIOs.front();
	}

	return ioData;
}

void SocketData::onSendComplete()
{
	lock_guard<mutex> lock(_mtxWaitSendIOList);
	if (!_waitSendIOs.empty())
	{
		IOData* ioData = _waitSendIOs.front();
		ioData->reset();
		_waitSendIOs.pop_front();
	}

	isSending = false;
}

void SocketData::setConnected(bool isConn)
{
	_isConnected = isConn;
	if (_isConnected)
	{
		_tpHeartbeatRecv = steady_clock::now(); // 心跳开始计时
	}
}

bool SocketData::isConnected() const
{
	return _isConnected;
}

void SocketData::resetHeartbeatRecv(const steady_clock::time_point& tp)
{
	if (tp >_tpHeartbeatRecv)
	{
		_tpHeartbeatRecv = tp;
	}
}

void SocketData::close()
{
	setConnected(false);
}