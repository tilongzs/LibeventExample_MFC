#include "Common.h"

#include <Shellapi.h>
#include <winioctl.h>
#include <ntddndis.h>
#include <strsafe.h>

#pragma comment(lib, "Gdiplus.lib")
#include <GdiPlus.h>
using namespace Gdiplus;

#pragma comment(lib, "IPHLPAPI.lib") 
#include <iphlpapi.h> 
#include <ws2tcpip.h>
#include <memory>
#include <algorithm>
#include <mutex>
#include <sstream>
#include <afxdisp.h>
#include <fstream>

using std::wistringstream;
using std::istringstream;
using std::ifstream;
using std::istreambuf_iterator;
using std::make_unique;

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

BOOL EnumTermAdapter(vector<IP_ADAPTER_INFO>& AdapterArray)
{
	PIP_ADAPTER_INFO	pAdapterInfo = NULL;
	PIP_ADAPTER_INFO	pAdapterTemp = NULL;
	DWORD				dwRtn = 0;
	ULONG				uNeedSize = 0;
	BOOL				bRtn = FALSE;

	do
	{
		// 先枚举网卡信息
		dwRtn = GetAdaptersInfo(pAdapterInfo, &uNeedSize);
		if (ERROR_BUFFER_OVERFLOW == dwRtn)
		{
			pAdapterInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uNeedSize);
		}

		if (NULL == pAdapterInfo)
		{
			break;
		}

		dwRtn = GetAdaptersInfo(pAdapterInfo, &uNeedSize);
		if (NO_ERROR != dwRtn)
		{
			break;
		}

		// 添加到数组里面
		pAdapterTemp = pAdapterInfo;
		while (pAdapterTemp)
		{
			IP_ADAPTER_INFO		AdapterNode = { 0 };
			CopyMemory(&AdapterNode, pAdapterTemp, sizeof(IP_ADAPTER_INFO));
			AdapterArray.emplace_back(AdapterNode);
			pAdapterTemp = pAdapterTemp->Next;
		}
		bRtn = TRUE;
	} while (0);

	if (pAdapterInfo)
	{
		HeapFree(GetProcessHeap(), 0, pAdapterInfo);
		pAdapterInfo = NULL;
	}
	return bRtn;
}

VOID GetAdapterDisplayName(char* szAdapterGuid, char* szDisplayName)
{
	HKEY		hKey = NULL;
	CHAR		szRegPath[MAX_PATH] = { 0 };

	ZeroMemory(szDisplayName, MAX_PATH);
	StringCbPrintfA(szRegPath, MAX_PATH, "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", szAdapterGuid);
	RegGetValueData(HKEY_LOCAL_MACHINE, (char*)szRegPath, "Name", szDisplayName);
}

BOOL IsAdapterLogicConnected(char* szAdapterName)
{
	ULONG       uConnectedState = IF_OPER_STATUS_NON_OPERATIONAL;
	vector<IP_ADAPTER_INFO> AdapterArray;
	DWORD		dwRetVal = 0;
	MIB_IFROW	IFRow = { 0 };
	BOOL		bRtn = FALSE;

	bRtn = EnumTermAdapter(AdapterArray);
	if (!bRtn)
	{
		return FALSE;
	}
	for (vector<IP_ADAPTER_INFO>::iterator it = AdapterArray.begin(); it != AdapterArray.end(); it++)
	{
		if (0 == _stricmp(szAdapterName, it->AdapterName))
		{
			IFRow.dwIndex = it->Index;
			dwRetVal = GetIfEntry(&IFRow);
			if (dwRetVal == NO_ERROR)
			{
				uConnectedState = IFRow.dwOperStatus;
			}
			break;
		}
	}
	if (IF_OPER_STATUS_OPERATIONAL == uConnectedState)
	{
		return TRUE;
	}
	return FALSE;
}

BOOL	IsAdapterPhyConnected(char* szAdapterName)
{
	BOOL		bRtn = FALSE;
	DWORD		dwReturnedCount = 0;
	ULONG       uConnectedState = 0;
	DWORD		dwBytesWritten = 0;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;
	CHAR		szDeviceName[MAX_PATH] = { 0 };
	ULONG		uOidCode = 0;

	StringCbCopyA(szDeviceName, MAX_PATH, "\\\\.\\");
	StringCbCatA(szDeviceName, MAX_PATH, szAdapterName);

	hDevice = CreateFileA(szDeviceName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, INVALID_HANDLE_VALUE);
	if (hDevice != INVALID_HANDLE_VALUE)
	{
		uOidCode = OID_GEN_MEDIA_CONNECT_STATUS;
		bRtn = DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &uOidCode, sizeof(uOidCode), &uConnectedState, sizeof(uConnectedState), &dwBytesWritten, NULL);
		CloseHandle(hDevice);
	}

	if (NdisMediaStateConnected == uConnectedState)
	{
		return TRUE;
	}
	return FALSE;;
}

BOOL IsVirtualNetCard(char* szAdapterName)
{
	char	szDisplayName[MAX_PATH] = { 0 };
	BOOL	bRtn = FALSE;

	GetAdapterDisplayName(szAdapterName, szDisplayName);
	if (strlen(szDisplayName) && (strstr(szDisplayName, "VMware") || strstr(szDisplayName, "VirtualBox")))
	{
		bRtn = TRUE;
	}
	return bRtn;
}

BOOL GetActiveAdapterInfo(IP_ADAPTER_INFO& AdapterInfo)
{
	vector<IP_ADAPTER_INFO> AdapterArray;
	BOOL	bRtn = FALSE;
	BOOL	bPhyConnected = FALSE;

	BOOL	bLogicConnected = FALSE;
	BOOL	bIsVmNetCard = FALSE;

	do
	{
		// 获取本地网卡信息
		if (!EnumTermAdapter(AdapterArray))
		{
			break;
		}
		// 开始枚举网卡，如果物理状态和逻辑状态都是连接，则就是当前活动网卡
		for (vector<IP_ADAPTER_INFO>::iterator it = AdapterArray.begin(); it != AdapterArray.end(); it++)
		{
			PIP_ADAPTER_INFO	pTemp = (PIP_ADAPTER_INFO)&(*it);
			bPhyConnected = IsAdapterPhyConnected(it->AdapterName);
			bLogicConnected = IsAdapterLogicConnected(it->AdapterName);
			bIsVmNetCard = IsVirtualNetCard(it->AdapterName);
			if (bPhyConnected && bLogicConnected && !bIsVmNetCard)
			{
				CopyMemory(&AdapterInfo, pTemp, sizeof(IP_ADAPTER_INFO));
				bRtn = TRUE;
				break;
			}
		}
	} while (0);

	return bRtn;
}

BOOL GetFirstPhysicAdapterInfo(IP_ADAPTER_INFO& AdapterInfo)
{
	vector<IP_ADAPTER_INFO> AdapterArray;
	BOOL	bRtn = FALSE;
	BOOL	bIsVmNetCard = FALSE;

	do
	{
		// 获取本地网卡信息
		if (!EnumTermAdapter(AdapterArray))
		{
			break;
		}
		// 开始枚举网卡，如果物理状态和逻辑状态都是连接，则就是当前活动网卡
		for (vector<IP_ADAPTER_INFO>::iterator it = AdapterArray.begin(); it != AdapterArray.end(); it++)
		{
			PIP_ADAPTER_INFO	pTemp = (PIP_ADAPTER_INFO)&(*it);
			bIsVmNetCard = IsVirtualNetCard(it->AdapterName);
			if (!bIsVmNetCard)
			{
				CopyMemory(&AdapterInfo, pTemp, sizeof(IP_ADAPTER_INFO));
				bRtn = TRUE;
				break;
			}
		}
	} while (0);

	return bRtn;
}

BOOL GetAdapterInfoByGuid(IP_ADAPTER_INFO& AdapterInfo, LPCSTR pAdapterName)
{
	vector<IP_ADAPTER_INFO> AdapterArray;
	BOOL	bRtn = FALSE;
	BOOL	bPhyConnected = FALSE;
	BOOL	bLogicConnected = FALSE;
	BOOL	bIsVmNetCard = FALSE;

	do
	{
		// 获取本地网卡信息
		if (!EnumTermAdapter(AdapterArray))
		{
			break;
		}
		// 开始枚举网卡，如果物理状态和逻辑状态都是连接，则就是当前活动网卡
		for (vector<IP_ADAPTER_INFO>::iterator it = AdapterArray.begin(); it != AdapterArray.end(); it++)
		{
			if (0 == _stricmp(pAdapterName, it->AdapterName))
			{
				PIP_ADAPTER_INFO	pTemp = (PIP_ADAPTER_INFO)&(*it);
				CopyMemory(&AdapterInfo, pTemp, sizeof(IP_ADAPTER_INFO));
				bRtn = TRUE;
				break;
			}
		}
	} while (0);

	return bRtn;
}

VOID GetAdapterBroadCastAddress(string strIpAddr, string strMaskAddr, string& strBroadCastAddress)
{
	in_addr addr;
	inet_pton(AF_INET, strIpAddr.c_str(), (void *)&addr);
	ULONG uIpAddr = addr.s_addr;
	inet_pton(AF_INET, strMaskAddr.c_str(), (void *)&addr);
	ULONG uMaskAddr = addr.s_addr;;

	ULONG uRealAddr = uIpAddr & uMaskAddr;
	ULONG uBroadcastAddr = uIpAddr & uMaskAddr | (~uMaskAddr);

	in_addr servAddr = { 0 };
	memcpy(&servAddr.S_un.S_addr, (DWORD*)&(uBroadcastAddr), sizeof(DWORD));
	CHAR szTemp[16] = { 0 };
	inet_ntop(AF_INET, (void *)&servAddr, szTemp, 16);
	strBroadCastAddress = szTemp;
}

VOID GetAdapterSegment(char* strIpAddr, char* strMaskAddr, char* szSegment)
{
	in_addr addr;
	inet_pton(AF_INET, strIpAddr, (void *)&addr);
	ULONG uIpAddr = addr.s_addr;
	inet_pton(AF_INET, strMaskAddr, (void *)&addr);
	ULONG uMaskAddr = addr.s_addr;;

	ULONG uSegment = uIpAddr&uMaskAddr;
	in_addr servAddr = { 0 };
	memcpy(&servAddr.S_un.S_addr, (DWORD*)&(uSegment), sizeof(DWORD));
	inet_ntop(AF_INET, (void *)&servAddr, szSegment, 16);
}

VOID GetAdapterMacAddress(IP_ADAPTER_INFO& AdapterData, char* szMacAddress)
{
	if (AdapterData.AddressLength >= 6)
	{
		ZeroMemory(szMacAddress, MAX_PATH);
		StringCbPrintfA(szMacAddress, MAX_PATH, "%02X:%02X:%02X:%02X:%02X:%02X",
			AdapterData.Address[0],
			AdapterData.Address[1],
			AdapterData.Address[2],
			AdapterData.Address[3],
			AdapterData.Address[4],
			AdapterData.Address[5]);
	}
}

VOID GetAdapterRealMac(string strAdapterGuid, string& strAdapterMac)
{
	HANDLE	hDevice = INVALID_HANDLE_VALUE;
	int		inBuf = OID_802_3_PERMANENT_ADDRESS;
	BYTE	outBuf[MAX_PATH] = { 0 };
	DWORD	dwBytesReturned = 0;
	BOOL	bRtn = FALSE;
	CHAR	szTemp[MAX_PATH] = { 0 };

	do
	{
		StringCbPrintfA(szTemp, MAX_PATH, "\\\\.\\%s", strAdapterGuid.c_str());
		hDevice = CreateFileA(szTemp, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
		if (INVALID_HANDLE_VALUE == hDevice)
		{
			break;
		}
		bRtn = DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, (LPVOID)&inBuf, sizeof(DWORD), outBuf, MAX_PATH, &dwBytesReturned, NULL);
		if (bRtn)
		{
			CHAR	szRealMac[MAX_PATH] = { 0 };
			StringCbPrintfA(szRealMac, MAX_PATH, "%02X:%02X:%02X:%02X:%02X:%02X", outBuf[0], outBuf[1], outBuf[2], outBuf[3], outBuf[4], outBuf[5]);
			strAdapterMac = szRealMac;
		}
	} while (0);

	if (INVALID_HANDLE_VALUE != hDevice)
	{
		CloseHandle(hDevice);
	}
}


std::vector<uint16_t> GetAllTcpConnectionsPort()
{
	std::vector<uint16_t> ret;
	ULONG size = 0;
	GetTcpTable(NULL, &size, TRUE);
	std::unique_ptr<char[]> buffer(new char[size]);

	PMIB_TCPTABLE tcpTable = reinterpret_cast<PMIB_TCPTABLE>(buffer.get());
	if (GetTcpTable(tcpTable, &size, FALSE) == NO_ERROR)
		for (size_t i = 0; i < tcpTable->dwNumEntries; i++)
			ret.emplace_back(ntohs((uint16_t)tcpTable->table[i].dwLocalPort));
	std::sort(std::begin(ret), std::end(ret));
	return ret;
}

std::vector<uint16_t> GetAllUdpConnectionsPort()
{
	std::vector<uint16_t> ret;
	ULONG size = 0;
	GetUdpTable(NULL, &size, TRUE);
	std::unique_ptr<char[]> buffer(new char[size]);

	PMIB_UDPTABLE udpTable = reinterpret_cast<PMIB_UDPTABLE>(buffer.get());
	if (GetUdpTable(udpTable, &size, FALSE) == NO_ERROR)
		for (size_t i = 0; i < udpTable->dwNumEntries; i++)
			ret.emplace_back(ntohs((uint16_t)udpTable->table[i].dwLocalPort));
	std::sort(std::begin(ret), std::end(ret));
	return ret;
}

uint16_t GetAvailableTCPPort(uint16_t begin, uint16_t end)
{
	auto vec = GetAllTcpConnectionsPort();
	for (uint16_t port = begin; port != end; ++port)
		if (!std::binary_search(std::begin(vec), std::end(vec), port))
			return port;
	return 0;
}

uint16_t GetAvailableUDPPort(uint16_t begin, uint16_t end)
{
	auto vec = GetAllUdpConnectionsPort();
	for (uint16_t port = begin; port != end; ++port)
		if (!std::binary_search(std::begin(vec), std::end(vec), port))
			return port;
	return 0;
}

uint16_t GetAvailablePort(uint16_t begin, uint16_t end)
{
	auto vecTcp = GetAllTcpConnectionsPort(),
		vecUdp = GetAllUdpConnectionsPort();
	for (uint16_t port = begin; port != end; ++port)
		if (!std::binary_search(std::begin(vecTcp), std::end(vecTcp), port) &&
			!std::binary_search(std::begin(vecUdp), std::end(vecUdp), port))
			return port;
	return 0;
}

wstring GenerateIP(DWORD dwIP)
{
	wchar_t strIP[16] = { 0 };
	WORD hiWord = HIWORD(dwIP);
	WORD loWord = LOWORD(dwIP);
	char nf1 = HIBYTE(hiWord);
	char nf2 = LOBYTE(hiWord);
	char nf3 = HIBYTE(loWord);
	char nf4 = LOBYTE(loWord);

	wsprintf(strIP, L"%u.%u.%u.%u", nf1, nf2, nf3, nf4);
	return wstring(strIP);
}

bool IsSame(const SOCKADDR_IN& addrA, const SOCKADDR_IN& addrB)
{
	return ((addrA.sin_addr.S_un.S_addr == addrB.sin_addr.S_un.S_addr)
		&& (addrA.sin_port == addrB.sin_port));
}

void ConvertIPPort(const SOCKADDR_IN& addr, OUT string& ip, OUT int& port)
{
	char charBuf[16] = { 0 };
	inet_ntop(AF_INET, &addr.sin_addr, charBuf, 16);
	ip = charBuf;
	port = ntohs(addr.sin_port);
}

bool ConvertIPPort(const string& ip, int port, OUT SOCKADDR_IN& addr)
{
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	return (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 0);
}

void ConvertIPPort(DWORD ip, int port, OUT SOCKADDR_IN& addr)
{
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);
}

wstring GetOuterIP()
{
	wstring strIp;
	wchar_t buf[MAX_PATH] = { 0 };
	wchar_t chTempIp[64] = { 0 };
	wchar_t ipBuf[64] = { 0 };

	//将网页数据临时文件中
	WCHAR tempFilePath[MAX_PATH] = { 0 };
	GetTempPath(MAX_PATH, tempFilePath);
	PathAppend(tempFilePath, L"outeriptemp");
	HRESULT ret = URLDownloadToFile(0, L"http://ip138.com/", tempFilePath, BINDF_GETNEWESTVERSION, NULL);
	if (S_OK == ret)
	{
		FILE *fp = nullptr;
		_wfopen_s(&fp, tempFilePath, L"r");
		if (fp != NULL)
		{
			fseek(fp, 0, SEEK_SET);
			fread(buf, 1, MAX_PATH, fp);
			fclose(fp);

			//在buf中查找 [ 的位置, iIndex是buf中从[开始剩下的字符串，包括[这个字符串
			wchar_t* iIndex = wcschr(buf, L'[');
			if (iIndex)
			{
				wsprintf(chTempIp, L"%s", iIndex);
				int nBuflen = wcslen(chTempIp);

				for (int i = 0; i < nBuflen; i++)
				{
					ipBuf[i] = chTempIp[i + 1];

					//如果发现有 ] 则截断
					if (chTempIp[i] == ']')
					{
						ipBuf[i - 1] = '\0';
					}
				}

				strIp = ipBuf;
			}
		}

		DeleteFile(tempFilePath);
	}

	return strIp;
}

VOID GetIpAddrSegment(LPCSTR lpIpAddr, LPCSTR lpMaskAddr, LPSTR lpSegment)
{
	in_addr addr;
	inet_pton(AF_INET, lpIpAddr, (void *)&addr);
	ULONG uIpAddr = addr.s_addr;
	inet_pton(AF_INET, lpMaskAddr, (void *)&addr);
	ULONG uMaskAddr = addr.s_addr;;

	ULONG uSegment = uIpAddr&uMaskAddr;
	in_addr servAddr = { 0 };
	memcpy(&servAddr.S_un.S_addr, (DWORD*)&(uSegment), sizeof(DWORD));

	ZeroMemory(lpSegment, 16);
	inet_ntop(AF_INET, (void *)&servAddr, lpSegment, 16);
}

BOOL RegGetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, char* szValueData)
{
	HKEY hSubKey = NULL;
	BOOL bRetVal = FALSE;
	LONG lRetVal = ERROR_SUCCESS;

	lRetVal = RegOpenKeyExA(hkey, pszSubKey, 0, KEY_READ, &hSubKey);
	if (lRetVal == ERROR_SUCCESS)
	{
		DWORD lpType = REG_SZ;
		DWORD lpcbData = MAX_PATH;

		lRetVal = RegQueryValueExA(hSubKey, pszValueName, NULL, &lpType, (LPBYTE)szValueData, &lpcbData);
		if (lRetVal == ERROR_SUCCESS)
		{
			bRetVal = TRUE;
		}
		RegCloseKey(hSubKey);
	}

	return bRetVal;
}


BOOL RegGetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, string& strValueData)
{
	HKEY hSubKey = NULL;
	BOOL bRetVal = FALSE;
	LONG lRetVal = ERROR_SUCCESS;
	CHAR szTemp[4096] = { 0 };

	strValueData = "";
	lRetVal = RegOpenKeyExA(hkey, pszSubKey, 0, KEY_READ, &hSubKey);
	if (lRetVal == ERROR_SUCCESS)
	{
		DWORD lpType = REG_SZ;
		DWORD lpcbData = 4096;

		lRetVal = RegQueryValueExA(hSubKey, pszValueName, NULL, &lpType, (LPBYTE)szTemp, &lpcbData);
		if (lRetVal == ERROR_SUCCESS)
		{
			bRetVal = TRUE;
			strValueData = szTemp;
		}
		RegCloseKey(hSubKey);
	}

	return bRetVal;
}

BOOL RegGetValueData(HKEY hkey, const CString& subKey, const CString& valueName, CString& valueData)
{
	HKEY hSubKey = NULL;
	BOOL bRetVal = FALSE;
	LONG lRetVal = ERROR_SUCCESS;
	WCHAR szTemp[4096] = { 0 };

	valueData = "";
	lRetVal = RegOpenKeyEx(hkey, subKey, 0, KEY_READ, &hSubKey);
	if (lRetVal == ERROR_SUCCESS)
	{
		DWORD lpType = REG_SZ;
		DWORD lpcbData = 4096;

		lRetVal = RegQueryValueEx(hSubKey, valueName, NULL, &lpType, (LPBYTE)szTemp, &lpcbData);
		if (lRetVal == ERROR_SUCCESS)
		{
			bRetVal = TRUE;
			valueData = szTemp;
		}
		RegCloseKey(hSubKey);
	}

	return bRetVal;
}

BOOL RegGetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, DWORD& dwValue)
{
	HKEY hSubKey = NULL;
	BOOL bRetVal = FALSE;
	LONG lRetVal = ERROR_SUCCESS;

	dwValue = 0;
	lRetVal = RegOpenKeyExA(hkey, pszSubKey, 0, KEY_READ, &hSubKey);
	if (lRetVal == ERROR_SUCCESS)
	{
		DWORD lpType = REG_DWORD;
		DWORD lpcbData = sizeof(DWORD);
		DWORD	dwTemp = 0;

		lRetVal = RegQueryValueExA(hSubKey, pszValueName, NULL, &lpType, (LPBYTE)&dwTemp, &lpcbData);
		if (lRetVal == ERROR_SUCCESS)
		{
			dwValue = dwTemp;
			bRetVal = TRUE;
		}
		RegCloseKey(hSubKey);
	}
	return bRetVal;
}


BOOL RegSetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, string strValueData)
{
	HKEY		hKey = NULL;
	LONG		lRetVal = ERROR_SUCCESS;
	BOOL		bRetVal = FALSE;

	do
	{
		lRetVal = RegOpenKeyExA(HKEY_LOCAL_MACHINE, pszSubKey, 0, KEY_WRITE, &hKey);
		if (ERROR_SUCCESS != lRetVal)
		{
			break;
		}
		bRetVal = RegSetValueExA(hKey, pszValueName, 0, REG_SZ, (LPBYTE)strValueData.c_str(), strValueData.length());
		if (ERROR_SUCCESS != lRetVal)
		{
			break;
		}
		bRetVal = TRUE;
	} while (0);

	if (NULL != hKey)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return (bRetVal);
}

BOOL RegSetValueData(HKEY hkey, const CString& subKey, const CString& valueName, CString valueData)
{
	HKEY		hKey = NULL;
	LONG		lRetVal = ERROR_SUCCESS;
	BOOL		bRetVal = FALSE;

	do
	{
		lRetVal = RegOpenKeyEx(hkey, subKey, 0, KEY_WRITE, &hKey);
		if (ERROR_SUCCESS != lRetVal)
		{
			//如果不能打开需要创建
			DWORD dw;
			lRetVal = RegCreateKeyEx(hkey, subKey, 0, REG_NONE, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &dw);
			if (ERROR_SUCCESS != lRetVal)
			{
				break;
			}
		}
		bRetVal = RegSetValueEx(hKey, valueName, 0, REG_SZ, (LPBYTE)valueData.GetBuffer(), valueData.GetLength() * sizeof(TCHAR));
		if (ERROR_SUCCESS != lRetVal)
		{
			break;
		}
		bRetVal = TRUE;
	} while (0);

	if (NULL != hKey)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return (bRetVal);
}

BOOL RegSetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, DWORD dwValue)
{
	HKEY		hKey = NULL;
	LONG		lRetVal = ERROR_SUCCESS;
	BOOL		bRetVal = FALSE;

	do
	{
		lRetVal = RegOpenKeyExA(HKEY_LOCAL_MACHINE, pszSubKey, 0, KEY_WRITE, &hKey);
		if (ERROR_SUCCESS != lRetVal)
		{
			break;
		}
		bRetVal = RegSetValueExA(hKey, pszValueName, 0, REG_DWORD, (LPBYTE)dwValue, sizeof(DWORD));
		if (ERROR_SUCCESS != lRetVal)
		{
			break;
		}
		bRetVal = TRUE;
	} while (0);

	if (NULL != hKey)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return (bRetVal);
}

BOOL RegGetValueData(LPCWSTR fullPath, wstring& data)
{
	BOOL ret = FALSE;
	vector<wstring> regVecPath;
	StrSplit(fullPath, L"\\", regVecPath);

	HKEY hKey = HKEY_CLASSES_ROOT;
	if (regVecPath[0] == L"HKEY_CLASSES_ROOT")
	{
		hKey = HKEY_CLASSES_ROOT;
	}
	else if (regVecPath[0] == L"HKEY_CURRENT_USER")
	{
		hKey = HKEY_CURRENT_USER;
	}
	else if (regVecPath[0] == L"HKEY_LOCAL_MACHINE")
	{
		hKey = HKEY_LOCAL_MACHINE;
	}
	else if (regVecPath[0] == L"HKEY_USERS")
	{
		hKey = HKEY_USERS;
	}
	else if (regVecPath[0] == L"HKEY_CURRENT_CONFIG")
	{
		hKey = HKEY_CURRENT_CONFIG;
	}
	else if (regVecPath[0] == L"HKEY_DYN_DATA")
	{
		hKey = HKEY_DYN_DATA;
	}
	else if (regVecPath[0] == L"HKEY_CURRENT_USER_LOCAL_SETTINGS")
	{
		hKey = HKEY_CURRENT_USER_LOCAL_SETTINGS;
	}

	wstring subKey;
	int size = regVecPath.size();
	for (int i = 1; i != size - 1; ++i)
	{
		subKey += regVecPath[i];
		subKey += L"\\";
	}

	HKEY hResultKey;
	if (ERROR_SUCCESS == RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &hResultKey))
	{
		WCHAR buf[1024] = { 0 };
		DWORD bufSize = 1024 * sizeof(WCHAR);
		DWORD dataType;
		if (ERROR_SUCCESS == RegQueryValueEx(hResultKey, regVecPath[size - 1].c_str(), NULL, &dataType, (LPBYTE)buf, &bufSize))
		{
			data = buf;
			ret = TRUE;
		}

		RegCloseKey(hResultKey);
	}

	return ret;
}

BOOL RegGetValueData(LPCWSTR fullPath, DWORD& data)
{
	BOOL ret = FALSE;
	vector<wstring> regVecPath;
	StrSplit(fullPath, L"\\", regVecPath);

	HKEY hKey = HKEY_CLASSES_ROOT;
	if (regVecPath[0] == L"HKEY_CLASSES_ROOT")
	{
		hKey = HKEY_CLASSES_ROOT;
	}
	else if (regVecPath[0] == L"HKEY_CURRENT_USER")
	{
		hKey = HKEY_CURRENT_USER;
	}
	else if (regVecPath[0] == L"HKEY_LOCAL_MACHINE")
	{
		hKey = HKEY_LOCAL_MACHINE;
	}
	else if (regVecPath[0] == L"HKEY_USERS")
	{
		hKey = HKEY_USERS;
	}
	else if (regVecPath[0] == L"HKEY_CURRENT_CONFIG")
	{
		hKey = HKEY_CURRENT_CONFIG;
	}
	else if (regVecPath[0] == L"HKEY_DYN_DATA")
	{
		hKey = HKEY_DYN_DATA;
	}
	else if (regVecPath[0] == L"HKEY_CURRENT_USER_LOCAL_SETTINGS")
	{
		hKey = HKEY_CURRENT_USER_LOCAL_SETTINGS;
	}

	wstring subKey;
	int size = regVecPath.size();
	for (int i = 1; i != size - 1; ++i)
	{
		subKey += regVecPath[i];
		subKey += L"\\";
	}

	HKEY hResultKey;
	if (ERROR_SUCCESS == RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &hResultKey))
	{
		DWORD bufSize = sizeof(DWORD);
		DWORD dataType;
		if (ERROR_SUCCESS == RegQueryValueEx(hResultKey, regVecPath[size - 1].c_str(), NULL, &dataType, (LPBYTE)&data, &bufSize))
		{
			ret = TRUE;
		}

		RegCloseKey(hResultKey);
	}

	return ret;
}


bool IsInteger(double f64Value)
{
	double f64Fraction, f64Integer;
	f64Fraction = modf(f64Value, &f64Integer);
	return f64Fraction == 0;
}

bool IsNum(CString strNum)
{
	int length = strNum.GetLength();
	if (0 == length)
	{
		return false;
	}

	bool ret = TRUE;
	for (int i = 0; i < length; i++)
	{
		char c = strNum.GetAt(i);
		if (!isdigit(c) && ('.' != c))
		{
			ret = FALSE;
			break;
		}
	}

	return ret;
}

int Double2Int(double f64Value)
{
	long s32Value;
	VarI4FromR8(f64Value, &s32Value);
	return s32Value;
}

UINT Double2UInt(double f64Value)
{
	ULONG u32Value;
	VarUI4FromR8(f64Value, &u32Value);
	return u32Value;
}

UINT64 Double2UInt64(double f64Value)
{
	ULONG64 u64Value;
	VarUI8FromR8(f64Value, &u64Value);
	return u64Value;
}

CString Int2CStr(const int& num)
{
	CString str;
	str.Format(L"%d", num);
	return str.Trim();
}

CString ULong2CStr(const ULONG& num)
{
	CString str;
	str.Format(L"%u", num);
	return str.Trim();
}

CString Float2CStr(const float& num)
{
	CString str;
	str.Format(L"%.3f", num);
	return str.Trim();
}

CString Double2CStr(const double& num)
{
	CString str;
	str.Format(L"%.8lf", num);
	return str.Trim();
}

CStringA Int2CStrA(const int& num)
{
	CStringA str;
	str.Format("%d", num);
	return str.Trim();
}

CStringA ULong2CStrA(const ULONG& num)
{
	CStringA str;
	str.Format("%u", num);
	return str.Trim();
}

CStringA Float2CStrA(const float& num)
{
	CStringA str;
	str.Format("%.3f", num);
	return str.Trim();
}

CStringA Double2CStrA(const double& num)
{
	CStringA str;
	str.Format("%.8lf", num);
	return str.Trim();
}

UINT CStr2UINT(const CString& str)
{
	char* ptr = nullptr;
	return strtoul(CStringA(str), nullptr, 10);
}

float CStr2Float(const CString& str)
{
	return strtof(CStringA(str), nullptr);
}

double CStr2Double(const CString& str)
{
	double num = 0;

	CString tmp(str);
	wistringstream iss(tmp.GetBuffer());
	iss >> num;
	tmp.ReleaseBuffer();

	return num;
}

double Str2Double(const string& str)
{
	double num = 0;

	istringstream iss(str);
	iss >> num;

	return num;
}

double Str2Double(const wstring& str)
{
	double num = 0;

	wistringstream iss(str);
	iss >> num;

	return num;
}

long Convert2Timestamp(const COleDateTime& datetime)
{
	SYSTEMTIME systime;
	datetime.GetAsSystemTime(systime);
	CTime tm(systime);
	return tm.GetTime();
}

long Convert2Timestamp(const CString& datetime)
{
	COleVariant vtime(datetime);
	vtime.ChangeType(VT_DATE);
	COleDateTime oleTime(vtime);
	return Convert2Timestamp(oleTime);
}

long Convert2Timestamp(const SYSTEMTIME& datetime)
{
	CString strTime;
	strTime.Format(_T("%d-%d-%d %02d:%02d:%02d"), datetime.wYear, datetime.wMonth, datetime.wDay, datetime.wHour, datetime.wMinute, datetime.wSecond);
	return Convert2Timestamp(strTime);
}

CString Convert2Datetime(long timestamp)
{
	COleDateTime oleTime(timestamp);
	return oleTime.Format(L"%Y-%m-%d %H:%M:%S");
}

CString Convert2Datetime(const SYSTEMTIME& datetime)
{
	CString strTime;
	strTime.Format(_T("%d-%d-%d %02d:%02d:%02d"), datetime.wYear, datetime.wMonth, datetime.wDay, datetime.wHour, datetime.wMinute, datetime.wSecond);
	return strTime;
}

CString Convert2Date(const SYSTEMTIME& datetime)
{
	CString strTime;
	strTime.Format(_T("%d-%d-%d"), datetime.wYear, datetime.wMonth, datetime.wDay);
	return strTime;
}

CTime Convert2CTime(const CString& strDateTime)
{
	WCHAR buf[MAX_PATH];
	wcscpy_s(buf, strDateTime);
	int Y, M, D, h, m, s;
	CTime today;
	swscanf_s(buf, L"%d-%d-%d %d:%d:%d", &Y, &M, &D, &h, &m, &s);

	return CTime(Y, M, D, h, m, s);
}

int Hex2Dec(CStringA strHex)
{
	int dec = 0;
	sscanf_s(strHex, "%x", &dec);
	return dec;
}

UINT Hex2UDec(CStringA strHex)
{
	UINT dec = 0;
	sscanf_s(strHex, "%x", &dec);
	return dec;
}

// WS2S、S2WS
#include <comutil.h>  
#pragma comment(lib, "comsuppw.lib")
string WS2S(const wstring& ws)
{
	_bstr_t t = ws.c_str();
	return (char*)t;
}

wstring S2WS(const string& s)
{
	_bstr_t t = s.c_str();
	return (wchar_t*)t;
}
/************************************************/

// UTF8与多字节(MultiByte)互转
CStringA UTF8AndMB_Convert(const CStringA &strSource, UINT nSourceCodePage, UINT nTargetCodePage)
{
	int nSourceLen = strSource.GetLength();
	int nWideBufLen = MultiByteToWideChar(nSourceCodePage, 0, strSource, -1, NULL, 0);

	wchar_t* pWideBuf = new wchar_t[nWideBufLen + 1];
	memset(pWideBuf, 0, (nWideBufLen + 1) * sizeof(wchar_t));

	MultiByteToWideChar(nSourceCodePage, 0, strSource, -1, (LPWSTR)pWideBuf, nWideBufLen);

	char* pMultiBuf = NULL;
	int nMiltiBufLen = WideCharToMultiByte(nTargetCodePage, 0, (LPWSTR)pWideBuf, -1, (char *)pMultiBuf, 0, NULL, NULL);

	pMultiBuf = new char[nMiltiBufLen + 1];
	memset(pMultiBuf, 0, nMiltiBufLen + 1);

	WideCharToMultiByte(nTargetCodePage, 0, (LPWSTR)pWideBuf, -1, (char *)pMultiBuf, nMiltiBufLen, NULL, NULL);

	CStringA strTarget(pMultiBuf);

	delete[] pWideBuf;
	delete[] pMultiBuf;

	return strTarget;
}

CStringA UTF8ToMB(const CStringA& utf8Str)
{
	if (IsTextUTF8(utf8Str, utf8Str.GetLength()))
	{
		return UTF8AndMB_Convert(utf8Str, CP_UTF8, CP_ACP);
	}

	return utf8Str;
}

CStringA MBToUTF8(const CStringA& MBStr)
{
	return UTF8AndMB_Convert(MBStr, CP_ACP, CP_UTF8);
}

CStringA UnicodeToUTF8(const CStringW& unicodeStr)
{
	char* pMultiBuf = NULL;
	int nMiltiBufLen = WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, pMultiBuf, 0, NULL, NULL);

	pMultiBuf = new char[nMiltiBufLen + 1];
	memset(pMultiBuf, 0, nMiltiBufLen + 1);

	WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, (char *)pMultiBuf, nMiltiBufLen, NULL, NULL);

	CStringA strTarget(pMultiBuf);
	delete[] pMultiBuf;

	return strTarget;
}

CStringW UTF8ToUnicode(const CStringA& utf8Str)
{
	UINT codepage = CP_UTF8;
	if (!IsTextUTF8(utf8Str, utf8Str.GetLength()))
	{
		codepage = CP_ACP;
	}

	int nSourceLen = utf8Str.GetLength();
	int nWideBufLen = MultiByteToWideChar(codepage, 0, utf8Str, -1, NULL, 0);

	wchar_t* pWideBuf = new wchar_t[nWideBufLen + 1];
	memset(pWideBuf, 0, (nWideBufLen + 1) * sizeof(wchar_t));

	MultiByteToWideChar(codepage, 0, utf8Str, -1, (LPWSTR)pWideBuf, nWideBufLen);

	CStringW strTarget(pWideBuf);
	delete[] pWideBuf;

	return strTarget;
}

CStringW MBToUnicode(const char* MBStr)
{
	CStringW strTarget;
	int len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, MBStr, -1, NULL, 0);
	if (len == 0)
	{
		return strTarget;
	}

	wchar_t* buffer = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, MBStr, -1, buffer, len);
	strTarget = buffer;
	delete[] buffer;
	return strTarget;
}

CStringA UnicodeToMB(const wchar_t* unicodeStr)
{
	CStringA strTarget;
	int len = WideCharToMultiByte(CP_ACP, 0, unicodeStr, -1, NULL, 0, NULL, NULL);
	if (len == 0)
	{
		return strTarget;
	}

	char *buffer = new char[len + 1];
	WideCharToMultiByte(CP_ACP, 0, unicodeStr, -1, buffer, len, NULL, NULL);
	buffer[len] = '\0';
	strTarget = buffer;
	delete[] buffer;
	return strTarget;
}


bool IsTextUTF8(const char* str, ULONGLONG length)
{
	DWORD nBytes = 0;//UFT8可用1-6个字节编码,ASCII用一个字节
	UCHAR chr;
	bool bAllAscii = true; //如果全部都是ASCII, 说明不是UTF-8
	for (int i = 0; i < length; i++)
	{
		chr = *(str + i);
		if ((chr & 0x80) != 0) // 判断是否ASCII编码,如果不是,说明有可能是UTF-8,ASCII用7位编码,但用一个字节存,最高位标记为0,o0xxxxxxx
			bAllAscii = false;
		if (nBytes == 0) //如果不是ASCII码,应该是多字节符,计算字节数
		{
			if (chr >= 0x80)
			{
				if (chr >= 0xFC && chr <= 0xFD)
					nBytes = 6;
				else if (chr >= 0xF8)
					nBytes = 5;
				else if (chr >= 0xF0)
					nBytes = 4;
				else if (chr >= 0xE0)
					nBytes = 3;
				else if (chr >= 0xC0)
					nBytes = 2;
				else
				{
					return false;
				}
				nBytes--;
			}
		}
		else //多字节符的非首字节,应为 10xxxxxx
		{
			if ((chr & 0xC0) != 0x80)
			{
				return false;
			}
			nBytes--;
		}
	}

	if (nBytes > 0) //违返规则
	{
		return false;
	}

	if (bAllAscii) //如果全部都是ASCII, 说明不是UTF-8
	{
		return false;
	}

	return true;
}


void StrSplit(WCHAR* pString, WCHAR* pDelim, vector<wstring>& vec)
{
	wstring	strNode = L"";
	WCHAR*	pTemp = NULL;
	WCHAR*	p = NULL;

	if (!pString)
	{
		return;
	}
	vec.clear();

	pTemp = wcstok_s(pString, pDelim, &p);
	while (pTemp != NULL)
	{
		strNode = pTemp;
		vec.emplace_back(strNode);
		pTemp = wcstok_s(NULL, pDelim, &p);
	}
}

void StrSplit(CString str, const CString& delim, vector<CString>& vec)
{
	if (str.IsEmpty() || delim.IsEmpty())
	{
		return;
	}
	vec.clear();

	CString	strNode = L"";
	WCHAR*	pTemp = NULL;
	WCHAR*	p = NULL;

	pTemp = wcstok_s(str.GetBuffer(), delim, &p);
	str.ReleaseBuffer();
	while (pTemp != NULL)
	{
		strNode = pTemp;
		vec.emplace_back(strNode);
		pTemp = wcstok_s(NULL, delim, &p);
	}
}

void StrSplit(CStringA str, const CStringA& delim, vector<CStringA>& vec)
{
	if (str.IsEmpty() || delim.IsEmpty())
	{
		return;
	}
	vec.clear();

	CStringA strNode = "";
	char*	pTemp = NULL;
	char*	p = NULL;

	pTemp = strtok_s(str.GetBuffer(), delim, &p);
	str.ReleaseBuffer();
	while (pTemp != NULL)
	{
		strNode = pTemp;
		vec.emplace_back(strNode);
		pTemp = strtok_s(NULL, delim, &p);
	}
}

void StrSplit(const std::string& inStr, const std::string& delimiter, std::vector<std::string>& outStrs)
{
	outStrs.clear();
	std::string::size_type lastPos = inStr.find_first_not_of(delimiter, 0);
	std::string::size_type pos = inStr.find_first_of(delimiter, lastPos);
	while (std::string::npos != pos || std::string::npos != lastPos)
	{
		outStrs.emplace_back(inStr.substr(lastPos, pos - lastPos));
		lastPos = inStr.find_first_not_of(delimiter, pos);
		pos = inStr.find_first_of(delimiter, lastPos);
	}
}

void StrSplit(const std::wstring& inStr, const std::wstring& delimiter, std::vector<std::wstring>& outStrs)
{
	outStrs.clear();
	std::wstring::size_type lastPos = inStr.find_first_not_of(delimiter, 0);
	std::wstring::size_type pos = inStr.find_first_of(delimiter, lastPos);
	while (std::wstring::npos != pos || std::wstring::npos != lastPos)
	{
		outStrs.emplace_back(inStr.substr(lastPos, pos - lastPos));
		lastPos = inStr.find_first_not_of(delimiter, pos);
		pos = inStr.find_first_of(delimiter, lastPos);
	}
}

BOOL IsWin64()
{
	BOOL bIsWinw64 = FALSE;
	SYSTEM_INFO info;
	GetNativeSystemInfo(&info);
	if (PROCESSOR_ARCHITECTURE_AMD64 == info.wProcessorArchitecture || PROCESSOR_ARCHITECTURE_IA64 == info.wProcessorArchitecture)
	{
		bIsWinw64 = TRUE;
	}
	else
	{
		bIsWinw64 = FALSE;
	}
	return bIsWinw64;
}

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	UINT  num = 0;          // number of image encoders
	UINT  size = 0;         // size of the image encoder array in bytes
	ImageCodecInfo* pImageCodecInfo = NULL;
	GetImageEncodersSize(&num, &size);
	if (size == 0)
		return -1;  // Failure
	pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
	if (pImageCodecInfo == NULL)
		return -1;  // Failure
	GetImageEncoders(num, size, pImageCodecInfo);
	for (UINT j = 0; j < num; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;  // Success
		}
	}

	free(pImageCodecInfo);
	return -1;  // Failure
}

string CombinePath(const string& folder, const string& extraPath)
{
	char buf[MAX_PATH];
	strcpy_s(buf, folder.size() + 1, folder.c_str());
	PathAppendA(buf, extraPath.c_str());
	return buf;
}

wstring CombinePath(const wstring& folder, const wstring& extraPath)
{
	wchar_t buf[MAX_PATH];
	wcscpy_s(buf, folder.c_str());
	PathAppend(buf, extraPath.c_str());
	return buf;
}

CString CombinePath(const CString& folder, const CString& extraPath)
{
	WCHAR buf[MAX_PATH] = { 0 };
	wcscpy_s(buf, folder);
	PathAppend(buf, extraPath);
	return buf;
}

#pragma comment(lib, "Version.lib")
CString GetFileVersion(const CString& strFilePath)
{
	CString strAppVersion;
	DWORD u32RessourceVersionInfoSize;
	DWORD u32JustAJunkVariabel;
	char* ps8VersionInfoPtr;
	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *pstTranslationPtr(nullptr);
	wchar_t* ps16InformationPtr;
	UINT  u32VersionInfoSize;
	wchar_t  as16VersionValue[255];

	u32RessourceVersionInfoSize = GetFileVersionInfoSize(strFilePath, &u32JustAJunkVariabel);
	if (0 != u32RessourceVersionInfoSize)
	{
		ps8VersionInfoPtr = new char[u32RessourceVersionInfoSize];
		if (GetFileVersionInfo(strFilePath, 0, u32RessourceVersionInfoSize, ps8VersionInfoPtr))
		{
			if (!VerQueryValue(
				ps8VersionInfoPtr,
				TEXT("VarFileInfo\\Translation"),
				(LPVOID*)&pstTranslationPtr,
				&u32VersionInfoSize))
			{
				delete[] ps8VersionInfoPtr;
				return strAppVersion;
			}
		}

		StringCchPrintf(as16VersionValue,
			255,
			L"\\StringFileInfo\\%04x%04x\\FileVersion",
			pstTranslationPtr[0].wLanguage,
			pstTranslationPtr[0].wCodePage);

		if (!VerQueryValue(
			ps8VersionInfoPtr,
			as16VersionValue,
			(LPVOID*)&ps16InformationPtr,
			&u32VersionInfoSize))
		{
			delete[] ps8VersionInfoPtr;
			return strAppVersion;
		}

		if (wcslen(ps16InformationPtr) > 0)
		{
			strAppVersion = CString(ps16InformationPtr);
		}
		delete[] ps8VersionInfoPtr;
	}
	return strAppVersion;
}

int CompareVersion(const CString& versionA, const CString& versionB)
{
	vector<CString> vecAVersion, vecBVersion;
	StrSplit(versionA, L".", vecAVersion);
	StrSplit(versionB, L".", vecBVersion);

	// 对比，以较短的为基准
	int ret = 0;
	const int vecAVersionSize = vecAVersion.size();
	const int vecBVersionSize = vecBVersion.size();
	int size = vecAVersionSize < vecBVersionSize ? vecAVersionSize : vecBVersionSize;
	for (int i = 0; i < size; ++i)
	{
		if (CStr2UINT(vecAVersion[i]) != CStr2UINT(vecBVersion[i]))
		{
			if (CStr2UINT(vecAVersion[i]) > CStr2UINT(vecBVersion[i]))
			{
				ret = 1;
				break;
			}
			else if (CStr2UINT(vecAVersion[i]) < CStr2UINT(vecBVersion[i]))
			{
				ret = -1;
				break;
			}
		}
	}

	if ((ret == 0) && (vecAVersion.size() != vecBVersion.size()))
	{
		// 如果前面的版本号相同，则认为较长的版本号更大
		ret = vecAVersionSize < vecBVersionSize ? -1 : 1;
	}

	return ret;
}

CString GetFileDirectory(const CString& path)
{
	WCHAR buffer[MAX_PATH];
	wcscpy_s(buffer, path);
	PathRemoveFileSpecW(buffer);
	return buffer;
}

CString GetLongPath(const CString& path)
{
	WCHAR buf[MAX_PATH] = { 0 };
	if (PathFileExists(path))
	{
		GetLongPathName(path, buf, MAX_PATH);
	}
	return buf;
}

CString PathGetDir(const CString& path)
{
	CString tmpPath(path);
	wchar_t* buffer = tmpPath.GetBuffer();
	PathRemoveFileSpec(buffer);
	tmpPath.ReleaseBuffer();

	return tmpPath;
}

CString PathGetExt(const CString& path)
{
	return PathFindExtension(path);
}

CString PathRemoveExt(const CString& path)
{
	CString tmpPath(path);
	wchar_t* buffer = tmpPath.GetBuffer();
	PathRemoveExtension(buffer);
	tmpPath.ReleaseBuffer();

	return tmpPath;
}

CString PathRenameExt(const CString& path, const CString& newExt)
{
	CString tmpPath(path);
	wchar_t* buffer = tmpPath.GetBuffer();
	PathRenameExtension(buffer, newExt);
	tmpPath.ReleaseBuffer();

	return tmpPath;
}

BOOL SHDeleteFolder(LPCTSTR pstrFolder, BOOL bAllowUndo)
{
	int iPathLen = _tcslen(pstrFolder);
	if (iPathLen >= MAX_PATH || iPathLen == 0)
	{
		return FALSE;
	}

	/*确保目录的路径以2个\0结尾*/
	TCHAR tczFolder[MAX_PATH + 1];
	ZeroMemory(tczFolder, (MAX_PATH + 1) * sizeof(TCHAR));
	wcscpy_s(tczFolder, pstrFolder);
	tczFolder[iPathLen] = _T('\0');
	tczFolder[iPathLen + 1] = _T('\0');

	SHFILEOPSTRUCT FileOp;
	ZeroMemory(&FileOp, sizeof(SHFILEOPSTRUCT));
	FileOp.fFlags |= FOF_SILENT;        /*不显示进度*/
	FileOp.fFlags |= FOF_NOERRORUI;        /*不报告错误信息*/
	FileOp.fFlags |= FOF_NOCONFIRMATION;/*直接删除，不进行确认*/
	FileOp.hNameMappings = NULL;
	FileOp.hwnd = NULL;
	FileOp.lpszProgressTitle = NULL;
	FileOp.wFunc = FO_DELETE;
	FileOp.pFrom = tczFolder;            /*要删除的目录，必须以2个\0结尾*/
	FileOp.pTo = NULL;

	/*根据传递的bAllowUndo参数确定是否删除到回收站*/
	if (bAllowUndo)
	{
		FileOp.fFlags |= FOF_ALLOWUNDO; /*删除到回收站*/
	}
	else
	{
		FileOp.fFlags &= ~FOF_ALLOWUNDO; /*直接删除，不放入回收站*/
	}

	/*删除目录*/
	if (0 == SHFileOperation(&FileOp))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

void FindAllFiles(vector<CString>& filePathList, CString rootFolder)
{
	CFileFind finder;
	BOOL isNotEmpty = finder.FindFile(rootFolder + _T("*.*")); // 总文件夹，开始遍历
	while (isNotEmpty)
	{
		isNotEmpty = finder.FindNextFile(); // 查找文件 
		CString filename = finder.GetFilePath(); // 获取文件的路径，可能是文件夹，可能是文件
		if (!(finder.IsDirectory()))
		{
			// 如果是文件则加入文件列表
			filePathList.emplace_back(filename);
		}
		else
		{
			// 递归遍历用户文件夹，跳过非用户文件夹
			if (!(finder.IsDots() || finder.IsHidden() || finder.IsSystem() || finder.IsTemporary() || finder.IsReadOnly()))
			{
				FindAllFiles(filePathList, filename + _T("/"));
			}
		}
	}
}

std::string GetFileString(string path)
{
	ifstream in(path);
	istreambuf_iterator<char> beg(in), end;
	string str(beg, end);
	return str;
}

#include <tlhelp32.h>
BOOL GetProcessIdByName(LPCWSTR lpProcName, LPDWORD lpPid)
{
	HANDLE	hProcSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32	ProcEntry = { 0 };
	BOOL	bRtn = FALSE;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap)
	{
		return FALSE;
	}

	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcSnap, &ProcEntry))
	{
		CloseHandle(hProcSnap);
		return FALSE;
	}

	do
	{
		if (0 == _wcsicmp(ProcEntry.szExeFile, lpProcName))
		{
			*lpPid = ProcEntry.th32ProcessID;
			bRtn = TRUE;
			break;
		}
	} while (Process32Next(hProcSnap, &ProcEntry));

	CloseHandle(hProcSnap);
	return bRtn;
}

BOOL KillProcessFromName(CString strProcessName)
{
	//创建进程快照(TH32CS_SNAPPROCESS表示创建所有进程的快照)  
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//PROCESSENTRY32进程快照的结构体  
	PROCESSENTRY32 pe;

	//实例化后使用Process32First获取第一个快照的进程前必做的初始化操作  
	pe.dwSize = sizeof(PROCESSENTRY32);


	//下面的IF效果同:  
	//if(hProcessSnap == INVALID_HANDLE_VALUE)   无效的句柄  
	if (!Process32First(hSnapShot, &pe))
	{
		return FALSE;
	}

	//将字符串转换为小写  
	strProcessName.MakeLower();

	//如果句柄有效  则一直获取下一个句柄循环下去  
	while (Process32Next(hSnapShot, &pe))
	{

		//pe.szExeFile获取当前进程的可执行文件名称  
		CString scTmp = pe.szExeFile;


		//将可执行文件名称所有英文字母修改为小写  
		scTmp.MakeLower();

		//比较当前进程的可执行文件名称和传递进来的文件名称是否相同  
		//相同的话Compare返回0  
		if (!scTmp.Compare(strProcessName))
		{

			//从快照进程中获取该进程的PID(即任务管理器中的PID)  
			DWORD dwProcessID = pe.th32ProcessID;
			HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
			::TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
			return TRUE;
		}
		scTmp.ReleaseBuffer();
	}
	strProcessName.ReleaseBuffer();
	return FALSE;
}

BOOL IsProcessRunning(CString strProcessName)
{
	BOOL isFind = FALSE;
	//创建进程快照(TH32CS_SNAPPROCESS表示创建所有进程的快照)  
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//PROCESSENTRY32进程快照的结构体  
	PROCESSENTRY32 pe;

	//实例化后使用Process32First获取第一个快照的进程前必做的初始化操作  
	pe.dwSize = sizeof(PROCESSENTRY32);

	//下面的IF效果同:  
	//if(hProcessSnap == INVALID_HANDLE_VALUE)   无效的句柄  
	if (!Process32First(hSnapShot, &pe))
	{
		return FALSE;
	}

	//将字符串转换为小写  
	strProcessName.MakeLower();

	//如果句柄有效  则一直获取下一个句柄循环下去  
	while (Process32Next(hSnapShot, &pe))
	{
		//pe.szExeFile获取当前进程的可执行文件名称  
		CString scTmp = pe.szExeFile;

		//将可执行文件名称所有英文字母修改为小写  
		scTmp.MakeLower();

		//比较当前进程的可执行文件名称和传递进来的文件名称是否相同  
		//相同的话Compare返回0  
		if (!scTmp.Compare(strProcessName))
		{
			isFind = TRUE;
			break;
		}
	}

	return isFind;
}

#include <sddl.h>
BOOL CreateDACL(SECURITY_ATTRIBUTES* pSA)
{
	if (NULL == pSA)
	{
		return FALSE;
	}

	// Define the SDDL for the DACL. This example sets 
	// the following access:
	//     Built-in guests are denied all access.
	//     Anonymous logon is denied all access.
	//     Authenticated users are allowed full control access.
	//     Administrators are allowed full control.
	// Modify these values as needed to generate the proper
	// DACL for your application. 
	const TCHAR * szSD = TEXT("D:")       // Discretionary ACL
		TEXT("(D;OICI;GA;;;BG)")    // Deny access to 
									// built-in guests
		TEXT("(D;OICI;GA;;;AN)")    // Deny access to 
									// anonymous logon
		TEXT("(A;OICI;GA;;;AU)")	// Allow full control
									// to authenticated 
									// users
		TEXT("(A;OICI;GA;;;BA)");   // Allow full control 
									// to administrators

	return ConvertStringSecurityDescriptorToSecurityDescriptor(szSD, SDDL_REVISION_1, &(pSA->lpSecurityDescriptor), NULL);
}

static BOOL GetProcessElevation(TOKEN_ELEVATION_TYPE* pElevationType)
{
	HANDLE hToken = NULL;

	DWORD dwSize;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	if (GetTokenInformation(hToken, TokenElevationType, pElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize))
	{
		return TRUE;
	}

	return FALSE;
}

bool IsHasUAC()
{
	TOKEN_ELEVATION_TYPE type;
	if (GetProcessElevation(&type))	// 检测是否管理员权限运行
	{
		if (TokenElevationTypeLimited == type)
		{
			return false;
		}
		else
		{
			return true;
		}
	}

	return false;
}

BOOL EnabledDebugPrivilege()
{
	HANDLE	hToken = NULL;
	LUID	luid = { 0 };
	BOOL	bRtn = FALSE;
	DWORD	dwError = 0;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (hToken)
	{
		TOKEN_PRIVILEGES	tkp = { 0 };

		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = luid;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		bRtn = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
		CloseHandle(hToken);
	}
	else
	{
		dwError = GetLastError();
	}

	return bRtn;
}

BOOL GetProcessToken(LPCWSTR lpProceName, LPHANDLE hToken)
{
	DWORD	dwProcId = 0;
	HANDLE	hProcess = NULL;
	BOOL	bRtn = FALSE;

	*hToken = NULL;

	if (FALSE == GetProcessIdByName(lpProceName, &dwProcId))
	{
		return FALSE;
	}
	// 提升权限
	EnabledDebugPrivilege();
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcId);
	if (NULL != hProcess)
	{
		bRtn = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken);
		CloseHandle(hProcess);
	}
	return bRtn;
}

BOOL RunProcess(LPCWSTR lpImagePath, LPWSTR lpArgs, BOOL bWait, BOOL bHiden)
{
	HANDLE	hToken = NULL;
	HANDLE	hDupToken = NULL;
	DWORD	dwSessionId = 0;
	DWORD	dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	PROCESS_INFORMATION ProcInfo = { 0 };
	STARTUPINFO StartInfo = { 0 };
	LPVOID	lpEnv = NULL;
	BOOL	bResult = FALSE;

	// 获取到winlogon.exe的令牌可能多个winlogon进程,session不为0（这里可能需要做下循环判断session是否为当前活动的session,暂时不判断）
	// TODO 目前暂时不判断当前的winlogon是否是活动桌面进程，************************需要判断************************？？？？？
	if (FALSE == GetProcessToken(L"winlogon.exe", &hToken))
	{
		return FALSE;
	}
	//  且是系统进程有足够权限了
	if (FALSE == DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
	{
		CloseHandle(hToken);
		return FALSE;
	}
#if 0
	// 上面没有判断是否是当前的活动session，这里直接设置为当前活动session即可
	dwSessionId = WTSGetActiveConsoleSessionId();
	DWORD	dwError = 0;
	// 提升权限
	EnabledDebugPrivilege();
	if (FALSE == SetTokenInformation(hDupToken, TokenSessionId, (void*)dwSessionId, sizeof(DWORD)))
	{
		dwError = GetLastError();
		CloseHandle(hDupToken);
		CloseHandle(hToken);
		return FALSE;
	}
#endif
	StartInfo.cb = sizeof(STARTUPINFO);
	TCHAR desktop[128] = { 0 };
	wsprintf(desktop, L"winsta0\\default");
	StartInfo.lpDesktop = desktop;

	if (bHiden)
	{
		dwCreationFlags |= CREATE_NO_WINDOW;
	}

	DWORD	dwError = 0;
	bResult = CreateProcessAsUser(
		hDupToken,            // client's access token
		lpImagePath,		// file to execute
		lpArgs,				// command line
		NULL,				// pointer to process SECURITY_ATTRIBUTES
		NULL,				// pointer to thread SECURITY_ATTRIBUTES
		FALSE,				// handles are not inheritable
		dwCreationFlags,	// creation flags
		NULL,              // pointer to new environment block 
		NULL,              // name of current directory 
		&StartInfo,        // pointer to STARTUPINFO structure
		&ProcInfo          // receives information about new process
	);
	if (bResult && bWait)
	{
		WaitForSingleObject(ProcInfo.hProcess, INFINITE);
	}
	else if (!bResult)
	{
		dwError = GetLastError();
	}

	CloseHandle(hDupToken);
	CloseHandle(hToken);

	return bResult;
}

wstring GenerateGUID()
{
	wstring str;
	try
	{
		GUID guid;
		CoCreateGuid(&guid);

		wchar_t strTmp[22] = { 0 };
		wsprintf(strTmp, L"%08x%04x%04x%02x%02x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1]);
		str = strTmp;
	}
	catch (...)
	{
		ASSERT(0);
	}

	return str;
}

CString GetModuleDir()
{
	WCHAR buf[MAX_PATH];
	GetModuleFileName(NULL, buf, MAX_PATH * sizeof(WCHAR));

	GetLongPathName(buf, buf, MAX_PATH * sizeof(WCHAR));
	PathRemoveFileSpec(buf);
	return buf;
}

CString GetModuleDir(const CString& moduleName)
{
	if (moduleName.IsEmpty())
	{
		return GetModuleDir();
	}

	WCHAR buf[MAX_PATH] = { 0 };
	HMODULE hMod = GetModuleHandle(moduleName);
	if (hMod != NULL)
	{
		GetModuleFileName(hMod, buf, MAX_PATH * sizeof(WCHAR));
	}

	if (wcslen(buf) > 0)
	{
		GetLongPathName(buf, buf, MAX_PATH * sizeof(WCHAR));
		PathRemoveFileSpec(buf);
	}
	return buf;
}

CString GetCPU_ID()
{
#ifdef _WIN64
	return WMI_GetCPU_ID();
#else
	return ASM_GetCPU_ID();
#endif // _WIN64
}

#ifndef _WIN64
CString ASM_GetCPU_ID()
{
	UINT uCpuID = 0U;
	BYTE szCpu[16] = { 0 };
	_asm
	{
		mov eax, 0
		cpuid
		mov dword ptr szCpu[0], ebx
		mov dword ptr szCpu[4], edx
		mov dword ptr szCpu[8], ecx
		mov eax, 1
		cpuid
		mov uCpuID, edx
	}

	CString str;
	str.Format(L"%u", uCpuID);
	return str;
}
#endif // _WIN64

#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
CString WMI_GetCPU_ID()
{
	CString CPU_ID;
	HRESULT hres;

	//初始化 COM.
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		return CPU_ID;              // Program has failed.
	}

	// 设置进程安全级别
	hres = CoInitializeSecurity(
		NULL,
		-1,      // COM negotiates service                 
		NULL,    // Authentication services
		NULL,    // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
		RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
		NULL,             // Authentication info
		EOAC_NONE,        // Additional capabilities
		NULL              // Reserved
	);
	if (FAILED(hres))
	{
		CoUninitialize();
		return CPU_ID;          // Program has failed.
	}

	//创建一个CLSID_WbemLocator对象
	IWbemLocator *pLoc = 0;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)&pLoc);
	if (FAILED(hres))
	{
		CoUninitialize();
		return CPU_ID;       // Program has failed.
	}

	IWbemServices *pSvc = 0;
	//使用pLoc连接到” root\cimv2” 并把pSvc的指针也搞定了
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // WMI namespace
		NULL,                    // User name
		NULL,                    // User password
		0,                       // Locale
		NULL,                    // Security flags                
		0,                       // Authority      
		0,                       // Context object
		&pSvc                    // IWbemServices proxy
	);

	if (FAILED(hres))
	{
		pLoc->Release();
		CoUninitialize();
		return CPU_ID;                // Program has failed.
	}

	hres = CoSetProxyBlanket(
		pSvc,                         // the proxy to set
		RPC_C_AUTHN_WINNT,            // authentication service
		RPC_C_AUTHZ_NONE,             // authorization service
		NULL,                         // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,       // authentication level
		RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
		NULL,                         // client identity
		EOAC_NONE                     // proxy capabilities    
	);
	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return CPU_ID;               // Program has failed.
	}

	/*
	这里就要引入WQL这个概念了。WQL就是WMI中的查询语言，WQL的全称是WMI Query Language，简称为WQL，翻译成中文好像可以成为Windows管理规范查询语言。熟悉SQL语言的朋友会感觉它和SQL非常相似。
	1、每个WQL语句必须以SELECT开始；
	2、SELECT后跟你需要查询的属性名（我刚才对应SQL将其称之为字段名了），也可以像SQL一样，以*表示返回所有属性值；
	3、FROM关键字；
	4、你要查询的类的名字；
	*/

	//为了接收结果，你必须定义一个枚举对象
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return CPU_ID;               // Program has failed.
	}
	else
	{
		IWbemClassObject *pclsObj = nullptr;
		ULONG uReturn = 0;
		while (pEnumerator)
		{
			hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
			if (0 == uReturn)
			{
				break;
			}

			VARIANT vtProp;
			// 获取属性值
			hres = pclsObj->Get(L"ProcessorId", 0, &vtProp, 0, 0);
			CPU_ID = vtProp;

			VariantClear(&vtProp);
		}
	}

	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return CPU_ID;
}

CString IpToStr(DWORD dIP)
{
	// IP to String
	CString strIP = _T("");
	WORD add1, add2, add3, add4;

	add1 = (WORD)(dIP & 255);
	add2 = (WORD)((dIP >> 8) & 255);
	add3 = (WORD)((dIP >> 16) & 255);
	add4 = (WORD)((dIP >> 24) & 255);
	strIP.Format(_T("%d.%d.%d.%d"), add4, add3, add2, add1);
	return strIP;
}

CString CExceptionWhat(CException* e)
{
	CString strLog;
	e->GetErrorMessage(strLog.GetBuffer(MAX_PATH), MAX_PATH);
	strLog.ReleaseBuffer();
	e->Delete();

	return strLog;
}

CString EncryptString(const CString& str)
{
	// 干扰码
	const CString disturbStr = L"123456789ABC";
	const int disturbLength = disturbStr.GetLength();

	// 获取CPU序列号
	CString cpuID = GetCPU_ID();
	ASSERT(!cpuID.IsEmpty());

	int length = str.GetLength();
	CString tmpStr;
	WCHAR* buf = tmpStr.GetBuffer(length);
	for (int i = 0; i != length; ++i)
	{
		int snNum = i % (cpuID.GetLength() - 1);
		int disturbNum = i % disturbLength;
		buf[i] = str[i] + cpuID[snNum] + disturbStr[disturbNum];
	}
	tmpStr.ReleaseBuffer();

	// 转码双字母
	CString endStr, tmpStr2, tmpNumStr1, tmpNumStr2;
	length = tmpStr.GetLength();
	int tmpNum = 0;
	for (int i = 0; i != length; ++i)
	{
		tmpNum = tmpStr[i];
		tmpStr2.Format(L"%-4d", tmpNum);
		tmpNumStr1.Format(L"%c%c", tmpStr2[0], tmpStr2[1]);
		tmpNumStr2.Format(L"%c%c", tmpStr2[2], tmpStr2[3]);
		tmpStr2.Format(L"%c%c", 65 + _wtoi(tmpNumStr1), 65 + _wtoi(tmpNumStr2));

		endStr += tmpStr2;
	}

	return endStr;
}

CString DecryptString(const CString& str)
{
	// 解码双字母
	CString endStr, tmpStr2, tmpNumStr1, tmpNumStr2;
	int length = str.GetLength();
	int tmpNum = 0;
	for (int i = 0; i != length; i += 2)
	{
		tmpStr2.Format(L"%d%d", str[i] - 65, str[i + 1] - 65);
		tmpNum = _wtoi(tmpStr2);
		tmpStr2.Format(L"%c", tmpNum);

		endStr += tmpStr2;
	}

	// 干扰码
	const CString disturbStr = L"123456789ABC";
	const int disturbLength = disturbStr.GetLength();

	// 获取CPU序列号
	CString cpuID = GetCPU_ID();
	ASSERT(!cpuID.IsEmpty());

	length = endStr.GetLength();
	CString tmpStr;
	WCHAR* buf = tmpStr.GetBuffer(length);
	for (int i = 0; i != length; ++i)
	{
		int snNum = i % (cpuID.GetLength() - 1);
		int disturbNum = i % disturbLength;
		buf[i] = endStr[i] - cpuID[snNum] - disturbStr[disturbNum];
	}
	tmpStr.ReleaseBuffer();

	return tmpStr;
}