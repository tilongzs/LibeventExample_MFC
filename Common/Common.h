#pragma once
#include <afx.h>
#include <ATLComTime.h>
#include <vector>
#include <list>
#include <string>

using std::vector;
using std::string;
using std::wstring;

// 释放句柄宏
#define RELEASE_HANDLE(x)               {if(x != NULL && x!=INVALID_HANDLE_VALUE){ CloseHandle(x);x = NULL;}}
// 释放Socket宏
#define RELEASE_SOCKET(x)               {if(x !=INVALID_SOCKET) { closesocket(x);x=INVALID_SOCKET;}}

// 异常处理类
 #include <vcruntime_exception.h>
 #include <iptypes.h>

// #include <winsock.h>
struct SException
{
	EXCEPTION_RECORD er;
	CONTEXT            context;

	SException(PEXCEPTION_POINTERS pep)
	{
		er = *(pep->ExceptionRecord);
		context = *(pep->ContextRecord);
	}

	operator DWORD() { return er.ExceptionCode; }
	DWORD GetCode() { return er.ExceptionCode; }
	static void MapSEtoCE() { _set_se_translator(TranslateSEToCE); }

	static void __cdecl TranslateSEToCE(UINT dwEC, PEXCEPTION_POINTERS pep)
	{
		throw SException(pep);
	}
};

// 网卡相关
BOOL	EnumTermAdapter(vector<IP_ADAPTER_INFO>& AdapterArray);				// 枚举系统所有的网卡
VOID	GetAdapterDisplayName(char* szAdapterGuid, char* szDisplayName);		// 通过网卡的GUID获取网卡的显示名
BOOL	IsAdapterLogicConnected(char* szAdapterName);							//  通过网卡的GUID获取网卡的逻辑状态
BOOL	IsAdapterPhyConnected(char* szAdapterName);								//  通过网卡的GUID获取网卡的物理状态
BOOL	IsVirtualNetCard(char* szAdapterName);									//  通过网卡的GUID获取是否是虚拟网卡
BOOL	GetActiveAdapterInfo(IP_ADAPTER_INFO& AdapterInfo);						// 获取系统网卡中第一个活动的网卡，物理以及逻辑状态都是连接的
BOOL	GetFirstPhysicAdapterInfo(IP_ADAPTER_INFO& AdapterInfo);			// 获取系统网卡中的第一个物理网卡
BOOL	GetAdapterInfoByGuid(IP_ADAPTER_INFO& AdapterInfo, LPCSTR pAdapterName); // 通过GUID获取网卡对应的信息
VOID	GetAdapterBroadCastAddress(string strIpAddr, string strMaskAddr, string& strBroadCastAddress);	// 获取网卡的广播地址
VOID	GetAdapterMacAddress(IP_ADAPTER_INFO& AdapterData, char* szMacAddress);	// 获取网卡的物理地址
VOID	GetIpAddrSegment(LPCSTR lpIpAddr, LPCSTR lpMaskAddr, LPSTR lpSegment);	// 获取网卡的IP段地址
VOID	GetAdapterRealMac(string strAdapterGuid, string& strAdapterMac);
vector<uint16_t> GetAllTcpConnectionsPort();
vector<uint16_t> GetAllUdpConnectionsPort();
uint16_t GetAvailableTCPPort(uint16_t begin = 49152, uint16_t end = 65535);
uint16_t GetAvailableUDPPort(uint16_t begin = 49152, uint16_t end = 65535);
uint16_t GetAvailablePort(uint16_t begin = 49152, uint16_t end = 65535);
wstring GenerateIP(DWORD dwIP);
bool IsSame(const SOCKADDR_IN& addrA, const SOCKADDR_IN& addrB);
void ConvertIPPort(const SOCKADDR_IN& addr, OUT string& ip, OUT int& port); // 网络字节顺序转本地字节顺序
bool ConvertIPPort(const string& ip, int port, OUT SOCKADDR_IN& addr);	// 本地字节顺序转网络字节顺序
void ConvertIPPort(DWORD ip, int port, OUT SOCKADDR_IN& addr);	// 本地字节顺序转网络字节顺序
wstring GetOuterIP();

// 注册表操作
BOOL	RegGetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, char* szValueData);
BOOL	RegGetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, string& strValueData);
BOOL	RegGetValueData(HKEY hkey, const CString& subKey, const CString& valueName, CString& valueData);
BOOL	RegGetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, DWORD& dwValue);
BOOL	RegSetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, string strValueData);
BOOL	RegSetValueData(HKEY hkey, const CString& subKey, const CString& valueName, CString valueData);
BOOL	RegSetValueData(HKEY hkey, const char* pszSubKey, const char* pszValueName, DWORD dwValue);
BOOL	RegGetValueData(LPCWSTR fullPath, wstring& data);
BOOL	RegGetValueData(LPCWSTR fullPath, DWORD& data);

// 数字转换
bool IsInteger(double f64Value);
bool IsNum(CString strNum);
int Double2Int(double f64Value);
UINT Double2UInt(double f64Value);
UINT64 Double2UInt64(double f64Value);
CString Int2CStr(const int& num);
CString ULong2CStr(const ULONG& num);
CString Float2CStr(const float& num);
CString Double2CStr(const double& num);
CStringA Int2CStrA(const int& num);
CStringA ULong2CStrA(const ULONG& num);
CStringA Float2CStrA(const float& num);
CStringA Double2CStrA(const double& num);
UINT CStr2UINT(const CString& str);
float CStr2Float(const CString& str);
double CStr2Double(const CString& str);
double Str2Double(const string& str);
double Str2Double(const wstring& str);
int Hex2Dec(CStringA strHex); // 16进制转10进制
UINT Hex2UDec(CStringA strHex);

// 时间操作
long Convert2Timestamp(const COleDateTime& datetime);
long Convert2Timestamp(const CString& datetime);
long Convert2Timestamp(const SYSTEMTIME& datetime);
CString Convert2Datetime(long timestamp);	// %d-%d-%d %02d:%02d:%02d
CString Convert2Datetime(const SYSTEMTIME& datetime); // %d-%d-%d %02d:%02d:%02d
CString Convert2Date(const SYSTEMTIME& datetime);  // %d-%d-%d
CTime Convert2CTime(const CString& strDateTime);

// 文字转换
string WS2S(const wstring& ws);
wstring S2WS(const string& s);
CStringA UTF8AndMB_Convert(const CStringA &strSource, UINT nSourceCodePage, UINT nTargetCodePage); // UTF8与多字节(MultiByte)互转
CStringA UTF8ToMB(const CStringA& utf8Str);
CStringA MBToUTF8(const CStringA& MBStr);
CStringA UnicodeToUTF8(const CStringW& unicodeStr);
CStringW UTF8ToUnicode(const CStringA& utf8Str);
CStringW MBToUnicode(const char* MBStr);
CStringA UnicodeToMB(const wchar_t* unicodeStr);
bool IsTextUTF8(const char* str, ULONGLONG length);

// 字符串操作
void StrSplit(WCHAR* pString, WCHAR* pDelim, vector<wstring>& vec);
void StrSplit(CString str, const CString& delim, vector<CString>& vec);
void StrSplit(CStringA str, const CStringA& delim, vector<CStringA>& vec);
void StrSplit(const string& inStr, const string& delimiter, vector<string>& outStrs);
void StrSplit(const wstring& inStr, const wstring& delimiter, vector<wstring>& outStrs);


// 路径操作
CString GetModuleDir();	// 获得主程序所在路径
CString GetModuleDir(const CString& moduleName);// 获得指定程序模块所在路径，例如xxx.dll
string CombinePath(const string& folder, const string& extraPath);
wstring CombinePath(const wstring& folder, const wstring& extraPath);
CString CombinePath(const CString& folder, const CString& extraPath);
CString GetLongPath(const CString& path); // 获取长文件路径名
CString PathGetDir(const CString& path);	// 去除文件名，得到目录
CString PathGetExt(const CString& path);	// 获取文件扩展名
CString PathRemoveExt(const CString& path); // 去除文件路径扩展名
CString PathRenameExt(const CString& path, const CString& newExt);	// 更改文件路径扩展名


// 文件操作
CString GetFileVersion(const CString& strFilePath);
int CompareVersion(const CString& versionA, const CString& versionB); // 对比两个版本号大小（1、0、-1）
CString GetFileDirectory(const CString& path);
BOOL SHDeleteFolder(LPCTSTR pstrFolder, BOOL bAllowUndo);
void FindAllFiles(vector<CString>& filePathList, CString rootFolder);	// 遍历文件夹中的所有文件
string GetFileString(string path); // 将文件转为字符串

// 进程操作
BOOL GetProcessIdByName(LPCWSTR lpProcName, LPDWORD lpPid);
BOOL KillProcessFromName(CString strProcessName);
BOOL IsProcessRunning(CString strProcessName);
BOOL CreateDACL(SECURITY_ATTRIBUTES* pSA);
bool IsHasUAC();//UserAccountControl
BOOL EnabledDebugPrivilege();
BOOL GetProcessToken(LPWSTR lpProceName, LPHANDLE hToken);
BOOL RunProcess(LPCWSTR lpImagePath, LPWSTR lpArgs, BOOL bWait, BOOL bHiden);

// 其他
BOOL IsWin64();
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid); // 图像处理
wstring GenerateGUID(); // 生成20位GUID
CString GetCPU_ID();	// 获取CPU的序列号
#ifndef _WIN64
CString ASM_GetCPU_ID();	// 仅X86可用
#endif
CString WMI_GetCPU_ID();
CString IpToStr(DWORD dIP);// IP to String
CString CExceptionWhat(CException* e);

CString EncryptString(const CString& str);
CString DecryptString(const CString& str);

