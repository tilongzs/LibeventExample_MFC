#pragma once
#include <afx.h>
#include <string>
#include <ws2tcpip.h>

using std::string;
using std::wstring;

wstring UTF8ToUnicode(const char* utf8Str);
wstring MBToUnicode(const char* MBStr);
wstring S2Unicode(const char* str);
wstring S2Unicode(const string& str);
bool IsUTF8(const char* str, size_t length);
string UnicodeToUTF8(const CStringW& unicodeStr);

void ConvertIPPort(const SOCKADDR_IN& addr, string& ip, int& port); // 网络字节顺序转本地字节顺序
bool ConvertIPPort(const string& ip, int port, SOCKADDR_IN& addr);	// 本地字节顺序转网络字节顺序
void ConvertIPPort(DWORD ip, int port, SOCKADDR_IN& addr);	// 本地字节顺序转网络字节顺序

CString GetModuleDir();
CString CombinePath(const CString& folder, const CString& extraPath);

string Int2Str(const int& num);