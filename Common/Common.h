#pragma once
#include <afx.h>
#include <string>
#include <ws2tcpip.h>

using std::string;
using std::wstring;
using std::string_view;

wstring UTF8ToUnicode(const char* utf8Str);
wstring MBToUnicode(const char* MBStr);
wstring S2Unicode(const char* str);
wstring S2Unicode(const string& str);
bool IsUTF8(const char* str, size_t length);
string UnicodeToUTF8(const CStringW& unicodeStr);
string UnicodeToMB(const CStringW& unicodeStr);

void ConvertIPPort(const SOCKADDR_IN& addr, string& ip, int& port); // 网络字节顺序转本地字节顺序
bool ConvertIPPort(const string& ip, int port, SOCKADDR_IN& addr);	// 本地字节顺序转网络字节顺序
void ConvertIPPort(DWORD ip, int port, SOCKADDR_IN& addr);	// 本地字节顺序转网络字节顺序
void ConvertIPLocal2Local(const ULONG lIP, string& strIP);// 本地字节顺序转本地字节顺序string

CString GetModuleDir();
CString CombinePath(const CString& folder, const CString& extraPath);

string Int2Str(const int& num);

string Base64Encode(const char* bytes, unsigned int len);

std::string CurentDirectory(); // 获取当前exe目录 D:/abc
std::string ConcatPathFileName(const std::string& path, const std::string& filename); // 路径拼接文件名（自动增加分隔符为"/"）
std::string StripFileName(const std::string& filepath); // 去除路径的最后一个成员 "D:/abc/d.pdf" => "D:/abc"

void debug(string_view utf8Log);
void info(string_view utf8Log);
void warn(string_view utf8Log);
void error(string_view utf8Log);