﻿#include "Common.h"
#include "spdlog/spdlog.h"
#include "sutfcpplib/utf_string.h"
#include <stringapiset.h>
#include <Shlwapi.h>
#include <memory>
#include <filesystem>

using namespace std;

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

wstring UTF8ToUnicode(const char* utf8Str)
{
	int nWideBufLen = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, NULL, 0);

	wchar_t* pWideBuf = new wchar_t[nWideBufLen + 1];
	memset(pWideBuf, 0, (nWideBufLen + 1) * sizeof(wchar_t));

	MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, (LPWSTR)pWideBuf, nWideBufLen);

	wstring strTarget(pWideBuf);
	delete[] pWideBuf;

	return strTarget;
}

wstring MBToUnicode(const char* MBStr)
{
	int nWideBufLen = MultiByteToWideChar(CP_ACP, 0, MBStr, -1, NULL, 0);

	wchar_t* pWideBuf = new wchar_t[nWideBufLen + 1];
	memset(pWideBuf, 0, (nWideBufLen + 1) * sizeof(wchar_t));

	MultiByteToWideChar(CP_ACP, 0, MBStr, -1, (LPWSTR)pWideBuf, nWideBufLen);

	wstring strTarget(pWideBuf);
	delete[] pWideBuf;

	return strTarget;
}

wstring S2Unicode(const char* str)
{
	if (IsUTF8(str, strlen(str)))
	{
		return UTF8ToUnicode(str);
	}
	else
	{
		return MBToUnicode(str);
	}
}

wstring S2Unicode(const string& str)
{
	const char* tmpStr = str.c_str();
	if (IsUTF8(tmpStr, strlen(tmpStr)))
	{
		return UTF8ToUnicode(tmpStr);
	}
	else
	{
		return MBToUnicode(tmpStr);
	}
}

string UnicodeToUTF8(const CStringW& unicodeStr)
{
	char* pMultiBuf = NULL;
	int nMiltiBufLen = WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, pMultiBuf, 0, NULL, NULL);

	pMultiBuf = new char[nMiltiBufLen + 1];
	memset(pMultiBuf, 0, nMiltiBufLen + 1);

	WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, (char*)pMultiBuf, nMiltiBufLen, NULL, NULL);

	string strTarget(pMultiBuf);
	delete[] pMultiBuf;

	return strTarget;
}

string UnicodeToMB(const CStringW& unicodeStr)
{
	int len = WideCharToMultiByte(CP_ACP, 0, unicodeStr, -1, NULL, 0, NULL, NULL);
	if (len == 0)
	{
		return "";
	}

	char* buffer = new char[len + 1];
	memset(buffer, 0, len + 1);

	WideCharToMultiByte(CP_ACP, 0, unicodeStr, -1, (char*)buffer, len, NULL, NULL);

	string strTarget(buffer);
	delete[] buffer;

	return strTarget;
}

bool IsUTF8(const char* str, size_t length)
{
	unsigned long nBytes = 0;//UFT8可用1-6个字节编码,ASCII用一个字节
	unsigned char chr;
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


void ConvertIPPort(const SOCKADDR_IN& addr, string& ip, uint16_t& port)
{
	char charBuf[16] = { 0 };
	inet_ntop(AF_INET, &addr.sin_addr, charBuf, 16);
	ip = charBuf;
	port = ntohs(addr.sin_port);
}

bool ConvertIPPort(const string& ip, uint16_t port, SOCKADDR_IN& addr)
{
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	return (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 0);
}

void ConvertIPPort(DWORD ip, uint16_t port, SOCKADDR_IN& addr)
{
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);
}

void ConvertIPLocal2Local(const ULONG lIP, string& strIP)
{
	char charBuf[16] = { 0 };
	sprintf_s(charBuf, "%u.%u.%u.%u",
		(unsigned char)*((char*)&lIP + 3),
		(unsigned char)*((char*)&lIP + 2),
		(unsigned char)*((char*)&lIP + 1),
		(unsigned char)*((char*)&lIP + 0));
	strIP = charBuf;
}

CString GetModuleDir()
{
	WCHAR buf[MAX_PATH];
	GetModuleFileName(NULL, buf, MAX_PATH * sizeof(WCHAR));

	GetLongPathName(buf, buf, MAX_PATH * sizeof(WCHAR));
	PathRemoveFileSpec(buf);
	return buf;
}

CString CombinePath(const CString& folder, const CString& extraPath)
{
	WCHAR buf[MAX_PATH] = { 0 };
	wcscpy_s(buf, folder);
	PathAppend(buf, extraPath);
	return buf;
}

string Int2Str(const int& num)
{
	return str_format("%d", num);
}

CString Int2CStr(const int& num)
{
	CString str;
	str.Format(L"%d", num);
	return str.Trim();
}

static const CStringA base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

string Base64Encode(const char* bytes, unsigned int len)
{
	string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (len--) {
		char_array_3[i++] = *(bytes++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;
}

std::string CurentDirectory()
{
	char buffer[260];
	if (_getcwd(buffer, sizeof(buffer)) != nullptr) {
		return buffer;
	}
	return ""; // 获取路径失败
}

static const char kPathSeparatorWindows = '\\';
static const char* PathSeparatorSet = "\\/";  // Intentionally no ':'
static const char kPathSeparator = '/';
std::string ConcatPathFileName(const std::string& path, const std::string& filename)
{
	std::string filepath = path;
	if (filepath.length()) {
		char& filepath_last_character = filepath.back();
		if (filepath_last_character == kPathSeparatorWindows) {
			filepath_last_character = kPathSeparator;
		}
		else if (filepath_last_character != kPathSeparator) {
			filepath += kPathSeparator;
		}
	}
	filepath += filename;
	// Ignore './' at the start of filepath.
	if (filepath[0] == '.' && filepath[1] == kPathSeparator) {
		filepath.erase(0, 2);
	}

	std::replace(filepath.begin(), filepath.end(), '\\', '/'); // PosixPath
	return filepath;
}

std::string StripPath(const std::string& filepath)
{
	size_t i = filepath.find_last_of(PathSeparatorSet);
	return i != std::string::npos ? filepath.substr(i + 1) : filepath;
}

std::string StripFileName(const std::string& filepath)
{
	size_t i = filepath.find_last_of(PathSeparatorSet);
	return i != std::string::npos ? filepath.substr(0, i) : "";
}

void debug(string_view utf8Log)
{
	spdlog::debug(utf8Log);
}

void info(string_view utf8Log)
{
	spdlog::info(utf8Log);
}

void warn(string_view utf8Log)
{
	spdlog::warn(utf8Log);
}

void error(string_view utf8Log)
{
	spdlog::error(utf8Log);
}

size_t getFileSize(const char* filePath)
{
	if (nullptr == filePath)
	{
		return 0;
	}

	struct _stat64i32 statbuf;
#ifdef _WIN32
	std::wstring wsFilePath = UTF8ToUnicode(filePath);
	_wstat(wsFilePath.c_str(), &statbuf);
#else
	_stat(filePath, &statbuf);
#endif
	return statbuf.st_size;
}

void MakeDirRecursively(const char* dirPath)
{
	auto parent = StripFileName(dirPath);
	if (parent.length()) 
	{
		MakeDirRecursively(parent.c_str());
	}

#ifdef _WIN32
	std::wstring wDirPath = UTF8ToUnicode(dirPath);
	(void)_wmkdir(wDirPath.c_str());
#else
	mkdir(dirPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP);
#endif
}
