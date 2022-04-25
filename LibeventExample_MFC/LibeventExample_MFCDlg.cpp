#include "pch.h"
#include "framework.h"
#include "LibeventExample_MFC.h"
#include "LibeventExample_MFCDlg.h"
#include "afxdialogex.h"
#include "Common/Common.h"
#include <afxsock.h>

#include<sys/types.h>  
#include<errno.h>  
#include <corecrt_io.h>
#include <thread>

// vcpkg管理
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/keyvalq_struct.h>
#include <event2/http_struct.h>
/*******************************/

using std::async;
using std::thread;
using std::this_thread::get_id;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WMSG_FUNCTION		WM_USER + 1
#define DEFAULT_SOCKET_IP "127.0.0.1"
#define DEFAULT_SOCKET_PORT 23300
#define SINGLE_PACKAGE_SIZE 1024 * 64 // 默认16384
#define SINGLE_UDP_PACKAGE_SIZE 65507 // 单个UDP包的最大大小（理论值：65507字节）

struct EventData
{
	CLibeventExample_MFCDlg* dlg;
	bufferevent* bev;
	ssl_ctx_st* ssl_ctx;
	ssl_st* ssl;
};

CLibeventExample_MFCDlg::CLibeventExample_MFCDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_LibeventExample_MFC_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CLibeventExample_MFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_MSG, _editRecv);
	DDX_Control(pDX, IDC_EDIT_PORT, _editPort);
	DDX_Control(pDX, IDC_EDIT_PORT_REMOTE, _editRemotePort);
	DDX_Control(pDX, IDC_CHECK_SSL, _btnUseSSL);
	DDX_Control(pDX, IDC_BUTTON_HTTP_SERVER, _btnHTTPServer);
	DDX_Control(pDX, IDC_BUTTON_HTTP_SERVER_STOP, _btnStopHttpServer);
}

BEGIN_MESSAGE_MAP(CLibeventExample_MFCDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WMSG_FUNCTION, &CLibeventExample_MFCDlg::OnFunction)
	ON_BN_CLICKED(IDC_BUTTON_DISCONN_CLIENT, &CLibeventExample_MFCDlg::OnBtnDisconnClient)
	ON_BN_CLICKED(IDC_BUTTON_LISTEN, &CLibeventExample_MFCDlg::OnBtnListen)
	ON_BN_CLICKED(IDC_BUTTON_CREATETIMER, &CLibeventExample_MFCDlg::OnBtnCreatetimer)
	ON_BN_CLICKED(IDC_BUTTON_STOP_LISTEN, &CLibeventExample_MFCDlg::OnBtnStopListen)
	ON_BN_CLICKED(IDC_BUTTON_CONNECT, &CLibeventExample_MFCDlg::OnBtnConnect)
	ON_BN_CLICKED(IDC_BUTTON_DISCONNECT_SERVER, &CLibeventExample_MFCDlg::OnBtnDisconnectServer)
	ON_BN_CLICKED(IDC_BUTTON_SEND_MSG, &CLibeventExample_MFCDlg::OnBtnSendMsg)
	ON_BN_CLICKED(IDC_BUTTON_UDP_BIND, &CLibeventExample_MFCDlg::OnBtnUdpBind)
	ON_BN_CLICKED(IDC_BUTTON_UDP_SEND_MSG, &CLibeventExample_MFCDlg::OnBtnUdpSendMsg)
	ON_BN_CLICKED(IDC_BUTTON_UDP_CLOSE, &CLibeventExample_MFCDlg::OnBtnUdpClose)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_SERVER, &CLibeventExample_MFCDlg::OnBtnHttpServer)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_SERVER_STOP, &CLibeventExample_MFCDlg::OnBtnStopHttpServer)
END_MESSAGE_MAP()

BOOL CLibeventExample_MFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	_editPort.SetWindowText(L"23300");
	_editRemotePort.SetWindowText(L"23300");

	_btnStopHttpServer.EnableWindow(FALSE);

	AppendMsg(L"启动");
	
	AfxSocketInit();

	return TRUE; 
}

void CLibeventExample_MFCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CLibeventExample_MFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CLibeventExample_MFCDlg::AppendMsg(const WCHAR* msg)
{
	WCHAR* tmpMsg = new WCHAR[wcslen(msg) + 1];
	memset(tmpMsg, 0, sizeof(WCHAR) * (wcslen(msg) + 1));
	wsprintf(tmpMsg, msg);

	TheadFunc* pFunc = new TheadFunc;
	pFunc->Func = ([=]()
		{
			if (_editRecv.GetLineCount() > 100)
			{
				_editRecv.Clear();
			}

			CString curMsg;
			_editRecv.GetWindowTextW(curMsg);
			curMsg += "\r\n";

			CString strTime;
			SYSTEMTIME   tSysTime;
			GetLocalTime(&tSysTime);
			strTime.Format(L"%02ld:%02ld:%02ld.%03ld ",
				tSysTime.wHour, tSysTime.wMinute, tSysTime.wSecond, tSysTime.wMilliseconds);

			curMsg += strTime;
			curMsg += tmpMsg;
			_editRecv.SetWindowTextW(curMsg);
			_editRecv.LineScroll(_editRecv.GetLineCount());

			delete[] tmpMsg;
		});

	PostMessage(WMSG_FUNCTION, (WPARAM)pFunc);
}

bool CLibeventExample_MFCDlg::IsUseSSL()
{
	return _btnUseSSL.GetCheck();
}

LRESULT CLibeventExample_MFCDlg::OnFunction(WPARAM wParam, LPARAM lParam)
{
	TheadFunc* pFunc = (TheadFunc*)wParam;
	pFunc->Func();
	delete pFunc;

	return TRUE;
}

void CLibeventExample_MFCDlg::OnBtnCreatetimer()
{
	InitTimer();
}

void OnEventTimer(evutil_socket_t fd, short event, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;
	dlg->AppendMsg(L"定时器");
}

void CLibeventExample_MFCDlg::InitTimer()
{
	event_base* eventBase = event_base_new();
	
	//ev = evtimer_new(_eventBase, DoTimer, NULL);
	event* ev = event_new(eventBase, -1, EV_ET/*一次性*/, OnEventTimer, this);
	if (ev) {
		timeval timeout = { 2, 0 };
// 		timeout.tv_sec = 2;
// 		timeout.tv_usec = 0;
		event_add(ev, &timeout);

		thread([&, eventBase, ev]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"定时器 结束");

			event_free(ev);
			event_base_free(eventBase);			
		}).detach();
	}
}

void CLibeventExample_MFCDlg::OnBtnDisconnClient()
{
	if (_currentEventData)
	{
		evutil_socket_t fd = bufferevent_getfd(_currentEventData->bev);
		if (_currentEventData->ssl)
		{
			SSL_shutdown(_currentEventData->ssl);
			_currentEventData->ssl = nullptr;
		}

		closesocket(fd);
		bufferevent_setfd(_currentEventData->bev, -1);
		//bufferevent_replacefd(_currentBufferevent, -1);// libevent 2.2.0
		bufferevent_free(_currentEventData->bev);
	}
}

static void OnServerWrite(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;

	eventData->dlg->AppendMsg(L"OnServerWrite");
}

static void OnServerRead(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;

	evbuffer* input = bufferevent_get_input(bev);
	size_t sz = evbuffer_get_length(input);
	if (sz > 0)
	{
		char* buffer = new char[sz]{0};
		bufferevent_read(bev, buffer, sz);

		CString tmpStr;
		tmpStr.Format(L"threadID:%d 收到%u字节", get_id(), sz);
		eventData->dlg->AppendMsg(tmpStr);		

		delete[] buffer;
	}
}

static void OnServerEvent(bufferevent* bev, short events, void* param)
{
	EventData* eventData = (EventData*)param;

	if (events & BEV_EVENT_EOF) 
	{
		eventData->dlg->AppendMsg(L"BEV_EVENT_EOF 连接关闭");
		if (eventData->ssl)
		{
			SSL_shutdown(eventData->ssl);
		}
		bufferevent_free(bev);
	}
	else if (events & BEV_EVENT_ERROR)
	{
		CString tmpStr;
		if (events & BEV_EVENT_READING)
		{
			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_READING错误errno:%d", errno);
		}
		else if (events & BEV_EVENT_WRITING)
		{
			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_WRITING错误errno:%d", errno);
		}
	
		eventData->dlg->AppendMsg(tmpStr);
		bufferevent_free(bev);
	}
}

static void OnServerEventAccept(evconnlistener* listener, evutil_socket_t fd, sockaddr* sa, int socklen, void* param)
{
	EventData* eventData = (EventData*)param;
	event_base* eventBase = evconnlistener_get_base(listener);

	int bufLen = SINGLE_PACKAGE_SIZE;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int));
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int));

	//构造一个bufferevent
	bufferevent* bev = nullptr;
	if (eventData->dlg->IsUseSSL())
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		eventData->ssl = SSL_new(eventData->ssl_ctx);
		SSL_set_fd(eventData->ssl, fd);
		bev = bufferevent_openssl_socket_new(eventBase, fd, eventData->ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	}
	else
	{
		bev = bufferevent_socket_new(eventBase, fd, BEV_OPT_CLOSE_ON_FREE);
	}

	if (!bev) 
	{
		eventData->dlg->AppendMsg(L"bufferevent_socket_new失败");
		event_base_loopbreak(eventBase);
		return;
	}
	eventData->bev = bev;

	// 修改读写上限
	int ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		eventData->dlg->AppendMsg(L"bufferevent_set_max_single_read失败");
	}
	ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		eventData->dlg->AppendMsg(L"bufferevent_set_max_single_write失败");
	}

	//绑定读事件回调函数、写事件回调函数、错误事件回调函数
	bufferevent_setcb(bev, OnServerRead, OnServerWrite, OnServerEvent, eventData);

	bufferevent_enable(bev, EV_READ | EV_WRITE);

	string remoteIP;
	int remotePort;
	ConvertIPPort(*(sockaddr_in*)sa, remoteIP, remotePort);
	CString tmpStr;
	tmpStr.Format(L"threadID:%d 新客户端%s:%d 连接", get_id(), S2Unicode(remoteIP).c_str(), remotePort);
	eventData->dlg->AppendMsg(tmpStr);
}

void CLibeventExample_MFCDlg::OnBtnListen()
{
	event_config* cfg = event_config_new();
	evthread_use_windows_threads();
	event_config_set_num_cpus_hint(cfg, 8);
	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);

	event_base* eventBase = event_base_new_with_config(cfg);
	if (!eventBase)
	{
		event_config_free(cfg);
		AppendMsg(L"创建eventBase失败");
		return;
	}
	event_config_free(cfg);
	cfg = nullptr;

	//创建、绑定、监听socket
	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);

	sockaddr_in localAddr = {0};
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(port);

	EventData* eventData = new EventData;
	eventData->dlg = this;

	if (IsUseSSL())
	{
		CString exeDir = GetModuleDir();
		CString serverCrtPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.crt");
		CString serverKeyPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.key");

		// 引入之前生成好的私钥文件和证书文件
		ssl_ctx_st* ssl_ctx = SSL_CTX_new(TLS_server_method());
		if (!ssl_ctx)
		{
			AppendMsg(L"ssl_ctx new failed");
			return;
		}
		int res = SSL_CTX_use_certificate_file(ssl_ctx, UnicodeToUTF8(serverCrtPath), SSL_FILETYPE_PEM);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_use_certificate_file failed");
			return;
		}
		res = SSL_CTX_use_PrivateKey_file(ssl_ctx, UnicodeToUTF8(serverKeyPath), SSL_FILETYPE_PEM);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_use_PrivateKey_file failed");
			return;
		}
		res = SSL_CTX_check_private_key(ssl_ctx);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_check_private_key failed");
			return;
		}

		eventData->ssl_ctx = ssl_ctx;
	}

	_listener = evconnlistener_new_bind(eventBase, OnServerEventAccept, eventData,
		LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
		(sockaddr*)&localAddr, sizeof(localAddr));
	if (!_listener)
	{
		AppendMsg(L"创建evconnlistener失败");
				
		event_base_free(eventBase);
		if (IsUseSSL())
		{
			SSL_CTX_free(eventData->ssl_ctx);
		}

		delete eventData;
		return;
	}
	_currentEventData = eventData;

	thread([&, eventBase]
	{
		event_base_dispatch(eventBase); // 阻塞
		AppendMsg(L"服务端socket event_base_dispatch线程 结束");
	
		evconnlistener_free(_listener);
		event_base_free(eventBase);
		if (IsUseSSL())
		{
			SSL_CTX_free(_currentEventData->ssl_ctx);
		}
		delete _currentEventData;
		_currentEventData = nullptr;
	}).detach();

	AppendMsg(L"服务端开始监听");
}

void CLibeventExample_MFCDlg::OnBtnStopListen()
{
	if (_listener)
	{
		evconnlistener_disable(_listener);
	}
}

static void OnClientWrite(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;

	eventData->dlg->AppendMsg(L"OnClientWrite");
}

static void OnClientRead(bufferevent* bev, void* param)
{
	EventData* eventData = (EventData*)param;

	evbuffer* input = bufferevent_get_input(bev);
	size_t sz = evbuffer_get_length(input);
	if (sz > 0)
	{
		char* buffer = new char[sz] {0};
		bufferevent_read(bev, buffer, sz);

		CString tmpStr;
		tmpStr.Format(L"threadID:%d 收到%u字节", get_id(), sz);
		eventData->dlg->AppendMsg(tmpStr);

		delete[] buffer;
	}
}

static void OnClientEvent(bufferevent* bev, short events, void* param)
{
	EventData* eventData = (EventData*)param;

	if (events & BEV_EVENT_CONNECTED)
	{
		eventData->dlg->AppendMsg(L"连接服务端成功");
	}
	else if (events & BEV_EVENT_EOF) 
	{
		eventData->dlg->AppendMsg(L"BEV_EVENT_EOF 连接关闭");
		bufferevent_free(bev);
	}
	else if (events & BEV_EVENT_ERROR)
	{
		CString tmpStr;
		if (events & BEV_EVENT_READING)
		{
			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_READING错误errno:%d", errno);
		}
		else if (events & BEV_EVENT_WRITING)
		{
			tmpStr.Format(L"BEV_EVENT_ERROR BEV_EVENT_WRITING错误errno:%d", errno);
		}
		eventData->dlg->AppendMsg(tmpStr);
		bufferevent_free(bev);
	}
}

void CLibeventExample_MFCDlg::OnBtnConnect()
{
	event_config* cfg = event_config_new();
	evthread_use_windows_threads();
	event_config_set_num_cpus_hint(cfg, 8);
	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);

	event_base* eventBase = event_base_new_with_config(cfg);
	if (!eventBase)
	{
		AppendMsg(L"创建eventBase失败");
		return;
	}
	event_config_free(cfg);
	cfg = nullptr;

	// 使用指定的本地IP、端口
	CString tmpStr;
// 	_editPort.GetWindowText(tmpStr);
// 	const int localPort = _wtoi(tmpStr);
// 
// 	sockaddr_in localAddr = { 0 };
// 	if (!ConvertIPPort(DEFAULT_SOCKET_IP, localPort, localAddr))
// 	{
// 		AppendMsg(L"IP地址无效");
// 	}
// 
// 	evutil_socket_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
// 	if (bind(sockfd, (sockaddr*)&localAddr, sizeof(localAddr)))
// 	{
// 		AppendMsg(L"TCP绑定失败");
// 		return;
// 	}
// 	bufferevent* bev = bufferevent_socket_new(eventBase, sockfd, BEV_OPT_CLOSE_ON_FREE);
	/************************************************************/

	EventData* eventData = new EventData;
	eventData->dlg = this;

	bufferevent* bev = nullptr;
	if (IsUseSSL())
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		eventData->ssl_ctx = SSL_CTX_new(TLS_client_method());
		eventData->ssl = SSL_new(eventData->ssl_ctx);
		bev = bufferevent_openssl_socket_new(eventBase, -1, eventData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
	}
	else
	{
		bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_CLOSE_ON_FREE);
	}

	if (bev == NULL)
	{
		AppendMsg(L"bufferevent_socket_new失败");
		event_base_free(eventBase);
		if (eventData->ssl_ctx)
		{
			SSL_CTX_free(eventData->ssl_ctx);
		}

		delete eventData;
		return;
	}
	eventData->bev = bev;
	_currentEventData = eventData;
	
	bufferevent_setcb(bev, OnClientRead, OnClientWrite, OnClientEvent, eventData);

	//连接服务端	
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	sockaddr_in serverAddr = { 0 };
	if (!ConvertIPPort(DEFAULT_SOCKET_IP, remotePort, serverAddr))
	{
		AppendMsg(L"IP地址无效");
	}

	int flag = bufferevent_socket_connect(bev, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (-1 == flag)
	{
		AppendMsg(L"连接服务端失败");
		bufferevent_free(bev);
		event_base_free(eventBase);
		return;
	}

	// 修改读写上限
	int bufLen = SINGLE_PACKAGE_SIZE;
	evutil_socket_t fd = bufferevent_getfd(bev);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int));
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int));
	int ret = bufferevent_set_max_single_read(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		AppendMsg(L"bufferevent_set_max_single_read失败");
	}
	ret = bufferevent_set_max_single_write(bev, SINGLE_PACKAGE_SIZE);
	if (ret != 0)
	{
		AppendMsg(L"bufferevent_set_max_single_write失败");
	}

	bufferevent_enable(bev, EV_READ | EV_WRITE);

	thread([&, eventBase]
	{
		event_base_dispatch(eventBase); // 阻塞
		AppendMsg(L"客户端socket event_base_dispatch线程 结束");

		event_base_free(eventBase);
		if (IsUseSSL())
		{
			SSL_CTX_free(_currentEventData->ssl_ctx);
		}
		delete _currentEventData;
		_currentEventData = nullptr;
	}).detach();
}

void CLibeventExample_MFCDlg::OnBtnDisconnectServer()
{
	if (_currentEventData)
	{
		if (_currentEventData->ssl)
		{
			SSL_shutdown(_currentEventData->ssl);
			_currentEventData->ssl = nullptr;
		}

		evutil_socket_t fd = bufferevent_getfd(_currentEventData->bev);
		closesocket(fd);
		bufferevent_setfd(_currentEventData->bev, -1);
		//bufferevent_replacefd(_currentEventData->bev, -1); // libevent 2.2.0
	}
}

void CLibeventExample_MFCDlg::OnBtnSendMsg()
{
	thread([&] {
		if (_currentEventData)
		{
	// 		char* msg = new char[]("hello libevent");
	// 		int len = strlen(msg);

			const int len = 1024 * 1024;
			char* msg = new char[len]{0};

			int ret = bufferevent_write(_currentEventData->bev, msg, len);
			if (ret != 0)
			{
				AppendMsg(L"发送数据失败");
			}

			delete[] msg;
		}
	}).detach();	
}

static void OnUDPRead(evutil_socket_t sockfd, short events, void* param)
{
	EventData* eventData = (EventData*)param;

	if (events & EV_READ)
	{
		struct sockaddr_in addr;
		socklen_t addLen = sizeof(addr);
		char* buffer = new char[SINGLE_UDP_PACKAGE_SIZE] {0};

		int recvLen = recvfrom(sockfd, buffer, SINGLE_UDP_PACKAGE_SIZE, 0, (sockaddr*)&addr, &addLen);
		if (recvLen == -1)
		{
			eventData->dlg->AppendMsg(L"recvfrom 失败");
		}
		else
		{
			string remoteIP;
			int remotePort;
			ConvertIPPort(addr, remoteIP, remotePort);

			CString tmpStr;
			tmpStr.Format(L"threadID:%d 收到来自%s:%d %u字节", get_id(), S2Unicode(remoteIP).c_str(), remotePort, recvLen);
			eventData->dlg->AppendMsg(tmpStr);
		}

		delete[] buffer;
	}
}

void CLibeventExample_MFCDlg::OnBtnUdpBind()
{
	event_base* eventBase = event_base_new();
	if (!eventBase)
	{
		AppendMsg(L"创建eventBase失败");
		return;
	}

	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);

	sockaddr_in localAddr = { 0 };	
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(port);

	_currentSockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (bind(_currentSockfd, (sockaddr*)&localAddr, sizeof(localAddr)))
	{
		AppendMsg(L"UDP绑定失败");
		return;
	}

	EventData* eventData = new EventData;
	eventData->dlg = this;

	_currentEvent = event_new(NULL, -1, 0, NULL, NULL);
	int ret = event_assign(_currentEvent, eventBase, _currentSockfd, EV_READ | EV_PERSIST, OnUDPRead, (void*)eventData);
	if (ret != 0)
	{
		AppendMsg(L"event_assign失败");
		event_free(_currentEvent);
		event_base_free(eventBase);
		return;
	}
	event_add(_currentEvent, nullptr);

	thread([&, eventBase, eventData]
	{
		event_base_dispatch(eventBase); // 阻塞
		AppendMsg(L"UDP线程 结束");

		event_free(_currentEvent);
		_currentEvent = nullptr;
		_currentSockfd = -1;
		event_base_free(eventBase);
		delete eventData;
	}).detach();

	AppendMsg(L"UDP启动成功");
}

void CLibeventExample_MFCDlg::OnBtnUdpSendMsg()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	sockaddr_in remoteAddr = { 0 };
	if (!ConvertIPPort(DEFAULT_SOCKET_IP, remotePort, remoteAddr))
	{
		AppendMsg(L"IP地址无效");
	}

	if (_currentSockfd != -1)
	{
		const int len = SINGLE_UDP_PACKAGE_SIZE;
		char* msg = new char[len] {0};
		int sendLen = sendto(_currentSockfd, msg, len, 0, (sockaddr*)&remoteAddr, sizeof(sockaddr_in));
		if (sendLen == -1) 
		{
			AppendMsg(L"UDP发送失败");
		}

		delete[] msg;
	}
}

void CLibeventExample_MFCDlg::OnBtnUdpClose()
{
	if (_currentSockfd != -1)
	{
		closesocket(_currentSockfd);
	}
}

static void OnHTTP_API_getA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	// http://127.0.0.1:23300/api/getA?q=test&s=some+thing
	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/getA?q=test&s=some+thing"
	evhttp_uri* decoded = evhttp_uri_parse(uri);// 解码uri
	if (!decoded)
	{
		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
		return;
	}

	const char* path = evhttp_uri_get_path(decoded); // 获取uri中的path部分 "/api/getA"
	if (!path)
	{
		path = "/";
	}

	const char* query = evhttp_uri_get_query(decoded); // 获取uri中的参数部分 "q=test&s=some+thing"
	if (!query)
	{
		evhttp_send_error(req, HTTP_NOCONTENT, NULL);
		return;
	}

	//查询指定参数的值
	evkeyvalq params = { 0 };
	evhttp_parse_query_str(query, &params);
	const char* value = evhttp_find_header(&params, "s"); // "some thing"
	value = evhttp_find_header(&params, "q"); // "test"

	// 回复
	evbuffer_add_printf(req->output_buffer, UnicodeToUTF8(L"感谢Thanks use getA"));
	//evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, HTTP_OK, "OK", nullptr);
}

static void OnHTTP_API_postA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	const char* s = "This is the test buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);
}

static void OnHTTP_API_setA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	const char* s = "This is the test buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);
}

static void OnHTTP_API_delA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	const char* s = "This is the test buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);
}

static void OnHTTPUnmatchedRequest(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	const char* s = "This is the generic buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);
}

void CLibeventExample_MFCDlg::OnBtnHttpServer()
{
	event_config* cfg = event_config_new();
	evthread_use_windows_threads();
	event_config_set_num_cpus_hint(cfg, 8);
	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);

	event_base* eventBase = event_base_new_with_config(cfg);
	if (!eventBase)
	{
		event_config_free(cfg);
		AppendMsg(L"创建eventBase失败");
		return;
	}
	event_config_free(cfg);
	cfg = nullptr;

	_httpServer = evhttp_new(eventBase);
	if (!_httpServer)
	{
		AppendMsg(L"创建http_server失败");

		event_base_free(eventBase);
		return;
	}

	evhttp_set_max_body_size(_httpServer, 1024 * 1024 * 10);
	evhttp_set_max_connections(_httpServer, 10000 * 100);

	_btnHTTPServer.EnableWindow(FALSE);
	_btnStopHttpServer.EnableWindow(TRUE);

	//创建、绑定、监听socket
	CString tmpStr;
	_editPort.GetWindowText(tmpStr);
	const int port = _wtoi(tmpStr);

	sockaddr_in localAddr = { 0 };
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(port);

	EventData* eventData = new EventData;
	eventData->dlg = this;

	if (IsUseSSL())
	{
		CString exeDir = GetModuleDir();
		CString serverCrtPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.crt");
		CString serverKeyPath = CombinePath(exeDir, L"../3rd/OpenSSL/server.key");

		// 引入之前生成好的私钥文件和证书文件
		ssl_ctx_st* ssl_ctx = SSL_CTX_new(TLS_server_method());
		if (!ssl_ctx)
		{
			AppendMsg(L"ssl_ctx new failed");
			return;
		}
		int res = SSL_CTX_use_certificate_file(ssl_ctx, UnicodeToUTF8(serverCrtPath), SSL_FILETYPE_PEM);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_use_certificate_file failed");
			return;
		}
		res = SSL_CTX_use_PrivateKey_file(ssl_ctx, UnicodeToUTF8(serverKeyPath), SSL_FILETYPE_PEM);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_use_PrivateKey_file failed");
			return;
		}
		res = SSL_CTX_check_private_key(ssl_ctx);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_check_private_key failed");
			return;
		}

		eventData->ssl_ctx = ssl_ctx;
	}

	_listener = evconnlistener_new_bind(eventBase, OnServerEventAccept, eventData,
		LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
		(sockaddr*)&localAddr, sizeof(localAddr));
	if (!_listener)
	{
		AppendMsg(L"创建evconnlistener失败");

		event_base_free(eventBase);
		if (IsUseSSL())
		{
			SSL_CTX_free(eventData->ssl_ctx);
		}

		delete eventData;
		return;
	}

	_httpSocket = evhttp_bind_listener(_httpServer, _listener);
	//_httpSocket = evhttp_bind_socket_with_handle(_httpServer, "0.0.0.0", port);
	if (!_httpSocket)
	{
		AppendMsg(L"创建evhttp_bind_socket失败");
		return;
	}

	//设置处理请求的超时时间(s)
	evhttp_set_timeout(_httpServer, 3);

	/*
		URI like http://127.0.0.1:23300/api/getA?q=test&s=some+thing
		The first entry is: key="q", value="test"
		The second entry is: key="s", value="some thing"
	*/		
	evhttp_set_cb(_httpServer, "/api/getA", OnHTTP_API_getA, this);

	evhttp_set_cb(_httpServer, "/api/postA", OnHTTP_API_postA, this);
	evhttp_set_cb(_httpServer, "/api/setA", OnHTTP_API_setA, this);
	evhttp_set_cb(_httpServer, "/api/delA", OnHTTP_API_delA, this);
	evhttp_set_gencb(_httpServer, OnHTTPUnmatchedRequest, this);
		
	AppendMsg(L"HTTP 服务端启动");
	thread([&, eventBase]
	{
		event_base_dispatch(eventBase); // 阻塞
		evhttp_free(_httpServer);
	}).detach();		
}

void CLibeventExample_MFCDlg::OnBtnStopHttpServer()
{
	if (_httpServer && _httpSocket)
	{
		evhttp_del_accept_socket(_httpServer, _httpSocket);

		AppendMsg(L"HTTP 服务端停止");
		_btnHTTPServer.EnableWindow(TRUE);
		_btnStopHttpServer.EnableWindow(FALSE);
	}
}
