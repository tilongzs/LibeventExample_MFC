#include "pch.h"
#include "framework.h"
#include "LibeventExample_MFC.h"
#include "LibeventExample_MFCDlg.h"
#include "Common/Common.h"
#include "Common/libeventWS.h"
#include <afxsock.h>
#include <sys/types.h>  
#include <errno.h>  
#include <corecrt_io.h>
#include <thread>
#include <fcntl.h>
#include <sys/stat.h>

// vcpkg管理
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <wincrypt.h>
/*******************************/

using namespace std;
using namespace chrono;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WMSG_FUNCTION		WM_USER + 1
#define DEFAULT_SOCKET_PORT 23300
#define SINGLE_PACKAGE_SIZE 1024 * 64 // 默认16384
#define SINGLE_UDP_PACKAGE_SIZE 65507 // 单个UDP包的最大大小（理论值：65507字节）
#define URL_MAX 4096

#define HTTP_MAX_HEAD_SIZE 1024 * 4
static const INT64 HTTP_MAX_BODY_SIZE = (INT64)1024 * 1024 * 1024 * 2 - 1024; // 不要超过2GB

class EventData
{
public:
	~EventData()
	{
		if (ssl_ctx)
		{
			SSL_CTX_free(ssl_ctx);
			ssl_ctx = nullptr;
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

		if (dlg)
		{
			dlg->OnEventDataDeleted(this);
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
			}
		}
	}

	CLibeventExample_MFCDlg* dlg = nullptr;
	bufferevent* bev = nullptr;
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;
};

struct HttpData
{
public:
	~HttpData()
	{
		Free();
	}

	void Free()
	{
		_mtx.lock();
		if (evConn)
		{
			evhttp_connection_free(evConn);
			evConn = nullptr;
		}

		if (evURI)
		{
			evhttp_uri_free(evURI);
			evURI = nullptr;
		}

		if (ssl_ctx)
		{
			SSL_CTX_free(ssl_ctx);
			ssl_ctx = nullptr;
		}

		if (ssl)
		{
			SSL_shutdown(ssl);
			ssl = nullptr;
		}

		if (req)
		{
			evhttp_request_free(req);
			req = nullptr;
		}
		_mtx.unlock();
	}

	CLibeventExample_MFCDlg* dlg = nullptr;
	evhttp_connection* evConn = nullptr;
	evhttp_uri* evURI = nullptr;
	evhttp_request* req = nullptr;

	bufferevent* bev = nullptr;
	ssl_ctx_st* ssl_ctx = nullptr;
	ssl_st* ssl = nullptr;

private:
	mutex _mtx;
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
	DDX_Control(pDX, IDC_IPADDRESS_REMOTE, _ipRemote);
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
	ON_BN_CLICKED(IDC_BUTTON_HTTP_GET, &CLibeventExample_MFCDlg::OnBtnHttpGet)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_POST, &CLibeventExample_MFCDlg::OnBtnHttpPost)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_PUT, &CLibeventExample_MFCDlg::OnBtnHttpPut)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_POST_FILE, &CLibeventExample_MFCDlg::OnBtnHttpPostFile)
	ON_BN_CLICKED(IDC_BUTTON_HTTP_DEL, &CLibeventExample_MFCDlg::OnBtnHttpDel)
	ON_BN_CLICKED(IDC_BUTTON_WEBSOCKET_CONNECT, &CLibeventExample_MFCDlg::OnBtnWebsocketConnect)
	ON_BN_CLICKED(IDC_BUTTON_WEBSOCKET_DISCONNECT_SERVER, &CLibeventExample_MFCDlg::OnBtnWebsocketDisconnectServer)
	ON_BN_CLICKED(IDC_BUTTON_DISCONN_WEBSOCKET_CLIENT, &CLibeventExample_MFCDlg::OnBtnDisconnWebsocketClient)
	ON_BN_CLICKED(IDC_BUTTON_CREATETIMER2, &CLibeventExample_MFCDlg::OnBtnStopTimer)
END_MESSAGE_MAP()

BOOL CLibeventExample_MFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	_editPort.SetWindowText(L"23300");
	_ipRemote.SetAddress(127, 0, 0, 1);
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

void CLibeventExample_MFCDlg::OnEventDataDeleted(EventData* eventData)
{
	lock_guard<mutex> lock(_mtxCurrentEventData);
	if (_currentEventData == eventData)
	{
		_currentEventData = nullptr;
	}
}

void CLibeventExample_MFCDlg::SetCurrentEventData(EventData* eventData)
{
	lock_guard<mutex> lock(_mtxCurrentEventData);
	_currentEventData = eventData;
}

int CLibeventExample_MFCDlg::OnWebsocketConnect(libeventWS* ws)
{
	string remoteIP = "0";
	int remotePort = 0;
	const struct sockaddr* remoteAddr = evhttp_connection_get_addr(ws->evConn);
	if (remoteAddr)
	{
		ConvertIPPort(*(sockaddr_in*)remoteAddr, remoteIP, remotePort);
	}

	CString tmpStr;
	if (_httpServer)
	{
		tmpStr.Format(L"新WebSocket客户端 %s:%d 已连接", S2Unicode(remoteIP).c_str(), remotePort);
	}
	else
	{
		tmpStr.Format(L"与WebSocket服务端 %s:%d 已连接", S2Unicode(remoteIP).c_str(), remotePort);
	}
	AppendMsg(tmpStr);
	
	_currentWS = ws;
	_isWebsocket = true;
	return true;
}

int CLibeventExample_MFCDlg::OnWebsocketDisconnect(libeventWS* ws)
{
	if (_httpServer)
	{
		AppendMsg(L"WebSocket客户端连接断开");
	}
	else
	{
		AppendMsg(L"与WebSocket服务端连接断开");
	}

	if (_currentWS == ws)
	{
		_currentWS = nullptr;
	}
	_isWebsocket = false;

	return true;
}

int CLibeventExample_MFCDlg::OnWebsocketRead(libeventWS* ws, uint8_t* buf, size_t size)
{
	CString strMsg;
	strMsg.Format(L"WebSocket收到数据 %u字节", size);
	AppendMsg(strMsg);

	return 0;
}

int CLibeventExample_MFCDlg::OnWebsocketWrite(libeventWS* ws)
{
	struct bufferevent* bev = evhttp_connection_get_bufferevent(ws->evConn);
	evbuffer* output = bufferevent_get_output(bev);
	size_t outputSize = evbuffer_get_length(output); // 总是0

	AppendMsg(L"WebSocket写入数据完成");
	return 0;
}

LRESULT CLibeventExample_MFCDlg::OnFunction(WPARAM wParam, LPARAM lParam)
{
	TheadFunc* pFunc = (TheadFunc*)wParam;
	pFunc->Func();
	delete pFunc;

	return TRUE;
}

void OnEventTimer(evutil_socket_t fd, short event, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;
	dlg->AppendMsg(L"定时器");
}

void CLibeventExample_MFCDlg::OnBtnCreatetimer()
{
	event_base* eventBase = event_base_new();

	//_timer = event_new(eventBase, -1, EV_ET/*一次性*/, OnEventTimer, this);
	event* timer = event_new(eventBase, -1, EV_PERSIST, OnEventTimer, this);
	if (timer)
	{
		timeval timeout = { 2, 0 };
		// 		timeout.tv_sec = 2;
		// 		timeout.tv_usec = 0;
		if (0 == event_add(timer, &timeout))
		{
			_timer = timer;

			thread([&, eventBase, timer]
				{
					event_base_dispatch(eventBase); // 阻塞
					AppendMsg(L"定时器 结束");

					event_free(timer);
					event_base_free(eventBase);
				}).detach();
		}
		else
		{
			event_free(timer);
			event_base_free(eventBase);
			AppendMsg(L"创建定时器失败");
		}
	}
}

void CLibeventExample_MFCDlg::OnBtnStopTimer()
{
	if (_timer)
	{
		event_del(_timer);
		_timer = nullptr;
	}
}

void CLibeventExample_MFCDlg::OnBtnDisconnClient()
{
	if (_currentEventData)
	{
		AppendMsg(L"手动断开与当前客户端的连接");
		_currentEventData->close();
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
		uint8_t* inputData = evbuffer_pullup(input, sz);

		CString tmpStr;
		tmpStr.Format(L"threadID:%d 收到%u字节", this_thread::get_id(), sz);
		eventData->dlg->AppendMsg(tmpStr);

		evbuffer_drain(input, sz);
	}
}

static void OnServerEvent(bufferevent* bev, short events, void* param)
{
	EventData* eventData = (EventData*)param;

	if (events & BEV_EVENT_EOF)
	{
		eventData->dlg->AppendMsg(L"BEV_EVENT_EOF 连接关闭");
		delete eventData;
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
		return;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) != 0)
	{
		return;
	}

	linger optLinger;
	optLinger.l_onoff = 1;
	optLinger.l_linger = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&optLinger, sizeof(optLinger)) != 0)
	{
		return;
	}

	if (evutil_make_socket_nonblocking(sockfd) < 0)
	{
		return;
	}

	// 构造一个bufferevent
	EventData* eventData = new EventData;
	eventData->dlg = listenEventData->dlg;
	bufferevent* bev = nullptr;
	if (listenEventData->dlg->IsUseSSL())
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
		eventData->dlg->AppendMsg(L"bufferevent_socket_new失败");
		event_base_loopbreak(eventBase);
		delete eventData;
		return;
	}
	eventData->bev = bev;
	eventData->dlg->SetCurrentEventData(eventData);

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

	string remoteIP = "0";
	int remotePort = 0;
	ConvertIPPort(*(sockaddr_in*)remoteAddr, remoteIP, remotePort);
	CString tmpStr;
	tmpStr.Format(L"threadID:%d 新客户端%s:%d 已连接", this_thread::get_id(), S2Unicode(remoteIP).c_str(), remotePort);
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

	sockaddr_in localAddr = { 0 };
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(port);

	EventData* eventData = new EventData;
	eventData->dlg = this;

	if (IsUseSSL())
	{
		/*
			生成x.509证书
			首选在安装好openssl的机器上创建私钥文件：server.key
			> openssl genrsa -out server.key 2048

			得到私钥文件后我们需要一个证书请求文件：server.csr，将来你可以拿这个证书请求向正规的证书管理机构申请证书
			> openssl req -new -key server.key -out server.csr

			最后我们生成自签名的x.509证书（有效期365天）：server.crt
			> openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
		*/
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
		int res = SSL_CTX_use_certificate_file(ssl_ctx, UnicodeToUTF8(serverCrtPath).c_str(), SSL_FILETYPE_PEM);
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_use_certificate_file failed");
			return;
		}
		res = SSL_CTX_use_PrivateKey_file(ssl_ctx, UnicodeToUTF8(serverKeyPath).c_str(), SSL_FILETYPE_PEM);
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
		delete eventData;
		return;
	}
	_listenEventData = eventData;

	thread([&, eventBase]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"服务端socket event_base_dispatch线程 结束");

			evconnlistener_free(_listener);
			delete _listenEventData;
			_listenEventData = nullptr;
			event_base_free(eventBase);
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
		uint8_t* inputData = evbuffer_pullup(input, sz);

		CString tmpStr;
		tmpStr.Format(L"threadID:%d 收到%u字节", this_thread::get_id(), sz);
		eventData->dlg->AppendMsg(tmpStr);

		evbuffer_drain(input, sz);
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
		delete eventData;
	}
	else if (events & BEV_EVENT_ERROR)
	{
		CString tmpStr;
		if (events & BEV_EVENT_READING)
		{
			tmpStr.Format(L"BEV_EVENT_ERROR 读错误errno:%d", errno);
		}
		else if (events & BEV_EVENT_WRITING)
		{
			tmpStr.Format(L"BEV_EVENT_ERROR 写错误errno:%d", errno);
		}
		else
		{
			tmpStr.Format(L"BEV_EVENT_ERROR 错误errno:%d", errno);
		}	
		eventData->dlg->AppendMsg(tmpStr);
		delete eventData;
	}
}

void CLibeventExample_MFCDlg::OnBtnConnect()
{
	CString tmpStr;

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

	EventData* eventData = new EventData;
	eventData->dlg = this;
	if (IsUseSSL())
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		eventData->ssl_ctx = SSL_CTX_new(TLS_client_method());
		eventData->ssl = SSL_new(eventData->ssl_ctx);
	}

	bufferevent* bev = nullptr;
#ifdef _USE_RANDOM_LOCALPORT
	// 使用随机的本地端口
	if (IsUseSSL())
	{
		bev = bufferevent_openssl_socket_new(eventBase, -1, eventData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	else
	{
		bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
#else
	// 使用指定的本地IP、端口
	_editPort.GetWindowText(tmpStr);
	const int localPort = _wtoi(tmpStr);

	sockaddr_in localAddr = { 0 };
	if (!ConvertIPPort("0.0.0.0", localPort, localAddr))
	{
		AppendMsg(L"IP地址无效");
	}

	evutil_socket_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
	// 修改socket属性
	int bufLen = SINGLE_PACKAGE_SIZE;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufLen, sizeof(int)) != 0)
	{
		return;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufLen, sizeof(int)) != 0)
	{
		return;
	}

	linger optLinger;
	optLinger.l_onoff = 1;
	optLinger.l_linger = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&optLinger, sizeof(optLinger)) != 0)
	{
		return;
	}
	if (evutil_make_socket_nonblocking(sockfd) < 0)
	{
		return;
	}

	if (::bind(sockfd, (sockaddr*)&localAddr, sizeof(localAddr)) != 0)
	{
		AppendMsg(L"TCP绑定失败");
		return;
	}

	if (IsUseSSL())
	{
		bev = bufferevent_openssl_socket_new(eventBase, sockfd, eventData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	else
	{
		bev = bufferevent_socket_new(eventBase, sockfd, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
#endif

	if (nullptr == bev)
	{
		AppendMsg(L"bufferevent_socket_new失败");
		delete eventData;
		event_base_free(eventBase);
		return;
	}
	eventData->bev = bev;

	bufferevent_setcb(bev, OnClientRead, OnClientWrite, OnClientEvent, eventData);

	//连接服务端
	DWORD dwRemoteIP;
	_ipRemote.GetAddress(dwRemoteIP);

	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	sockaddr_in serverAddr = { 0 };
	ConvertIPPort(dwRemoteIP, remotePort, serverAddr);

	int flag = bufferevent_socket_connect(bev, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (-1 == flag)
	{
		AppendMsg(L"连接服务端失败");
		delete eventData;
		event_base_free(eventBase);
		return;
	}

	_currentEventData = eventData;

	// 修改读写上限
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

			delete _currentEventData;
			_currentEventData = nullptr;
			event_base_free(eventBase);
		}).detach();
}

void CLibeventExample_MFCDlg::OnBtnDisconnectServer()
{
	if (_currentEventData)
	{
		AppendMsg(L"手动断开与当前服务端的连接");
		_currentEventData->close();
	}
}

void CLibeventExample_MFCDlg::OnBtnSendMsg()
{
	thread([&] 
	{
		const int len = 1024 * 10;
		uint8_t* msg = new uint8_t[len]{ 0 };
		memset(msg, 'T', len - 1);

		if (_isWebsocket)
		{
			if (_currentWS)
			{
				int ret = websocketSend(_currentWS, msg, len, WS_OP_BINARY);
				if (ret <= 0)
				{
					AppendMsg(L"发送数据失败");
				}
			}
		}
		else
		{
			if (_currentEventData)
			{
				int ret = bufferevent_write(_currentEventData->bev, msg, len);
				if (ret != 0)
				{
					AppendMsg(L"发送数据失败");
				}
			}
		}

		delete[] msg;
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
			tmpStr.Format(L"threadID:%d 收到来自%s:%d %u字节", this_thread::get_id(), S2Unicode(remoteIP).c_str(), remotePort, recvLen);
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
	if (::bind(_currentSockfd, (sockaddr*)&localAddr, sizeof(localAddr)))
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
	DWORD dwRemoteIP;
	_ipRemote.GetAddress(dwRemoteIP);

	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	sockaddr_in remoteAddr = { 0 };
	ConvertIPPort(dwRemoteIP, remotePort, remoteAddr);

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

	const evhttp_uri* evURI = evhttp_request_get_evhttp_uri(req);
	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/getA?q=test&s=some+thing"
	//evhttp_uri* evURI = evhttp_uri_parse(uri);// 解码uri
	if (!evURI)
	{
		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
		return;
	}
	// 	char uri[URL_MAX] = {0};
	// 	evhttp_uri_join((evhttp_uri*)evURI, uri, URL_MAX);// 获取请求uri "/api/getA?q=test&s=some+thing"

	const char* path = evhttp_uri_get_path(evURI); // 获取uri中的path部分 "/api/getA"
	if (!path)
	{
		path = "/";
	}

	const char* query = evhttp_uri_get_query(evURI); // 获取uri中的参数部分 "q=test&s=some+thing"
	const char* scheme = evhttp_uri_get_scheme(evURI); // nullptr
	const char* fragment = evhttp_uri_get_fragment(evURI); // nullptr

	// 查询指定参数的值
	evkeyvalq params = { 0 };
	evhttp_parse_query_str(query, &params);
	const char* value = evhttp_find_header(&params, "s"); // "some thing"
	value = evhttp_find_header(&params, "q"); // "test"

	// 回复
	evbuffer_add_printf(req->output_buffer, UnicodeToUTF8(L"谢谢！Thanks use getA").c_str());
	//evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, HTTP_OK, "OK", nullptr);

	CString strMsg;
	strMsg.Format(L"收到%s:%d PutA接口请求", CString(req->remote_host), req->remote_port);
	dlg->AppendMsg(strMsg);
}

static void OnHTTP_API_postA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;
	// http://127.0.0.1:23300/api/postA?q=test&s=some+thing

	const evhttp_uri* evURI = evhttp_request_get_evhttp_uri(req);
	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/postA?q=test&s=some+thing"
	//evhttp_uri* evURI = evhttp_uri_parse(uri);// 解码uri
	if (!evURI)
	{
		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
		return;
	}
	// 	char uri[URL_MAX] = {0};
	// 	evhttp_uri_join((evhttp_uri*)evURI, uri, URL_MAX);// 获取请求uri "/api/posttA?q=test&s=some+thing"

	const char* path = evhttp_uri_get_path(evURI); // 获取uri中的path部分 "/api/postA"
	if (!path)
	{
		path = "/";
	}

	const char* query = evhttp_uri_get_query(evURI); // 获取uri中的参数部分 "q=test&s=some+thing"
	const char* fragment = evhttp_uri_get_fragment(evURI);

	// 查询指定参数的值
	evkeyvalq params = { 0 };
	evhttp_parse_query_str(query, &params);
	const char* value = evhttp_find_header(&params, "s"); // "some thing"
	value = evhttp_find_header(&params, "q"); // "test"

	// 获取Headers
	evkeyvalq* headers = evhttp_request_get_input_headers(req);
	value = evhttp_find_header(headers, "Host");
	value = evhttp_find_header(headers, "BodySize");
	size_t bodySize = atoi(value);

	// 获取数据长度
	size_t len = evbuffer_get_length(req->input_buffer);
	if (len != bodySize)
	{
		evhttp_send_reply(req, HTTP_NOCONTENT, "wrong bodySize", nullptr);
		CString strMsg;
		strMsg.Format(L"bodySize:%u 但实际收到PostA接口%u字节数据", bodySize, len);
		dlg->AppendMsg(strMsg);
		return;
	}

	if (len > 0)
	{
		// 获取数据指针
		unsigned char* data = evbuffer_pullup(req->input_buffer, len);

		// 处理数据...

		// 清空数据
		evbuffer_drain(req->input_buffer, len);
	}

	// 模拟时延/超时
	//this_thread::sleep_for(chrono::seconds(5));

	// 回复
	const size_t bufSize = 65535 * 10;
	char* postBuf = new char[bufSize] {'B'};
	evbuffer_add(req->output_buffer, postBuf, bufSize);
	delete[] postBuf;
	evhttp_send_reply(req, HTTP_OK, nullptr, nullptr);

	CString strMsg;
	strMsg.Format(L"收到PostA接口%u字节数据", len);
	dlg->AppendMsg(strMsg);
}

static void OnHTTP_API_postFileA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;
	// http://127.0.0.1:23300/api/postFileA?q=test&s=some+thing

	const evhttp_uri* evURI = evhttp_request_get_evhttp_uri(req);
	const char* uri = evhttp_request_get_uri(req);// 获取请求uri "/api/postFileA?q=test&s=some+thing"
	//evhttp_uri* evURI = evhttp_uri_parse(uri);// 解码uri
	if (!evURI)
	{
		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
		return;
	}
	// 	char uri[URL_MAX] = {0};
	// 	evhttp_uri_join((evhttp_uri*)evURI, uri, URL_MAX);// 获取请求uri "/api/postFileA?q=test&s=some+thing"

	const char* path = evhttp_uri_get_path(evURI); // 获取uri中的path部分 "/api/postFileA"
	if (!path)
	{
		path = "/";
	}

	const char* query = evhttp_uri_get_query(evURI); // 获取uri中的参数部分 "q=test&s=some+thing"
	const char* fragment = evhttp_uri_get_fragment(evURI);

	// 查询指定参数的值
	evkeyvalq params = { 0 };
	evhttp_parse_query_str(query, &params);
	const char* value = evhttp_find_header(&params, "s"); // "some thing"
	value = evhttp_find_header(&params, "q"); // "test"

	// 获取Headers
	evkeyvalq* headers = evhttp_request_get_input_headers(req);
	value = evhttp_find_header(headers, "FileSize");
	size_t fileSize = atoi(value);
	wstring fileName = UTF8ToUnicode(evhttp_find_header(headers, "FileName"));

	// 获取数据长度
	size_t len = evbuffer_get_length(req->input_buffer);
	if (len != fileSize)
	{
		evhttp_send_reply(req, HTTP_NOCONTENT, "wrong bodySize", nullptr);
		CString strMsg;
		strMsg.Format(L"fileName:%s fileSize:%u 但实际收到PostFileA接口%u字节数据", fileName.c_str(), fileSize, len);
		dlg->AppendMsg(strMsg);
		return;
	}

	if (len > 0)
	{
		// 获取数据指针
		unsigned char* data = evbuffer_pullup(req->input_buffer, len);

		// 处理数据...

		// 清空数据
		evbuffer_drain(req->input_buffer, len);
	}

	// 模拟时延/超时
	//this_thread::sleep_for(chrono::seconds(5));

	// 回复
	const size_t bufSize = 65535 * 10;
	char* postBuf = new char[bufSize] {'B'};
	evbuffer_add(req->output_buffer, postBuf, bufSize);
	delete[] postBuf;
	evhttp_send_reply(req, HTTP_OK, nullptr, nullptr);

	CString strMsg;
	strMsg.Format(L"收到PostFileA接口 %s %u字节数据", fileName.c_str(), len);
	dlg->AppendMsg(strMsg);
}


static void OnHTTP_API_putA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	size_t len = evbuffer_get_length(req->input_buffer);
	if (len > 0)
	{
		// 获取数据指针
		unsigned char* data = evbuffer_pullup(req->input_buffer, len);

		// 处理数据...

		// 清空数据
		evbuffer_drain(req->input_buffer, len);
	}

	const char* s = "This is the test buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);

	CString strMsg;
	strMsg.Format(L"收到PutA接口%u字节数据", len);
	dlg->AppendMsg(strMsg);
}

static void OnHTTP_API_delA(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	size_t len = evbuffer_get_length(req->input_buffer);
	if (len > 0)
	{
		// 获取数据指针
		unsigned char* data = evbuffer_pullup(req->input_buffer, len);

		// 处理数据...

		// 清空数据
		evbuffer_drain(req->input_buffer, len);
	}

	const char* s = "This is the test buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);

	CString strMsg;
	strMsg.Format(L"收到DelA接口%u字节数据", len);
	dlg->AppendMsg(strMsg);
}

static void OnHTTP_Websocket(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	libeventWS* ws = handleWebsocketRequest(req, arg, bind(&CLibeventExample_MFCDlg::OnWebsocketConnect, dlg, placeholders::_1),
		bind(&CLibeventExample_MFCDlg::OnWebsocketDisconnect, dlg, placeholders::_1),
		bind(&CLibeventExample_MFCDlg::OnWebsocketRead, dlg, placeholders::_1, placeholders::_2, placeholders::_3),
		bind(&CLibeventExample_MFCDlg::OnWebsocketWrite, dlg, placeholders::_1));
	if (!ws)
	{
		dlg->AppendMsg(L"处理WebSocket升级请求错误");
	}
}

static void OnHTTPUnmatchedRequest(evhttp_request* req, void* arg)
{
	CLibeventExample_MFCDlg* dlg = (CLibeventExample_MFCDlg*)arg;

	const char* s = "This is the generic buf";
	evbuffer_add(req->output_buffer, s, strlen(s));
	evhttp_send_reply(req, 200, "OK", nullptr);
}

static bufferevent* OnHTTPSetBev(struct event_base* base, void* arg)
{
	EventData* eventData = (EventData*)arg;

	eventData->bev = bufferevent_openssl_socket_new(base,
		-1,
		SSL_new(eventData->ssl_ctx),
		BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	return eventData->bev;
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

	// 连接参数设置
	evhttp_set_max_headers_size(_httpServer, HTTP_MAX_HEAD_SIZE);
	evhttp_set_max_body_size(_httpServer, HTTP_MAX_BODY_SIZE);
	evhttp_set_max_connections(_httpServer, 10000 * 100);
	evhttp_set_timeout(_httpServer, 10);//设置闲置连接自动断开的超时时间(s)

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

		int res = SSL_CTX_use_certificate_chain_file(ssl_ctx, UnicodeToUTF8(serverCrtPath).c_str());
		if (res != 1)
		{
			AppendMsg(L"SSL_CTX_use_certificate_chain_file failed");
			return;
		}
		res = SSL_CTX_use_PrivateKey_file(ssl_ctx, UnicodeToUTF8(serverKeyPath).c_str(), SSL_FILETYPE_PEM);
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

		evhttp_set_bevcb(_httpServer, OnHTTPSetBev, eventData);
	}

	_httpSocket = evhttp_bind_socket_with_handle(_httpServer, "0.0.0.0", port);
	if (!_httpSocket)
	{
		AppendMsg(L"创建evhttp_bind_socket失败");
		delete eventData;
		evhttp_free(_httpServer);
		return;
	}

	/*
		URI like http://127.0.0.1:23300/api/getA?q=test&s=some+thing
		The first entry is: key="q", value="test"
		The second entry is: key="s", value="some thing"
	*/
	evhttp_set_cb(_httpServer, "/api/getA", OnHTTP_API_getA, this);
	evhttp_set_cb(_httpServer, "/api/postA", OnHTTP_API_postA, this);
	evhttp_set_cb(_httpServer, "/api/postFileA", OnHTTP_API_postFileA, this);
	evhttp_set_cb(_httpServer, "/api/putA", OnHTTP_API_putA, this);
	evhttp_set_cb(_httpServer, "/api/delA", OnHTTP_API_delA, this);
	evhttp_set_cb(_httpServer, "/websocket", OnHTTP_Websocket, this);
	evhttp_set_gencb(_httpServer, OnHTTPUnmatchedRequest, this);

	AppendMsg(L"HTTP 服务端启动");
	thread([&, eventData, eventBase]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"HTTP服务端 event_base_dispatch线程 结束");

			delete eventData;
			event_base_free(eventBase);
		}).detach();
}

void CLibeventExample_MFCDlg::OnBtnStopHttpServer()
{
	if (_httpServer && _httpSocket)
	{
		evhttp_del_accept_socket(_httpServer, _httpSocket);
		evhttp_free(_httpServer);

		AppendMsg(L"HTTP 服务端停止");
		_btnHTTPServer.EnableWindow(TRUE);
		_btnStopHttpServer.EnableWindow(FALSE);
	}
}

static void OnHttpResponseGetA(evhttp_request* req, void* arg)
{
	HttpData* httpData = (HttpData*)arg;

	if (req)
	{
		// 获取数据长度
		size_t len = evbuffer_get_length(req->input_buffer);
		if (len > 0)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(req->input_buffer, len);
			char* responseStr = new char[len + 1]{ 0 };
			memcpy(responseStr, data, len);

			CString strMsg;
			strMsg.Format(L"收到GetA接口回复：%s", UTF8ToUnicode(responseStr).c_str());
			httpData->dlg->AppendMsg(strMsg);
			delete[] responseStr;

			// 清空数据
			evbuffer_drain(req->input_buffer, len);
			evhttp_request_free(req);
		}
	}
	else
	{
		httpData->dlg->AppendMsg(L"GetA失败");
	}

	// 主动断开与服务器连接
	httpData->Free();
}

void CLibeventExample_MFCDlg::OnBtnHttpGet()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/getA?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	evthread_use_windows_threads();
	event_base* eventBase = event_base_new();

	HttpData* httpData = new HttpData;
	httpData->dlg = this;

	httpData->evURI = evhttp_uri_parse(uri);
	const char* host = evhttp_uri_get_host(httpData->evURI);
	int port = evhttp_uri_get_port(httpData->evURI);
	httpData->evConn = evhttp_connection_base_new(eventBase, NULL, host, port);

	evhttp_request* req = evhttp_request_new(OnHttpResponseGetA, httpData);

	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_GET, "/api/getA?q=test&s=some+thing");

	thread([&, eventBase, httpData]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"客户端HttpGet event_base_dispatch线程 结束");

			delete httpData;
			event_base_free(eventBase);
		}).detach();
}

static void OnHttpResponsePostA(evhttp_request* req, void* arg)
{
	HttpData* httpData = (HttpData*)arg;
	if (req)
	{
		// 获取数据长度
		size_t len = evbuffer_get_length(req->input_buffer);
		if (len > 0)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(req->input_buffer, len);

			// 处理数据...

			// 清空数据
			evbuffer_drain(req->input_buffer, len);
		}
		evhttp_request_free(req);

		CString strMsg;
		strMsg.Format(L"收到PostA接口回复%u字节数据", len);
		httpData->dlg->AppendMsg(strMsg);
	}
	else
	{
		httpData->dlg->AppendMsg(L"PostA失败");
	}

	// 主动断开与服务器连接
	//httpData->Free();
}

void CLibeventExample_MFCDlg::OnBtnHttpPost()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/postA?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	evthread_use_windows_threads();
	event_base* eventBase = event_base_new();

	HttpData* httpData = new HttpData;
	httpData->dlg = this;

	httpData->evURI = evhttp_uri_parse(uri);
	const char* host = evhttp_uri_get_host(httpData->evURI);
	int port = evhttp_uri_get_port(httpData->evURI);

	if (IsUseSSL())
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		httpData->ssl_ctx = SSL_CTX_new(TLS_client_method());
		httpData->ssl = SSL_new(httpData->ssl_ctx);
		httpData->bev = bufferevent_openssl_socket_new(eventBase, -1, httpData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		if (httpData->bev)
		{
			bufferevent_ssl_set_flags(httpData->bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
		}
	}
	else
	{
		httpData->bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	if (httpData->bev == NULL)
	{
		AppendMsg(L"bev创建失败");
		delete httpData;
		return;
	}

	httpData->evConn = evhttp_connection_base_bufferevent_new(eventBase, NULL, httpData->bev, host, port);
	if (httpData->evConn == NULL)
	{
		AppendMsg(L"evhttp_connection_base_bufferevent_new失败");
		delete httpData;
		return;
	}

	evhttp_connection_set_max_headers_size(httpData->evConn, HTTP_MAX_HEAD_SIZE);
	evhttp_connection_set_max_body_size(httpData->evConn, HTTP_MAX_BODY_SIZE);
	evhttp_connection_set_timeout(httpData->evConn, 3);// 设置超时时间(s)

	evhttp_request* req = evhttp_request_new(OnHttpResponsePostA, httpData);

	// 标准Header
	evhttp_add_header(req->output_headers, "Connection", "keep-alive");
	evhttp_add_header(req->output_headers, "Host", "localhost");

	// 自定义Header
	const size_t bufSize = 1024 * 1024; // 单次最大1GB（1024 * 1024 * 1024）
	evhttp_add_header(req->output_headers, "bodySize", Int2Str(bufSize).c_str());

	// 自定义Body数据
	char* postBuf = new char[bufSize];
	memset(postBuf, 'A', bufSize);
	evbuffer_add(req->output_buffer, postBuf, bufSize);
	delete[] postBuf;

	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_POST, "/api/postA?q=test&s=some+thing");

	thread([&, eventBase, httpData]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"客户端HttpPost event_base_dispatch线程 结束");

			// 先断开连接，后释放eventBase
			delete httpData;
			event_base_free(eventBase);
		}).detach();
}

static void OnHttpResponsePostFileA(evhttp_request* req, void* arg)
{
	HttpData* httpData = (HttpData*)arg;
	if (req)
	{
		// 获取数据长度
		size_t len = evbuffer_get_length(req->input_buffer);
		if (len > 0)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(req->input_buffer, len);

			// 处理数据...

			// 清空数据
			evbuffer_drain(req->input_buffer, len);
		}
		evhttp_request_free(req);

		CString strMsg;
		strMsg.Format(L"收到PostFileA接口回复%u字节数据", len);
		httpData->dlg->AppendMsg(strMsg);
	}
	else
	{
		httpData->dlg->AppendMsg(L"PostFileA失败");
	}

	// 主动断开与服务器连接
	//httpData->Free();
}

void CLibeventExample_MFCDlg::OnBtnHttpPostFile()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CFileDialog dlg(TRUE, NULL, NULL, OFN_FILEMUSTEXIST,
		_T("All Files (*.*)|*.*||"),
		NULL);
	if (dlg.DoModal() != IDOK)
	{
		return;
	}

	// 加载文件
	/*
	* _wsopen_s说明
	https://docs.microsoft.com/zh-cn/previous-versions/w64k0ytk(v=vs.110)?redirectedfrom=MSDN
	*/
	int readFile = NULL;
	int ret = _wsopen_s(&readFile, dlg.GetPathName(), _O_RDONLY | _O_BINARY, _SH_DENYWR, _S_IREAD); // 使用宽字节接口解决中文问题
	if (0 != ret)
	{
		AppendMsg(L"读取文件失败");
		return;
	}

	struct _stat64 st;
	_wstat64(dlg.GetPathName(), &st); // 获取文件信息
	if (st.st_size > HTTP_MAX_BODY_SIZE)
	{
		AppendMsg(L"文件体积过大");
		return;
	}

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/postFileA?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	evthread_use_windows_threads();
	event_base* eventBase = event_base_new();

	HttpData* httpData = new HttpData;
	httpData->dlg = this;

	httpData->evURI = evhttp_uri_parse(uri);
	const char* host = evhttp_uri_get_host(httpData->evURI);
	int port = evhttp_uri_get_port(httpData->evURI);

	if (IsUseSSL())
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		httpData->ssl_ctx = SSL_CTX_new(TLS_client_method());
		httpData->ssl = SSL_new(httpData->ssl_ctx);
		httpData->bev = bufferevent_openssl_socket_new(eventBase, -1, httpData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		if (httpData->bev)
		{
			bufferevent_ssl_set_flags(httpData->bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
		}
	}
	else
	{
		httpData->bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	if (httpData->bev == NULL)
	{
		AppendMsg(L"bev创建失败");
		delete httpData;
		return;
	}

	httpData->evConn = evhttp_connection_base_bufferevent_new(eventBase, NULL, httpData->bev, host, port);
	if (httpData->evConn == NULL)
	{
		AppendMsg(L"evhttp_connection_base_bufferevent_new失败");
		delete httpData;
		return;
	}

	evhttp_connection_set_max_headers_size(httpData->evConn, HTTP_MAX_HEAD_SIZE);
	evhttp_connection_set_max_body_size(httpData->evConn, HTTP_MAX_BODY_SIZE);
	//evhttp_connection_set_timeout(httpData->evConn, 30);// 可以不设置超时时间；设置超时时间，文件越大，需要的时间越长(s)

	evhttp_request* req = evhttp_request_new(OnHttpResponsePostFileA, httpData);

	// 标准Header
	evhttp_add_header(req->output_headers, "Connection", "keep-alive");
	evhttp_add_header(req->output_headers, "Host", "localhost");

	// 自定义Header
	const size_t fileSize = st.st_size; // 单次最大2GB（1024 * 1024 * 1024 - 1024）
	string strFileName = UnicodeToUTF8(dlg.GetFileName()); // 文件名使用UTF-8存储
	evhttp_add_header(req->output_headers, "FileName", strFileName.c_str());
	evhttp_add_header(req->output_headers, "FileSize", Int2Str(fileSize).c_str());

	// 文件数据
	ret = evbuffer_add_file(req->output_buffer, readFile, 0, fileSize);
	if (0 != ret)
	{
		AppendMsg(L"evbuffer_add_file失败");
		event_base_free(eventBase);
		return;
	}

	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_POST, "/api/postFileA?q=test&s=some+thing");

	thread([&, eventBase, httpData]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"客户端HttpPost event_base_dispatch线程 结束");

			delete httpData;
			event_base_free(eventBase);
		}).detach();
}

static void OnHttpResponsePutA(evhttp_request* req, void* arg)
{
	auto threadID = this_thread::get_id();
	HttpData* httpData = (HttpData*)arg;
	if (req)
	{
		// 获取数据长度
		size_t len = evbuffer_get_length(req->input_buffer);
		if (len > 0)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(req->input_buffer, len);

			// 处理数据...

			// 清空数据
			evbuffer_drain(req->input_buffer, len);
		}

		CString strMsg;
		strMsg.Format(L"收到PutA接口回复%u字节数据", len);
		httpData->dlg->AppendMsg(strMsg);
	}
	else
	{
		httpData->dlg->AppendMsg(L"PutA失败");
	}

	evhttp_request_free(httpData->req);
	httpData->req = nullptr;
}

void CLibeventExample_MFCDlg::OnBtnHttpPut()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	thread([&, remotePort]
		{
			CString strURI;
			strURI.Format(L"http://127.0.0.1:%d/api/putA?q=test&s=some+thing", remotePort);
			string utf8URI = UnicodeToUTF8(strURI);
			const char* uri = utf8URI.c_str();

			evthread_use_windows_threads();
			event_base* eventBase = event_base_new();

			HttpData* httpData = new HttpData;
			httpData->dlg = this;

			httpData->evURI = evhttp_uri_parse(uri);
			const char* host = evhttp_uri_get_host(httpData->evURI);
			int port = evhttp_uri_get_port(httpData->evURI);

			if (IsUseSSL())
			{
				// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
				httpData->ssl_ctx = SSL_CTX_new(TLS_client_method());
				httpData->ssl = SSL_new(httpData->ssl_ctx);
				httpData->bev = bufferevent_openssl_socket_new(eventBase, -1, httpData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
				if (httpData->bev)
				{
					bufferevent_ssl_set_flags(httpData->bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
				}
			}
			else
			{
				httpData->bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
			}
			if (httpData->bev == NULL)
			{
				AppendMsg(L"bev创建失败");
				delete httpData;
				return;
			}

			httpData->evConn = evhttp_connection_base_bufferevent_new(eventBase, NULL, httpData->bev, host, port);
			if (httpData->evConn == NULL)
			{
				AppendMsg(L"evhttp_connection_base_bufferevent_new失败");
				delete httpData;
				return;
			}

			evhttp_connection_set_max_headers_size(httpData->evConn, HTTP_MAX_HEAD_SIZE);
			evhttp_connection_set_max_body_size(httpData->evConn, HTTP_MAX_BODY_SIZE);
			evhttp_connection_set_timeout(httpData->evConn, 1);// 设置闲置连接自动断开的超时时间(s)

			auto funReq = [httpData, eventBase]
			{
				auto threadID = this_thread::get_id();
				evhttp_request* req = evhttp_request_new(OnHttpResponsePutA, httpData);
				httpData->req = req;

				// 标准Header
				evhttp_add_header(req->output_headers, "Connection", "keep-alive");
				evhttp_add_header(req->output_headers, "Host", "localhost");

				// 自定义Header
				const size_t bufSize = 1024; // 单次最大1GB（1024 * 1024 * 1024）
				evhttp_add_header(req->output_headers, "bodySize", Int2Str(bufSize).c_str());

				// 自定义Body数据
				char* postBuf = new char[bufSize] {'A'};
				evbuffer_add(req->output_buffer, postBuf, bufSize);
				delete[] postBuf;

				evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_PUT, "/api/putA?q=test&s=some+thing");
				httpData->dlg->AppendMsg(L"evhttp_make_request");
			};

			// 创建空白定时器，以维持eventBase
			auto funcDoNothingTimer = [](evutil_socket_t fd, short event, void* arg) {};
			event* ev = event_new(eventBase, -1, EV_PERSIST, funcDoNothingTimer, nullptr);
			timeval timeout = { 0, 100 };
			event_add(ev, &timeout);

			// 间隔发送请求，模拟长连接	
			thread([funReq, ev]
				{
					int num = 0;
					do
					{
						funReq();

						this_thread::sleep_for(chrono::seconds(5));

						num++;
					} while (num < 5);
					event_del(ev);
					event_free(ev);
				}).detach();

				event_base_dispatch(eventBase); // 阻塞			

				// 先断开连接，后释放eventBase
				delete httpData;
				event_base_free(eventBase);
				AppendMsg(L"客户端HttpPut event_base_dispatch线程 结束");

		}).detach();
}

static void OnHttpResponseDelA(evhttp_request* req, void* arg)
{
	HttpData* httpData = (HttpData*)arg;

	if (req)
	{
		// 获取数据长度
		size_t len = evbuffer_get_length(req->input_buffer);
		if (len > 0)
		{
			// 获取数据指针
			unsigned char* data = evbuffer_pullup(req->input_buffer, len);
			char* responseStr = new char[len + 1]{ 0 };
			memcpy(responseStr, data, len);

			CString strMsg;
			strMsg.Format(L"收到DelA接口回复：%s", UTF8ToUnicode(responseStr).c_str());
			httpData->dlg->AppendMsg(strMsg);
			delete[] responseStr;

			// 清空数据
			evbuffer_drain(req->input_buffer, len);
			evhttp_request_free(req);
		}
	}

	// 主动断开与服务器连接
	httpData->Free();
}

void CLibeventExample_MFCDlg::OnBtnHttpDel()
{
	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"http://127.0.0.1:%d/api/delA?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	evthread_use_windows_threads();
	event_base* eventBase = event_base_new();

	HttpData* httpData = new HttpData;
	httpData->dlg = this;

	httpData->evURI = evhttp_uri_parse(uri);
	const char* host = evhttp_uri_get_host(httpData->evURI);
	int port = evhttp_uri_get_port(httpData->evURI);

	if (IsUseSSL())
	{
		// bufferevent_openssl_socket_new方法包含了对bufferevent和SSL的管理，因此当连接关闭的时候不再需要SSL_free
		httpData->ssl_ctx = SSL_CTX_new(TLS_client_method());
		httpData->ssl = SSL_new(httpData->ssl_ctx);
		httpData->bev = bufferevent_openssl_socket_new(eventBase, -1, httpData->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		if (httpData->bev)
		{
			bufferevent_ssl_set_flags(httpData->bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
		}
	}
	else
	{
		httpData->bev = bufferevent_socket_new(eventBase, -1, BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);
	}
	if (httpData->bev == NULL)
	{
		AppendMsg(L"bev创建失败");
		delete httpData;
		return;
	}

	httpData->evConn = evhttp_connection_base_bufferevent_new(eventBase, NULL, httpData->bev, host, port);
	if (httpData->evConn == NULL)
	{
		AppendMsg(L"evhttp_connection_base_bufferevent_new失败");
		delete httpData;
		return;
	}

	evhttp_request* req = evhttp_request_new(OnHttpResponseDelA, httpData);
	if (req == NULL)
	{
		AppendMsg(L"evhttp_request_new失败");
		delete httpData;
		return;
	}

	evhttp_make_request(httpData->evConn, req, EVHTTP_REQ_GET, "/api/delA?q=test&s=some+thing");

	thread([&, eventBase, httpData]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"客户端HttpGet event_base_dispatch线程 结束");

			delete httpData;
			event_base_free(eventBase);
		}).detach();
}

void CLibeventExample_MFCDlg::OnBtnWebsocketConnect()
{
	evthread_use_windows_threads();
	event_base* eventBase = event_base_new();

	CString tmpStr;
	_editRemotePort.GetWindowText(tmpStr);
	const int remotePort = _wtoi(tmpStr);

	CString strURI;
	strURI.Format(L"ws://127.0.0.1:%d/websocket?q=test&s=some+thing", remotePort);
	string utf8URI = UnicodeToUTF8(strURI);
	const char* uri = utf8URI.c_str();

	libeventWS* ws = nullptr;
#ifdef _USE_RANDOM_LOCALPORT
	// 使用随机的本地端口
	ws = websocketConnect(eventBase, uri,
		bind(&CLibeventExample_MFCDlg::OnWebsocketConnect, this, placeholders::_1),
		bind(&CLibeventExample_MFCDlg::OnWebsocketDisconnect, this, placeholders::_1),
		bind(&CLibeventExample_MFCDlg::OnWebsocketRead, this, placeholders::_1, placeholders::_2, placeholders::_3),
		bind(&CLibeventExample_MFCDlg::OnWebsocketWrite, this, placeholders::_1),
		IsUseSSL(),
		"0.0.0.0", 0);
#else
	// 使用指定的本地IP、端口
	_editPort.GetWindowText(tmpStr);
	const int localPort = _wtoi(tmpStr);

	ws = websocketConnect(eventBase, uri,
		bind(&CLibeventExample_MFCDlg::OnWebsocketConnect, this, placeholders::_1),
		bind(&CLibeventExample_MFCDlg::OnWebsocketDisconnect, this, placeholders::_1),
		bind(&CLibeventExample_MFCDlg::OnWebsocketRead, this, placeholders::_1, placeholders::_2, placeholders::_3),
		bind(&CLibeventExample_MFCDlg::OnWebsocketWrite, this, placeholders::_1),
		IsUseSSL(),
		"0.0.0.0", localPort);
#endif
	if (!ws)
	{
		AppendMsg(L"WebSocket客户端连接失败");
	}

	thread([&, eventBase]
		{
			event_base_dispatch(eventBase); // 阻塞
			AppendMsg(L"客户端WebSocket event_base_dispatch线程 结束");
			event_base_free(eventBase);
		}).detach();
}


void CLibeventExample_MFCDlg::OnBtnWebsocketDisconnectServer()
{
	if (_currentWS)
	{
		_currentWS->close();
		_currentWS = nullptr;
	}
}

void CLibeventExample_MFCDlg::OnBtnDisconnWebsocketClient()
{
	if (_currentWS)
	{
		_currentWS->close();
		_currentWS = nullptr;
	}
}


