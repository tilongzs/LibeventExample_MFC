﻿#pragma once
#include <afxdialogex.h>

#include <functional>
#include <future>
#include <chrono>

#include "event2/event.h"
#include "event2/thread.h"
#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_ssl.h"
#include "event2/buffer.h"
#include "event2/listener.h"
#include "event2/http.h"
#include "event2/keyvalq_struct.h"
#include "event2/http_struct.h"
#include "event2/bufferevent_struct.h"
#include "event2/ws.h"

#include "Common/TCPHandler.h"
#include "TCPHandler.h"

using std::function;
using std::future;
using std::mutex;
using std::chrono::steady_clock;
using std::list;

class EventData;
class LibeventWS;
struct evws_connection;

class CLibeventExample_MFCDlg : public CDialogEx
{
public:
	CLibeventExample_MFCDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_LibeventExample_MFC_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);

	struct TheadFunc
	{
		function<void()> Func;
	};
protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	LRESULT OnFunction(WPARAM wParam, LPARAM lParam);
private:
	CEdit _editRecv;
	CEdit _editPort;
	CEdit _editRemotePort;
	CButton _btnUseSSL;
	CButton _btnHTTPServer;
	CButton _btnStopHttpServer;
	CIPAddressCtrl _ipRemote;
	CEdit _editWSServer;

	// Timer
	event*			_timer;

	mutex		_mtxCurrentEventData;
	EventData* _currentEventData = nullptr;
	// TCP
	TCPHandler	_tcpHandler;

	// UDP
	evutil_socket_t _currentSockfd = -1;
	event* _currentEvent = nullptr;

	// HTTP
	evhttp* _httpServer = nullptr;
	evhttp_bound_socket* _httpSocket;

	// Websocket
	bool			_isWebsocket = false;
	LibeventWS* _currentWS = nullptr;
	evws_connection* _wsConnection = nullptr;

public:
	void AppendMsg(const WCHAR* msg);
	bool IsUseSSL();
	void SetCurrentEventData(EventData* eventData);
	int OnWebsocketConnect(LibeventWS* ws);
	int OnWebsocketDisconnect(LibeventWS* ws);
	int OnWebsocketRead(LibeventWS* ws, uint8_t* buf, size_t size);
	int OnWebsocketWrite(LibeventWS* ws);
	void SetWSConnection(evws_connection* wsConnection);
	void OnWebsocketClose(evws_connection* wsConnection);

private:
	void onAccept(EventData* eventData, const sockaddr* remoteAddr);
	void onConnected(EventData* eventData);
	void onDisconnect(const EventData* eventData);
	void onRecv(const EventData* socketData, const LocalPackage* localPackage);
	void onSend(const EventData* socketData, const LocalPackage* localPackage);

	afx_msg void OnBtnDisconnClient();
	afx_msg void OnBtnListen();
	afx_msg void OnBtnCreatetimer();
	afx_msg void OnBtnStopTimer();
	afx_msg void OnBtnStopListen();
	afx_msg void OnBtnConnect();
	afx_msg void OnBtnDisconnectServer();
	afx_msg void OnBtnSendMsg();
	afx_msg void OnBtnSendFile();
	afx_msg void OnBtnUdpBind();
	afx_msg void OnBtnUdpSendMsg();
	afx_msg void OnBtnUdpClose();
	afx_msg void OnBtnHttpServer();
	afx_msg void OnBtnStopHttpServer();
	afx_msg void OnBtnHttpGet();
	afx_msg void OnBtnHttpPost();
	afx_msg void OnBtnHttpPut();
	afx_msg void OnBtnHttpPostFile();
	afx_msg void OnBtnHttpDel();
	afx_msg void OnBtnWebsocketConnect();
	afx_msg void OnBtnWebsocketDisconnectServer();
	afx_msg void OnBtnDisconnWebsocketClient();
};
