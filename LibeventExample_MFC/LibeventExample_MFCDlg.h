#pragma once
#include <functional>
#include <future>

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

using std::function;
using std::future;
using std::mutex;

class EventData;

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

	// TCP
	evconnlistener* _listener = nullptr;
	EventData* _listenEventData = nullptr;
	mutex		_mtxCurrentEventData;
	EventData* _currentEventData = nullptr;

	// UDP
	evutil_socket_t _currentSockfd = -1;
	event* _currentEvent = nullptr;

	// HTTP
	evhttp* _httpServer = nullptr;
	evhttp_bound_socket* _httpSocket;

	void InitTimer();
public:
	void AppendMsg(const WCHAR* msg);
	bool IsUseSSL();
	void OnEventDataDeleted(EventData* eventData);
	void SetCurrentEventData(EventData* eventData);

private:
	afx_msg void OnBtnDisconnClient();
	afx_msg void OnBtnListen();
	afx_msg void OnBtnCreatetimer();
	afx_msg void OnBtnStopListen();
	afx_msg void OnBtnConnect();
	afx_msg void OnBtnDisconnectServer();
	afx_msg void OnBtnSendMsg();
	afx_msg void OnBtnUdpBind();
	afx_msg void OnBtnUdpSendMsg();
	afx_msg void OnBtnUdpClose();
	afx_msg void OnBtnHttpServer();
	afx_msg void OnBtnStopHttpServer();
public:
	afx_msg void OnBtnHttpGet();
	afx_msg void OnBtnHttpPost();
	afx_msg void OnBtnHttpPut();
	afx_msg void OnBtnHttpPostFile();
	afx_msg void OnBtnHttpDel();
};
