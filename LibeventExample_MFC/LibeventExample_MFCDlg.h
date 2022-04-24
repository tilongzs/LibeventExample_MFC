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

using std::function;
using std::future;

struct EventData;

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

	// TCP
	evconnlistener* _listener = nullptr;
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

private:
	afx_msg void OnBnClickedButtonDisconnClient();
	afx_msg void OnBnClickedButtonListen();
	afx_msg void OnBnClickedButtonCreatetimer();
	afx_msg void OnBnClickedButtonStopListen();
	afx_msg void OnBnClickedButtonConnect();
	afx_msg void OnBnClickedButtonDisconnectServer();
	afx_msg void OnBnClickedButtonSendMsg();
	afx_msg void OnBnClickedButtonUdpBind();
	afx_msg void OnBnClickedButtonUdpSendMsg();	
	afx_msg void OnBnClickedButtonUdpClose();
public:
	CButton _btnHTTPServer;
	afx_msg void OntnHttpServer();
	CButton _btnStopHttpServer;
	afx_msg void OnBtnStopHttpServer();
};
