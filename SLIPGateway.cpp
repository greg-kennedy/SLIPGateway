// SLIPGateway
// Greg Kennedy - 2025

#define WIN32_LEAN_AND_MEAN
#include <winsock.h>
// provides StrToInt
#include <shlwapi.h>
// ICMP ping functions via DLL
//#include <icmpapi.h>

// auto A/W char selection
#include <tchar.h>

// C++ library
#include <fstream>
// data structures
#include <vector>
#include <map>
#include <queue>

#include "resource.h"

using namespace std;

// DEFINES
// Windows messages, three types (one per socket type)
#define WM_SOCKET_LISTEN (WM_USER + 1)
#define WM_SOCKET_LOCAL (WM_USER + 2)
#define WM_SOCKET_REMOTE_UDP (WM_USER + 3)
#define WM_SOCKET_REMOTE_TCP (WM_USER + 4)

// TCP flags
#define FLAG_ACK  0x10
#define FLAG_RST  0x04
#define FLAG_SYN  0x02
#define FLAG_FIN  0x01
#define FLAG_NONE 0x00

// Size of internal receive buffer - 1500 bytes works for Ethernet
#define RECV_BUF_SIZE 1500

// class defs
//  uniquely identify a connection between src and dst
struct Connection {
	const unsigned int addr_src;
	const unsigned int addr_dst;
	const unsigned short port_src;
	const unsigned short port_dst;

	Connection(const unsigned int addr_src, const unsigned int addr_dst, const unsigned short port_src, const unsigned short port_dst) :
		addr_src(addr_src), addr_dst(addr_dst), port_src(port_src), port_dst(port_dst) {
	}
};
// needed to allow map insert / find
static bool operator<(const Connection& l, const Connection& r) {
	return (l.addr_src < r.addr_src ||
		(l.addr_src == r.addr_src && l.addr_dst < r.addr_dst) ||
		(l.addr_src == r.addr_src && l.addr_dst == r.addr_dst && l.port_src < r.port_src) ||
		(l.addr_src == r.addr_src && l.addr_dst == r.addr_dst && l.port_src == r.port_src && l.port_dst < r.port_dst));
}

// info about a UDP connection - the socket, send-state, and a queue of packets to send
struct UDPState {
	const SOCKET sock_remote;
	queue< vector<char> > send_buf;
	bool ready;

	UDPState(const SOCKET sock_remote) :
		sock_remote(sock_remote), ready(false) {
	}
};
// details about a TCP connection, which is more involved than a UDP
struct TCPState {
	const SOCKET sock_remote;
	queue< vector<char> > send_buf;
	bool ready;

	enum State { LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_LOCAL, FIN_REMOTE } state;

	unsigned int local_seq; // the last byte we ack'd from local
	unsigned int remote_seq; // our sequence number, sent with every packet

	// Bytes to send back to the local client
	vector<char> recv_buf;
	unsigned short window;
	const unsigned short mss;

	TCPState(const SOCKET sock_remote, const unsigned short mss) :
		sock_remote(sock_remote), ready(false), state(LISTEN), local_seq(0), remote_seq(0), mss(mss) {
	}
};

// Local client we are talking SLIP with
struct Local {
	// socket state - TCP packet backlog to the remote
	queue< vector<char> > send_buf;
	bool ready;

	// holds incomplete incoming packets from client
	vector<char> buf;
	// SLIP escape signifier
	bool esc;

	// ID of last packet sent
	unsigned short packet_id;

	// proxied connections to remotes
	map<Connection, UDPState> udp;
	map<Connection, TCPState> tcp;

	Local() :
		ready(false), esc(false), packet_id(0) {
	}
};

// List of all connected "local" clients
static map<SOCKET, Local> locals;

// a reverse lookup for remote sockets
struct Reverse {
	const SOCKET sock_local;
	const Connection conn;

	Reverse(const SOCKET sock_local, const Connection conn) :
		sock_local(sock_local), conn(conn) {
	}
};
static map<SOCKET, Reverse> reverse_udp;
static map<SOCKET, Reverse> reverse_tcp;

// listen sockets for incoming clients
static SOCKET sock_listen = INVALID_SOCKET;

// globals
//  log file
static ofstream fLog;
//  packet log
static ofstream pLog;

//  App icon - shown in the dlg box but also on the systray
static HANDLE hIcon;

// ///////////////////////////////////////////////////////////////////////////
// helper and misc functions
// ///////////////////////////////////////////////////////////////////////////

// convert a wstr to a str... which we must do for TCHAR to write to ostream
static string tstrtostr(LPCTSTR tstr)
{
#ifdef _UNICODE
	const wstring wstr(tstr);
	if (wstr.empty()) return string();
	const int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], wstr.size(), NULL, 0, NULL, NULL);
	string strTo(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
#else
	return string(tstr);
#endif
}

// Display an error dialog-box with error code and readable error message.
static int ErrorBox(const HWND hWnd, LPCTSTR lpFunction, const int dwError)
{
	LPTSTR lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwError,
		0,
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	fLog << "ErrorBox: " << tstrtostr(lpFunction).c_str() << "(): " << tstrtostr(lpMsgBuf).c_str() << endl;

	// Display the error in a msgbox (title = function name), then free and return
	MessageBox(hWnd, lpMsgBuf, lpFunction, MB_ICONERROR);
	LocalFree(lpMsgBuf);
	return dwError;
}

// as above but call WSAGetLastError
static int ErrorBox(const HWND hWnd, LPCTSTR lpFunction) {
	// Retrieve the system error message for the most recent Winsock error code
	return ErrorBox(hWnd, lpFunction, WSAGetLastError());
}

// Write packet logging header info
static void LogPacketHeader(const unsigned int size) {
	// begin a packet log entry
	unsigned int temp;

	// timestamp
	const unsigned int ticks = GetTickCount();
	temp = ticks / 1000;
	pLog.write((char*)&temp, 4);
	temp = (ticks % 1000) * 1000;
	pLog.write((char*)&temp, 4);

	// packet size
	pLog.write((char*)&size, 4);
	pLog.write((char*)&size, 4);
}

// Send helper - send as many bytes as you can - if it would block return
static bool SendHelper(const SOCKET s, queue< vector<char> >& queue_data, bool& ready) {
	//	if (!ready) fLog << " in SendHelper but not Ready" << endl;
	//	if (queue_data.empty()) fLog << " in SendHelper but queue Empty" << endl;
	while (ready && !queue_data.empty()) {
		vector<char>& data = queue_data.front();
		int nBytesSent = 0;
		int nBytesToSend = data.size();

		//		fLog << "SendHelper(s = " << s << ", data.size() = " << data.size() << ")" << endl;

		do {
			//			fLog << " . Sending " << nBytesToSend << " beginning at " << nBytesSent;
			const int nBytesJustSent = send(s, &data[nBytesSent], nBytesToSend, 0);
			//			fLog << " ... managed " << nBytesJustSent << endl;
			if (nBytesJustSent != SOCKET_ERROR) {
				nBytesSent += nBytesJustSent;
				nBytesToSend -= nBytesJustSent;
			}
			else if (WSAGetLastError() == WSAEWOULDBLOCK) {
				// fewer bytes were sent because it would block
//				fLog << " ...> WSAEWOULDBLOCK, returning" << endl;

				// update data by shortening it - assuming anything was sent at all...
				if (nBytesSent)
					data = vector<char>(data.begin() + nBytesSent, data.end());

				// exit early
				ready = false;
				return true;
			}
			else {
				// different, major error in sending!
//				fLog << " ...> SOCKET ERROR, returning" << endl;
				return false;
			}
		} while (ready && nBytesToSend > 0);

		// if we reached here, pop the front off the queue and loop
		queue_data.pop();
	}

	return true;
}

// ///////////////////////////////////////////////////////////////////////////
// SOCKET CLEANUP
// ///////////////////////////////////////////////////////////////////////////

// Close a remote UDP socket and remove its entries from other structures
static void CloseRemoteUDPSocket(const SOCKET sock_remote, const SOCKET sock_local, const Connection& conn)
{
	closesocket(sock_remote);
	const map<SOCKET, Local>::iterator it = locals.find(sock_local);
	if (it != locals.end())
		it->second.udp.erase(conn);
	reverse_udp.erase(sock_remote);
}

// Close a remote TCP socket and remove its entries from other structures
static void CloseRemoteTCPSocket(const SOCKET sock_remote, const SOCKET sock_local, const Connection& conn)
{
	closesocket(sock_remote);
	const map<SOCKET, Local>::iterator it = locals.find(sock_local);
	if (it != locals.end())
		it->second.tcp.erase(conn);
	reverse_tcp.erase(sock_remote);
}

// Close a local socket and all its remote connections
static void CloseLocalSocket(const SOCKET sock_local, const Local& l)
{
	for (map<Connection, UDPState>::const_iterator udp = l.udp.begin(); udp != l.udp.end(); ++udp) {
		closesocket(udp->second.sock_remote);
		// bypass erasing from locals.udp as it's erased entirely later
		reverse_udp.erase(udp->second.sock_remote);
	}
	for (map<Connection, TCPState>::const_iterator tcp = l.tcp.begin(); tcp != l.tcp.end(); ++tcp) {
		closesocket(tcp->second.sock_remote);
		reverse_tcp.erase(tcp->second.sock_remote);
	}

	closesocket(sock_local);
	locals.erase(sock_local);
}

// Terminate all sockets and clear all data structures
static void DisableListenSocket(const SOCKET sock_listen)
{
	// Go through every local client and shut them down
	for (map<SOCKET, Local>::const_iterator it = locals.begin(); it != locals.end(); ++it) {
		for (map<Connection, UDPState>::const_iterator udp = it->second.udp.begin(); udp != it->second.udp.end(); ++udp)
			closesocket(udp->second.sock_remote);

		for (map<Connection, TCPState>::const_iterator tcp = it->second.tcp.begin(); tcp != it->second.tcp.end(); ++tcp)
			closesocket(tcp->second.sock_remote);

		closesocket(it->first);
	}

	closesocket(sock_listen);

	reverse_udp.clear();
	reverse_tcp.clear();
	locals.clear();
}

// ///////////////////////////////////////////////////////////////////////////
// LOCAL SOCKET
// ///////////////////////////////////////////////////////////////////////////

// ///////////////////////////////////
// SLIP functions - Sends a packet to a client (SLIP in fmt)
//  This effectively builds a fake TCP/IP packet w/ payload and flags, then send() to
//  the client - also escaping 0xC0 as needed

// SLIP encoding helper
static void SLIP(vector<char>& v, const char c)
{
	if (c == '\xC0') {
		v.push_back('\xDB');
		v.push_back('\xDC');
	}
	else if (c == '\xDB') {
		v.push_back('\xDB');
		v.push_back('\xDD');
	}
	else
		v.push_back(c);
}

// Add an IPv4 header to a packet vector
static void SLIPIPHeader(vector<char>& packet, const unsigned short len, const unsigned short id, const char proto, const unsigned int addr_src, const unsigned int addr_dst) {

	//
	LogPacketHeader(len);

	// IP header
	char ip[20] = {
		// version and length. DSCP and ECN
		(4 << 4) | 5, 0,
		// length
		len >> 8, len,
		// ID
		id >> 8, id,
		// Flags and Frag Offset (assume no fragments)
		0, 0,
		// TTL (always 64), Protocol
		'\x40', proto,
		// checksum (fill later)
		0, 0,
		// src addr
		addr_src >> 24, addr_src >> 16, addr_src >> 8, addr_src,
		// dst addr
		addr_dst >> 24, addr_dst >> 16, addr_dst >> 8, addr_dst
	};

	// calculate IP checksum
	{
		unsigned int checksum = 0;
		for (int i = 0; i < 20; i += 2)
			checksum += (((unsigned char)ip[i] << 8) | (unsigned char)ip[i + 1]);

		// carry handling
		while (checksum & 0xFFFF0000)
			checksum = (checksum >> 16) + (checksum & 0xFFFF);

		checksum = ~checksum;
		ip[10] = checksum >> 8;
		ip[11] = checksum;
	}

	// packet log IP header
	pLog.write(ip, 20);
	// add ip header to SLIP packet
	for (int i = 0; i < 20; i++)
		SLIP(packet, ip[i]);
}

static void SLIPPayload(vector<char>& packet, const vector<char>& payload)
{
	// log UDP payload
	if (!payload.empty())
		pLog.write(&payload[0], payload.size());
	pLog.flush();

	// add payload to SLIP packet
	for (vector<char>::const_iterator it = payload.begin(); it != payload.end(); ++it)
		SLIP(packet, *it);

	// SLIP frame end
	packet.push_back('\xC0');
}

// Encode a ICMP packet to SLIP and place it into the send buffer to the client
static bool SLIPICMPPacket(const SOCKET sock_local, Local& l,
	const unsigned int addr_src, const unsigned int addr_dst,
	const char type, const char code, const vector<char>& payload)
{
	// calculate complete packet size - 20 IP header, 4 ICMP header, payload size
	const unsigned short icmp_len = 4 + payload.size();
	const unsigned short packet_len = 20 + icmp_len;

	fLog << "SLIPICMPPacket(sock_local = " << sock_local << ", src = " << addr_src << ":" << ":" << addr_dst << ") size=" << payload.size() << endl;

	// ////////
	// compose packet
	vector<char> packet;
	// take a stab at an initial packet size (+1 for SLIP frame end)
	packet.reserve(packet_len + 1);

	// set up the two headers
	//  IP first
	SLIPIPHeader(packet, packet_len, l.packet_id, IPPROTO_ICMP, addr_src, addr_dst);
	l.packet_id++;

	// ICMP HEADER
	char icmp[4] = {
		// type and code
		type, code,
		// checksum (fill later)
		0, 0
	};

	// calculate checksum
	{
		unsigned int checksum = 0;

		// ICMP header
		for (int i = 0; i < 4; i += 2)
			checksum += (((unsigned char)icmp[i] << 8) | (unsigned char)icmp[i + 1]);

		// ICMP payload
		int shift = 0;
		for (vector<char>::const_iterator it = payload.begin(); it != payload.end(); ++it)
		{
			shift ^= 8;
			checksum += ((unsigned char)(*it) << shift);
		}

		// carry handling
		while (checksum & 0xFFFF0000)
			checksum = (checksum >> 16) + (checksum & 0xFFFF);

		checksum = ~checksum;
		icmp[2] = checksum >> 8;
		icmp[3] = checksum;
	}

	// log ICMP header
	pLog.write(icmp, 4);
	// add icmp header to SLIP packet
	for (int i = 0; i < 4; i++)
		SLIP(packet, icmp[i]);

	SLIPPayload(packet, payload);

	//	fLog << " . Prepared to send ICMP SLIP packet (size=" << packet.size() << ") to local client" << endl;

		// put the packet in the send-buffer and then attempt to send.
	l.send_buf.push(packet);
	return SendHelper(sock_local, l.send_buf, l.ready);
}

// Encode a UDP packet to SLIP and place it into the send buffer to the client
static bool SLIPUDPPacket(const SOCKET sock_local, Local& l,
	const unsigned int addr_src, const unsigned int addr_dst, const unsigned short port_src, const unsigned short port_dst,
	const vector<char>& payload)
{
	// calculate complete packet size - 20 IP header, 8 UDP header, payload size
	const unsigned short udp_len = 8 + payload.size();
	const unsigned short packet_len = 20 + udp_len;

	fLog << "SLIPUDPPacket(sock_local = " << sock_local << ", src = " << addr_src << ":" << port_src << ", dest = " << addr_dst << ":" << port_dst << ") size=" << payload.size() << endl;

	// ////////
	// compose packet
	vector<char> packet;
	// take a stab at an initial packet size (+1 for SLIP frame end)
	packet.reserve(packet_len + 1);

	// set up the two headers
	//  IP first
	SLIPIPHeader(packet, packet_len, l.packet_id, IPPROTO_UDP, addr_src, addr_dst);
	l.packet_id++;

	// UDP HEADER
	char udp[8] = {
		// src port -- remember packet is remote -> local
		port_src >> 8, port_src,
		// dst port
		port_dst >> 8, port_dst,
		// length
		udp_len >> 8, udp_len,
		// checksum (fill later)
		0, 0
	};

	// calculate checksum
	{
		unsigned int checksum = 0;
		// UDP pseudo-header
		// source addr and dest addr
		checksum += (addr_src >> 16);
		checksum += (addr_src & 0xFFFF);
		checksum += (addr_dst >> 16);
		checksum += (addr_dst & 0xFFFF);
		// reserved (0) and protocol
		checksum += IPPROTO_UDP;
		// "UDP Length" (header + body sizes)
		checksum += udp_len;

		// UDP header
		for (int i = 0; i < 8; i += 2)
			checksum += (((unsigned char)udp[i] << 8) | (unsigned char)udp[i + 1]);

		// UDP payload
		int shift = 0;
		for (vector<char>::const_iterator it = payload.begin(); it != payload.end(); ++it)
		{
			shift ^= 8;
			checksum += ((unsigned char)(*it) << shift);
		}

		// carry handling
		while (checksum & 0xFFFF0000)
			checksum = (checksum >> 16) + (checksum & 0xFFFF);

		checksum = ~checksum;
		udp[6] = checksum >> 8;
		udp[7] = checksum;
	}

	// log UDP header
	pLog.write(udp, 8);
	// add udp header to SLIP packet
	for (int i = 0; i < 8; i++)
		SLIP(packet, udp[i]);

	SLIPPayload(packet, payload);

	//	fLog << " . Prepared to send UDP SLIP packet (size=" << packet.size() << ") to local client" << endl;

		// put the packet in the send-buffer and then attempt to send.
	l.send_buf.push(packet);
	return SendHelper(sock_local, l.send_buf, l.ready);
}

// Encode a TCP packet to SLIP and place it into the send buffer to the client
static bool SLIPTCPPacket(const SOCKET sock_local, Local& l,
	const unsigned int addr_src, const unsigned int addr_dst, const unsigned short port_src, const unsigned short port_dst,
	const unsigned int seq_num, const unsigned int ack_num,
	const unsigned char flags, const vector<char>& payload)
{
	// calculate complete packet size - 20 IP header, 20 TCP header, payload size
	const unsigned short tcp_len = 20 + payload.size();
	const unsigned short packet_len = 20 + tcp_len;

	fLog << "SLIPTCPPacket(sock_local = " << sock_local << ", src = " << addr_src << ":" << port_src << ", dest = " << addr_dst << ":" << port_dst << ") size=" << payload.size() << endl;

	// ////////
	// compose packet
	vector<char> packet;
	// take a stab at an initial packet size (+1 for SLIP frame end)
	packet.reserve(packet_len + 1);

	// set up the two headers
	//  IP first
	SLIPIPHeader(packet, packet_len, l.packet_id, IPPROTO_TCP, addr_src, addr_dst);
	l.packet_id++;

	// TCP HEADER
	char tcp[20] = {
		// src port -- remember packet is remote -> local
		port_src >> 8, port_src,
		// dst port
		port_dst >> 8, port_dst,
		// seq. num - index of the first byte of this packet
		seq_num >> 24, seq_num >> 16, seq_num >> 8, seq_num,
		// ack num - next byte expected from remote
		ack_num >> 24, ack_num >> 16, ack_num >> 8, ack_num,
		// data offset and reserved, flags
		5 << 4, flags,
		// window (always accept unlimited)
		'\xFF', '\xFF',
		// checksum (fill later)
		0, 0,
		// URG ptr (always 0)
		0, 0
	};

	// calculate checksum
	{
		unsigned int checksum = 0;
		// TCP pseudo-header
		// source addr and dest addr
		checksum += (addr_src >> 16);
		checksum += (addr_src & 0xFFFF);
		checksum += (addr_dst >> 16);
		checksum += (addr_dst & 0xFFFF);
		// reserved (0) and protocol
		checksum += IPPROTO_TCP;
		// "TCP Length"
		checksum += tcp_len;

		// TCP header
		for (int i = 0; i < 20; i += 2)
			checksum += (((unsigned char)tcp[i] << 8) | (unsigned char)tcp[i + 1]);

		// TCP payload
		int shift = 0;
		for (vector<char>::const_iterator it = payload.begin(); it != payload.end(); ++it)
		{
			shift ^= 8;
			checksum += ((unsigned char)(*it) << shift);
		}

		// carry handling
		while (checksum & 0xFFFF0000)
			checksum = (checksum >> 16) + (checksum & 0xFFFF);

		checksum = ~checksum;
		tcp[16] = checksum >> 8;
		tcp[17] = checksum;
	}

	// log TCP header
	pLog.write(tcp, 20);
	for (int i = 0; i < 20; i++)
		SLIP(packet, tcp[i]);

	SLIPPayload(packet, payload);

	//	fLog << " . Prepared to send TCP SLIP packet (size=" << packet.size() << ") to local client" << endl;

		// put the packet in the send-buffer and then attempt to send.
	l.send_buf.push(packet);
	return SendHelper(sock_local, l.send_buf, l.ready);
}

// ///////////////////////////////////
// Recv functions - Got a packet from Local, now decide what to do with it

// Read an ICMP packet from the Local client and send it to a Remote
static void RecvLocalICMP(const HWND hDlg, const SOCKET sock_local, Local& l) {
	// start of ICMP header
	const unsigned short protoOffset = ((unsigned char)l.buf[0] & 0xF) * 4;

	// get the source IP / dest IP
	const unsigned int addr_src = ntohl(*(unsigned int*)&l.buf[12]);
	const unsigned int addr_dst = ntohl(*(unsigned int*)&l.buf[16]);

	// (Options parsing ignored for ICMP)
	fLog << "RecvLocalICMP, src = " << addr_src << ", dst = " << addr_dst << endl;

	// Only support ECHO REQUEST (type 8)
	if (l.buf[protoOffset] != 8) {
		fLog << " . Ignoring local ICMP message type 0x" << hex << l.buf[protoOffset] << dec << endl;
		return;
	}

	// TODO: Should use the ICMP.DLL feature to send ICMP messages, possibly in own thread.
	//  For now, fake a ping response as always working.
	SLIPICMPPacket(sock_local, l, addr_dst, addr_src, 0, l.buf[protoOffset + 1], vector<char>(l.buf.begin() + protoOffset + 4, l.buf.end()));
}

// Read a UDP packet from the Local client and send it to a Remote
static void RecvLocalUDP(const HWND hDlg, const SOCKET sock_local, Local& l) {
	// start of UDP header
	const unsigned short protoOffset = ((unsigned char)l.buf[0] & 0xF) * 4;

	// first: get the source IP / port / dest IP / port and look them up
	const Connection conn = Connection(
		ntohl(*(unsigned int*)&l.buf[12]),
		ntohl(*(unsigned int*)&l.buf[16]),
		ntohs(*(unsigned short*)&l.buf[protoOffset]),
		ntohs(*(unsigned short*)&l.buf[protoOffset + 2])
	);

	// (Options parsing ignored for UDP)
	fLog << "RecvLocalUDP, src = " << conn.addr_src << ":" << conn.port_src << ", dst= " << conn.addr_dst << ":" << conn.port_dst << endl;

	map<Connection, UDPState>::iterator it = l.udp.find(conn);

	if (it == l.udp.end()) {
		// This connection hasn't been proxied yet
		fLog << "Creating / binding new socket" << endl;

		// build remote address off the incoming packet
		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(conn.addr_dst);
		addr.sin_port = htons(conn.port_dst);

		const SOCKET sock_remote = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock_remote == INVALID_SOCKET)
		{
			// failed to get a socket, just drop it
			ErrorBox(hDlg, _T("socket"));
			return;
		}

		if (WSAAsyncSelect(sock_remote, hDlg, WM_SOCKET_REMOTE_UDP, FD_WRITE | FD_READ) == SOCKET_ERROR) {
			// failed to set this up for select(), close it and bail
			ErrorBox(hDlg, _T("WSAAsyncSelect"));
			closesocket(sock_remote);
			return;
		}

		if (connect(sock_remote, (const sockaddr*)(&addr), sizeof(addr)) == SOCKET_ERROR) {
			// couldn't bind() to address, close and return
			ErrorBox(hDlg, _T("connect"));
			closesocket(sock_remote);
			return;
		}

		// made conn request - log the details
		it = l.udp.insert(make_pair(conn, UDPState(sock_remote))).first;
		// and the reverse-lookup
		reverse_udp.insert(make_pair(sock_remote, Reverse(sock_local, conn)));
	}

	// send data to remote
	UDPState& udp = it->second;
	const unsigned short payloadStart = protoOffset + 8;

	udp.send_buf.push(vector<char>(l.buf.begin() + payloadStart, l.buf.end()));
	if (!SendHelper(udp.sock_remote, udp.send_buf, udp.ready)) {
		// error sending UDP packets for some reason
		ErrorBox(hDlg, _T("send"));

		CloseRemoteUDPSocket(udp.sock_remote, sock_local, conn);
	}
}

static void RecvLocalTCP(const HWND hDlg, const SOCKET sock_local, Local& l) {
	// start of TCP header
	const unsigned short protoOffset = ((unsigned char)l.buf[0] & 0xF) * 4;

	// first: get the source IP / port / dest IP / port and look them up
	const Connection conn = Connection(
		ntohl(*(unsigned int*)&l.buf[12]),
		ntohl(*(unsigned int*)&l.buf[16]),
		ntohs(*(unsigned short*)&l.buf[protoOffset]),
		ntohs(*(unsigned short*)&l.buf[protoOffset + 2])
	);

	// other incoming info from the TCP packet
	// seq. and ack. num
	const unsigned int seq_num = ntohl(*(unsigned int*)&l.buf[protoOffset + 4]);
	const unsigned int ack_num = ntohl(*(unsigned int*)&l.buf[protoOffset + 8]);
	// start of Data after TCP header
	const unsigned short dataOffset = ((unsigned char)l.buf[protoOffset + 12] >> 4) * 4;
	// flags
	const unsigned char flags = (unsigned char)l.buf[protoOffset + 13];
	// 2 bytes window size
	const unsigned short window = ntohs(*(unsigned short*)&l.buf[protoOffset + 14]);
	// 2 bytes checksum, ignored
	// 2 bytes URG pointer, ignored

	// TCP options parsing
	// defaults
	unsigned short mss = 536;

	// parse beginning 20 bytes after the start of TCP header, until data is reached
	unsigned short j = protoOffset + 20;
	while (j < protoOffset + dataOffset) {
		// end-of-block
		if (l.buf[j] == 0) break;
		// NOP
		if (l.buf[j] == 1) { j++; continue; }
		// kind, length, mss
		if (l.buf[j] == 2) {
			if (l.buf[j + 1] == 4) {
				mss = ntohs(*(unsigned short*)&l.buf[j + 2]);
			}
		}
		// regardless advance length
		j += l.buf[j + 1];
	}

	// data part of packet
	const unsigned short payloadStart = dataOffset + protoOffset;
	const unsigned short payloadSize = l.buf.size() - payloadStart;

	fLog << "RecvLocalTCP, src = " << conn.addr_src << ":" << conn.port_src << ", dst= " << conn.addr_dst << ":" << conn.port_dst << endl;
	fLog << " . protoOffset = " << protoOffset << ", dataOffset = " << dataOffset << ", seq_num " << seq_num << ", ack_num " << ack_num << endl;

	map<Connection, TCPState>::iterator it = l.tcp.find(conn);

	if (it == l.tcp.end()) {
		// We don't know about this yet, so let's create an entry.
		// This connection hasn't been proxied yet
		fLog << "Creating / binding new socket" << endl;

		const SOCKET sock_remote = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock_remote == INVALID_SOCKET)
		{
			// failed to get a socket, just drop it I guess?
			ErrorBox(hDlg, _T("socket"));
			return;
		}

		if (WSAAsyncSelect(sock_remote, hDlg, WM_SOCKET_REMOTE_TCP, FD_CLOSE | FD_CONNECT | FD_WRITE | FD_READ) == SOCKET_ERROR) {
			ErrorBox(hDlg, _T("WSAAsyncSelect"));
			closesocket(sock_remote);
			return;
		}

		// don't connect() yet, save that for SYN handling

		// made conn request - log the details
		it = l.tcp.insert(make_pair(conn, TCPState(sock_remote, mss))).first;
		// and the reverse-lookup
		reverse_tcp.insert(make_pair(sock_remote, Reverse(sock_local, conn)));
	}
	TCPState& tcp = it->second;

	// update TCP window to current packet's setting
	tcp.window = window;

	// giant state machine for TCP incoming packets
	//  actually it's inside-out and based on the packet flags instead of the states - more concise
	if (flags & FLAG_RST) {
		// forcibly closes our connection no matter the state
		fLog << " . . RST packet: closing remote connection" << endl;
		CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
	}
	else if (flags & FLAG_SYN) {
		fLog << " . . SYN packet: ";
		switch (tcp.state) {
		case TCPState::State::LISTEN:
			// SYN packet - trying to make connection.  We proxy this into a new socket,
			//  then reply depending on success / failure
			fLog << "opening new connection" << endl;

			// copy initial ack_num
			tcp.local_seq = seq_num + 1;

			// remote has no seq until connection completes

			// build remote address off the incoming packet
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(conn.addr_dst);
			addr.sin_port = htons(conn.port_dst);

			if (connect(tcp.sock_remote, (const sockaddr*)(&addr), sizeof(addr)) == SOCKET_ERROR &&
				WSAGetLastError() != WSAEWOULDBLOCK) {
				// this always returns SOCKET_ERROR but we care about whether it's WSAEWOULDBLOCK or something else
				ErrorBox(hDlg, _T("connect"));
				CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			}
			else {
				// advance state
				tcp.state = TCPState::State::SYN_SENT;
			}
			break;

		case TCPState::State::SYN_SENT:
		case TCPState::State::SYN_RECEIVED:
			fLog << "Duplicate SYN?" << endl;
			// Another SYN packet - possibly a duplicate, or old
			//  we already have begun opening the remote connection though...
			// just update our seq.num and let local figure it out
			tcp.local_seq = seq_num + 1;
			break;

		default:
			// all other states, let's ignore this entirely.  we're already synchronized.
			// TODO: I _think_ you're actually supposed to repeat ack here
			fLog << "Out-of-order SYN" << endl;
			break;
		}
	}
	else if (flags & FLAG_FIN) {
		switch (tcp.state) {
		case TCPState::State::LISTEN:
			// client trying to FIN something before we're ready.  come back when you've got a SYN.
			fLog << "FIN before SYN" << endl;
			CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			break;

		case TCPState::State::SYN_SENT:
		case TCPState::State::SYN_RECEIVED:
			// definitely wrong
			fLog << "FIN during SYN" << endl;
			SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
				tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());
			CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			break;

		case TCPState::State::ESTABLISHED:
			// TODO validate sequence number
			fLog << "FIN received during normal conn" << endl;
			// remote is done sending data.  ACK them, and half-close the remote.
			tcp.local_seq++;
			SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
				tcp.remote_seq, tcp.local_seq, FLAG_ACK, vector<char>());

			if (shutdown(tcp.sock_remote, 1) != 0) {
				ErrorBox(hDlg, _T("shutdown"));
				CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			}
			else {
				// state is "client sent their FIN, got ACK'd, waiting for server FIN"
				tcp.state = TCPState::State::FIN_LOCAL;
			}
			break;

		case TCPState::State::FIN_LOCAL:
			// FIN when already in FIN_LOCAL is ignorable
			break;

		case TCPState::State::FIN_REMOTE:
			// TODO validate sequence number
			fLog << "FIN received during half-opened conn" << endl;
			// The remote has already shut down their half, now the client is done.
			//  ACK this and then close everything.
			tcp.local_seq++;
			SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
				tcp.remote_seq, tcp.local_seq, FLAG_ACK, vector<char>());

			shutdown(tcp.sock_remote, 2);
			CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			break;

		}
	}
	else if (flags & FLAG_ACK) {
		switch (tcp.state) {
		case TCPState::State::LISTEN:
			// client trying to ACK something before we're ready.  come back when you've got a SYN.
			fLog << "ACK before SYN" << endl;
			CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			break;

		case TCPState::State::SYN_SENT:
			// definitely wrong
			fLog << "ACK before SYN_RECEIVED" << endl;
			SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
				tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());
			CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
			break;

		case TCPState::State::SYN_RECEIVED: {
			// TODO check sequence number
			fLog << "ACK response to SYN-ACK" << endl;
			tcp.state = TCPState::State::ESTABLISHED;

			// if data's been piling up in the queue we can send up to window bytes back, in chunks of MSS
			unsigned int limit = min(tcp.recv_buf.size(), tcp.window);
			unsigned int offset = 0;
			while (offset < limit) {
				int bufSize = min(limit - offset, tcp.mss);
				SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
					tcp.remote_seq + offset, tcp.local_seq, FLAG_ACK, vector<char>(tcp.recv_buf.begin() + offset, tcp.recv_buf.begin() + offset + bufSize));
				offset += bufSize;
			}

			// set a timer for TCP retransmission
//			SetTimer(hDlg, tcp.sock_remote, 500, NULL);
			break;
		}

		case TCPState::State::ESTABLISHED: {

			// Two things happen when we get an ACK packet in ESTABLISHED state:
			// . a packet may have payload data, which we should send and ACK
			// TODO this doesn't work with TCP keepalive, which needs to reply to empty packets after some time
			if (seq_num == tcp.local_seq)
			{
				// does it have data attached?
				if (payloadSize > 0) {
					// put the incoming data into the queue to pass along
					tcp.send_buf.push(vector<char>(l.buf.begin() + payloadStart, l.buf.end()));
					if (!SendHelper(tcp.sock_remote, tcp.send_buf, tcp.ready)) {
						// serious error
						ErrorBox(hDlg, _T("send"));

						SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
							ack_num, tcp.local_seq, FLAG_RST, vector<char>());

						CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
						break;
					}

					// ack whatever they sent us anyway.  use the seqnum of our next send
					tcp.local_seq = seq_num + payloadSize;
					unsigned int remote_seq = tcp.remote_seq + min(tcp.window, tcp.recv_buf.size());
					SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
						remote_seq, tcp.local_seq, FLAG_ACK, vector<char>());
				}
			}
			else if (seq_num < tcp.local_seq && payloadSize > 0) {
				// we already saw that!  stop it
				fLog << " Replying to previously ack'd repeat send of " << payloadSize << " bytes" << endl;
				unsigned int remote_seq = tcp.remote_seq + min(tcp.window, tcp.recv_buf.size());
				SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
					remote_seq, tcp.local_seq, FLAG_ACK, vector<char>());
			}
			else {
				fLog << " SEQ data out of order, expect retransmit I guess" << endl;
			}

			// . an ACK can move remote_seq forward, and then maybe allow more in the window
			int diff = ack_num - tcp.remote_seq;
			if (diff > 0) {
				// ACK number moved forward
				if (diff <= tcp.recv_buf.size()) {

					fLog << " ACK an additional " << diff << " bytes, advancing" << endl;

					// throw out diff bytes from remote -> local TCP buffer
					tcp.remote_seq = ack_num;
					tcp.recv_buf = vector<char>(tcp.recv_buf.begin() + diff, tcp.recv_buf.end());

					if (tcp.recv_buf.empty()) {
						// kill any TCP retransmit timer, remote has ack'd everything we had
//						KillTimer(hDlg, tcp.sock_remote);
					}
					else {
						// since we removed diff bytes from the head, we can send diff bytes at the end

						unsigned int offset = tcp.window - diff;
						unsigned int limit = min(tcp.recv_buf.size(), tcp.window);
						fLog << "Recv buf not empty, we can send from " << offset << endl;
						while (offset < limit) {
							int bufSize = min(limit - offset, tcp.mss);
							SLIPTCPPacket(sock_local, l, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
								tcp.remote_seq + offset, tcp.local_seq, FLAG_ACK, vector<char>(tcp.recv_buf.begin() + offset, tcp.recv_buf.begin() + offset + bufSize));
							offset += bufSize;
						}

						// reset a timer for TCP retransmission
//							SetTimer(hDlg, tcp.sock_remote, 500, NULL);
					}
				}
				else {
					fLog << " ACK in the future (" << diff << "), ignoring" << endl;
				}
			}
			else {
				fLog << " ACK data in the past (" << diff << ", ignoring" << endl;
			}

			break;
		}
		case TCPState::State::FIN_LOCAL:
		case TCPState::State::FIN_REMOTE:
			// ACK when in a FIN state.  These are both ignorable, FIN handling is done outside this.
			fLog << "ACK received during FIN state" << endl;
			break;
		}
	}
	else {
		// all other unflagged packets
		fLog << "Packet without flags?" << endl;
	}
}

// Handles a WSAAsyncSelect message on a Local socket
static void HandleLocalSocket(const HWND hDlg, const WPARAM sock_local, const LPARAM event)
{
	//	fLog << "HandleLocalSocket ( socket " << sock_local << " ) ";

	const map<SOCKET, Local>::iterator it = locals.find(sock_local);
	if (it == locals.end()) {
		// didn't find it? that's odd, this should never happen
		MessageBox(hDlg, _T("Unknown socket?"), NULL, MB_ICONERROR);
		// well, try to close it anyway, maybe it'll go away
		closesocket(sock_local);
		return;
	}
	Local& l = it->second;

	const unsigned short error = WSAGETSELECTERROR(event);
	if (error) {
		ErrorBox(hDlg, _T("WSAGETSELECTERROR(WM_SOCKET_LOCAL)"), error);

		// delete the client - which includes the connected sockets
		CloseLocalSocket(sock_local, l);
		return;
	}

	// New data waiting, or this socket was closed.
	switch (WSAGETSELECTEVENT(event))
	{
	case FD_READ:
	{
		//		fLog << " . FD_READ" << endl;

		char recvbuf[RECV_BUF_SIZE];
		const int byteCount = recv(sock_local, recvbuf, sizeof(recvbuf), 0);

		if (byteCount == SOCKET_ERROR) {
			// ideally we don't call recv() with nothing available - that's the point of FD_READ -
			//  but if it does happen we don't want to kill the connection
			if (WSAGetLastError() != WSAEWOULDBLOCK) {
				ErrorBox(hDlg, _T("recv() - negative result"));
				CloseLocalSocket(sock_local, l);
			}
			break;
		}

		if (byteCount > 0) {
			//			fLog << " . Got " << byteCount << " bytes... buf-state " << l.buf.size() << ", esc=" << l.esc << endl;
			for (int i = 0; i < byteCount; i++) {
				//				fLog << " [" << hex << (unsigned int)(recvbuf[i] & 0xFF) << dec << "]";
								// SLIP DECODER
				if (l.esc) {
					// currently processing ESC char from client
					if (recvbuf[i] == '\xDC')
						l.buf.push_back('\xC0');
					else if (recvbuf[i] == '\xDD')
						l.buf.push_back('\xDB');
					else {
						// Local sent 0xDB and didn't follow with 0xDC nor 0xDD - this is a SLIP error!
						//  Act as though esc. was unintentional.  This will probably result in a malformed packet.
//						fLog << " SLIP error............" << endl;
						l.buf.push_back('\xDB');
						l.buf.push_back(recvbuf[i]);
					}
					l.esc = false;
				}
				else if (recvbuf[i] == '\xDB') {
					// begin escape sequence
					l.esc = true;
				}
				else if (recvbuf[i] == '\xC0') {
					// frame end...
					if (l.buf.size() > 0) {
						// log
						fLog << " . Received complete packet!" << endl;

						// packet log
						LogPacketHeader(l.buf.size());
						pLog.write(&l.buf[0], l.buf.size());
						pLog.flush();

						// packet wasn't empty.  Check if it's well-formed and a minimal 20 bytes (IP header size), process if so.
						if (l.buf.size() < 20 || l.buf.size() != ntohs(*(unsigned short*)&l.buf[2])) {
							fLog << " . . Buf size is " << l.buf.size() << " while expected size is " << ntohs(*(unsigned short*)&l.buf[2]) << endl;
							// drop bad packet
							//MessageBox(hDlg, TEXT("Malformed packet from client"), NULL, MB_OK);
						}
						else {
							if (((unsigned char)l.buf[0] >> 4) != 4) {
								// not ipv4... can't handle those packets
								fLog << " ---- not ipv4?" << endl;
							}
							else {
								// protocol in byte 9
								if (l.buf[9] == IPPROTO_ICMP) {
									RecvLocalICMP(hDlg, sock_local, l);
								}
								if (l.buf[9] == IPPROTO_UDP) {
									RecvLocalUDP(hDlg, sock_local, l);
								}
								else if (l.buf[9] == IPPROTO_TCP) {
									RecvLocalTCP(hDlg, sock_local, l);
								}
								else {
									fLog << " -- unsupported protocol " << (unsigned short)l.buf[9] << endl;
								}
							}
						}

						// all done, clear buffer for next packet
						//l.esc = false;
						l.buf.clear();
					}
				}
				else {
					// all other cases - normal copy char to buffer
					l.buf.push_back(recvbuf[i]);
				}
			}
		}
		else if (byteCount == 0) {
			// client closed the connection
			fLog << "FD_READ: recv() == 0: Remote closed" << endl;
			CloseLocalSocket(sock_local, l);
		}
		break;
	}

	case FD_WRITE:
		//		fLog << "Ready to write to " << sock_local << "..." << endl;
		l.ready = true;

		// try to empty any pending buffer contents
		if (!SendHelper(sock_local, l.send_buf, l.ready)) {
			// serious error
			ErrorBox(hDlg, _T("send"));

			// drop client
			CloseLocalSocket(sock_local, l);
		}
		break;

	case FD_CLOSE:
		// client closed the connection
		fLog << "FD_CLOSE: Local closed" << endl;
		CloseLocalSocket(sock_local, l);
		break;
	}
}

// ///////////////////////////////////////////////////////////////////////////
// REMOTE SOCKET
// ///////////////////////////////////////////////////////////////////////////

// Packet arrival from a remote UDP host - should be forwarded to the Local across TCP
static void HandleRemoteUDP(const HWND hDlg, const WPARAM sock_remote, const LPARAM event)
{
	// search for this socket in the remote-connection info
	const map<SOCKET, Reverse>::iterator reverse = reverse_udp.find(sock_remote);
	if (reverse == reverse_udp.end()) {
		// didn't find it? that's odd, this should never happen
		MessageBox(hDlg, _T("Unknown remote UDP socket?"), NULL, MB_ICONERROR);
		// well, try to close it anyway, maybe it'll go away
		closesocket(sock_remote);
		return;
	}

	// unpack a few things
	const SOCKET sock_local = reverse->second.sock_local;
	const Connection& conn = reverse->second.conn;

	const unsigned short error = WSAGETSELECTERROR(event);
	if (error) {
		ErrorBox(hDlg, _T("WSAGETSELECTERROR(WM_SOCKET_REMOTE_UDP)"), error);
		CloseRemoteUDPSocket(sock_remote, sock_local, conn);
		return;
	}

	const map<SOCKET, Local>::iterator it_local = locals.find(sock_local);
	if (it_local == locals.end())
	{
		// this should never happen...
		fLog << "ERROR: got Remote UDP without matching Local" << endl;
		CloseRemoteUDPSocket(sock_remote, sock_local, conn);
		return;
	}
	Local& local = it_local->second;
	const map<Connection, UDPState>::iterator it_udp = local.udp.find(conn);
	if (it_udp == local.udp.end())
	{
		// should also never happen
		fLog << "ERROR: no local UDPstate for conn" << endl;
		CloseRemoteUDPSocket(sock_remote, sock_local, conn);
		return;
	}
	UDPState& udp = it_udp->second;

	// New data waiting, or this socket was closed.
	switch (WSAGETSELECTEVENT(event))
	{
	case FD_READ: {
		char recvbuf[RECV_BUF_SIZE];
		const int byteCount = recv(sock_remote, recvbuf, sizeof(recvbuf), 0);
		if (byteCount == SOCKET_ERROR) {
			// ideally we don't call recv() with nothing available - that's the point of FD_READ -
			//  but if it does happen we don't want to kill the connection
			if (WSAGetLastError() != WSAEWOULDBLOCK) {
				ErrorBox(hDlg, _T("recv() - negative result"));
				CloseRemoteUDPSocket(sock_remote, sock_local, conn);
			}
			break;
		}

		// we have a buffer.  pass this to local client
		SLIPUDPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src, vector<char>(recvbuf, recvbuf + byteCount));
		break;
	}

	case FD_WRITE:
		fLog << "Ready to write to " << sock_remote << "..." << endl;

		udp.ready = true;

		// try to empty any pending buffer contents
		if (!SendHelper(sock_remote, udp.send_buf, udp.ready)) {
			// serious error
			ErrorBox(hDlg, _T("send"));
			CloseRemoteUDPSocket(sock_remote, sock_local, conn);
		}
		break;
	}
}

// Handles a socket event from a Remote TCP connection.  This should be proxied over to the local TCP.
static void HandleRemoteTCP(const HWND hDlg, const WPARAM sock_remote, const LPARAM event)
{
	// search for this socket in the remote-connection info
	const map<SOCKET, Reverse>::iterator reverse = reverse_tcp.find(sock_remote);
	if (reverse == reverse_tcp.end()) {
		// didn't find it? that's odd, this should never happen
		MessageBox(hDlg, _T("Unknown remote TCP socket?"), NULL, MB_ICONERROR);
		// well, try to close it anyway, maybe it'll go away
		closesocket(sock_remote);
		return;
	}

	// unpack a few things
	const SOCKET sock_local = reverse->second.sock_local;
	const Connection& conn = reverse->second.conn;

	const map<SOCKET, Local>::iterator it_local = locals.find(sock_local);
	if (it_local == locals.end())
	{
		// this should never happen...
		fLog << "ERROR: got Remote TCP without matching Local" << endl;
		CloseRemoteTCPSocket(sock_remote, sock_local, conn);
		return;
	}
	Local& local = it_local->second;
	const map<Connection, TCPState>::iterator it_tcp = local.tcp.find(conn);
	if (it_tcp == local.tcp.end())
	{
		// should also never happen
		fLog << "ERROR: no local TCPstate for conn" << endl;
		CloseRemoteTCPSocket(sock_remote, sock_local, conn);
		return;
	}
	TCPState& tcp = it_tcp->second;

	const unsigned short error = WSAGETSELECTERROR(event);
	if (error) {
		ErrorBox(hDlg, _T("WSAGETSELECTERROR(WM_SOCKET_REMOTE_TCP)"), error);

		// Send an RST if some kind of major error occurs
		SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
			tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());
		// close socket and drop the linkage in maps
		CloseRemoteTCPSocket(sock_remote, sock_local, conn);
		return;
	}

	// New data waiting, or this socket was closed.
	switch (WSAGETSELECTEVENT(event))
	{
	case FD_CONNECT:
		fLog << "CONNECT: Remote connected." << endl;
		// SYN packet can be ACK'd and we can advance the state to half-open (awaiting ACK of our seqnum)
		//  (if this failed it was already handled by the WSAGETSELECT error above)
		if (tcp.state == TCPState::State::SYN_SENT) {
			tcp.remote_seq = rand() | (rand() << 15) | (rand() << 30);
			fLog << " sending SYN-ACK to conn, w/ ts seq_num = " << tcp.local_seq << ", " << tcp.remote_seq << endl;
			SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
				tcp.remote_seq, tcp.local_seq, FLAG_SYN | FLAG_ACK, vector<char>());
			tcp.remote_seq++;
			tcp.state = TCPState::State::SYN_RECEIVED;
		}
		else {
			// TCP out of order?! (should send RST?)
			CloseRemoteTCPSocket(sock_remote, sock_local, conn);
		}
		break;

	case FD_READ: {
		char recvbuf[RECV_BUF_SIZE];

		const int byteCount = recv(sock_remote, recvbuf, sizeof(recvbuf), 0);
		//		fLog << "FD_RECV: got " << byteCount << " bytes" << endl;
		if (byteCount == SOCKET_ERROR) {
			// ideally we don't call recv() with nothing available - that's the point of FD_READ -
			//  but if it does happen we don't want to kill the connection
			if (WSAGetLastError() != WSAEWOULDBLOCK) {
				// probably should RST here
				SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
					tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());

				ErrorBox(hDlg, _T("recv() - negative result"));
				CloseRemoteUDPSocket(sock_remote, sock_local, conn);
			}
			break;
		}
		else if (byteCount > 0) {
			// we have a buffer.  better stash this away with the local client
			int offset = tcp.recv_buf.size();
			tcp.recv_buf.insert(tcp.recv_buf.end(), recvbuf, recvbuf + byteCount);

			if (tcp.state == TCPState::State::ESTABLISHED ||
				tcp.state == TCPState::State::FIN_LOCAL) {

				// we could maybe send this to the client, if they're still in ESTABLISHED or FIN_LOCAL state (able to get data)
				unsigned int limit = min(tcp.recv_buf.size(), tcp.window);
				while (offset < limit) {
					int bufSize = min(limit - offset, tcp.mss);
					SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
						tcp.remote_seq + offset, tcp.local_seq, FLAG_ACK, vector<char>(tcp.recv_buf.begin() + offset, tcp.recv_buf.begin() + offset + bufSize));
					offset += bufSize;
				}

				// set a timer for TCP retransmission
				// SetTimer(hDlg, tcp.sock_remote, 500, NULL);
			}
		}
		else if (byteCount == 0) {
			// This indicates remote closure.  Depending on the state, this could mean various things.
			if (tcp.state == TCPState::State::ESTABLISHED) {
				// Remote is done sending data and we should FIN in that direction.
				tcp.remote_seq++;
				SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
					tcp.remote_seq, tcp.local_seq, FLAG_FIN, vector<char>());

				if (shutdown(tcp.sock_remote, 0) != 0) {
					ErrorBox(hDlg, _T("shutdown"));
					CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
				}
				else {
					// state is "client sent their FIN, got ACK'd, waiting for server FIN"
					tcp.state = TCPState::State::FIN_REMOTE;
				}
				break;
			}
			else if (tcp.state == TCPState::State::FIN_LOCAL) {
				// the client already shut their end down, so we can basically terminate here.
				// Remote is done sending data and we should FIN in that direction.
				tcp.remote_seq++;
				SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
					tcp.remote_seq, tcp.local_seq, FLAG_FIN, vector<char>());

				shutdown(tcp.sock_remote, 2);
				CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
				break;
			}
			else {
				// no idea, just close it
				SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
					tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());
				CloseRemoteTCPSocket(tcp.sock_remote, sock_local, conn);
				break;
			}
		}
		break;
	}
	case FD_WRITE:
		fLog << "FD_WRITE: Ready to write to " << sock_remote << "..." << endl;
		tcp.ready = true;

		// try to empty any pending buffer contents
		if (!SendHelper(sock_remote, tcp.send_buf, tcp.ready)) {
			// serious error
			ErrorBox(hDlg, _T("send"));

			// probably should RST here
			SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
				tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());

			CloseRemoteTCPSocket(sock_remote, sock_local, conn);
		}
		break;

	case FD_CLOSE:
		fLog << "FD_CLOSE.  Sending RST" << endl;
		// TODO - should FIN here
		// TODO - TODO - should recv() until getting 0 here
		SLIPTCPPacket(sock_local, local, conn.addr_dst, conn.addr_src, conn.port_dst, conn.port_src,
			tcp.remote_seq, tcp.local_seq, FLAG_RST, vector<char>());
		CloseRemoteTCPSocket(sock_remote, sock_local, conn);
		break;
	}
}

// ///////////////////////////////////////////////////////////////////////////
// LISTEN SOCKET
// ///////////////////////////////////////////////////////////////////////////

// Sets up a listen socket and registers it to take new conns from local-clients
static SOCKET EnableListenSocket(const HWND hDlg, const unsigned short port, const bool listenAny)
{
	// let's set up a listening socket
	const SOCKET sock_listen = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock_listen == INVALID_SOCKET)
	{
		ErrorBox(hDlg, _T("socket"));
		SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("Error in socket() call."));
		return INVALID_SOCKET;
	}

	// try to register for asynchronous messages
	if (WSAAsyncSelect(sock_listen, hDlg, WM_SOCKET_LISTEN, FD_ACCEPT) == SOCKET_ERROR) {
		ErrorBox(hDlg, _T("WSAAsyncSelect"));
		closesocket(sock_listen);

		SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("Error in WSAAsyncSelect() call."));
		return INVALID_SOCKET;
	}

	// set up the listening address info
	SOCKADDR_IN InternetAddr;
	InternetAddr.sin_family = AF_INET;
	// TODO - a checkbox for listen_any vs listen_loopback
	InternetAddr.sin_addr.s_addr = htonl(listenAny ? INADDR_ANY : INADDR_LOOPBACK);
	InternetAddr.sin_port = htons(port);

	if (bind(sock_listen, (struct sockaddr*)&InternetAddr, sizeof(InternetAddr)) == SOCKET_ERROR) {
		ErrorBox(hDlg, _T("bind"));
		closesocket(sock_listen);

		SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("Error in bind() call."));
		return INVALID_SOCKET;
	}

	if (listen(sock_listen, SOMAXCONN) == SOCKET_ERROR) {
		ErrorBox(hDlg, _T("listen"));
		closesocket(sock_listen);

		SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("Error in listen() call."));
		return INVALID_SOCKET;
	}

	return sock_listen;
}

// Handles a socket event on the Listen Socket.  Usually this means accept() a new connection from a Local.
static bool HandleListenSocket(const HWND hDlg, const WPARAM sock_listen, const LPARAM event)
{
	const unsigned short error = WSAGETSELECTERROR(event);
	if (error) {
		// according to Winsock documentation, this never happens - so if it DOES, it's an exceptional event
		ErrorBox(hDlg, _T("WSAGETSELECTERROR(WM_SOCKET_LISTEN)"), error);

		// shut everything down
		DisableListenSocket(sock_listen);

		return false;
	}

	// A new connection
	//  Attempt to Accept.
	if (WSAGETSELECTEVENT(event) == FD_ACCEPT)
	{
		fLog << " . FD_ACCEPT" << endl;
		const SOCKET sock_new = accept(sock_listen, NULL, NULL);
		if (sock_new == INVALID_SOCKET)
		{
			// a failure to accept is not fatal to the listen_sock
			ErrorBox(hDlg, _T("accept()"));
		}
		else if (WSAAsyncSelect(sock_new, hDlg, WM_SOCKET_LOCAL, FD_CLOSE | FD_WRITE | FD_READ) == SOCKET_ERROR) {
			ErrorBox(hDlg, _T("WSAAsyncSelect"));
			closesocket(sock_new);
		}
		else {
			// A new local client is here.
			fLog << " . Socket number " << sock_new << " connected" << endl;

			// disable Nagle algorithm for this socket
			//  usually you don't want to do this - however, since we're talking to localhost,
			//  bandwidth is not a concern
			const BOOL yes = TRUE;
			if (setsockopt(sock_new, IPPROTO_TCP, TCP_NODELAY, (const char*)&yes, sizeof(yes)) == SOCKET_ERROR) {
				// this is not fatal but we might want to know about it
				ErrorBox(hDlg, _T("setsockopt"));
			}

			locals.insert(make_pair(sock_new, Local()));
		}
	}

	return true;
}

// ///////////////////////////////////////////////////////////////////////////
// WINDOWS UI FUNCTIONS
// ///////////////////////////////////////////////////////////////////////////

static
#ifdef _WIN64
INT_PTR
#else
BOOL
#endif
CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg) {
	case WM_INITDIALOG: {

		fLog << "WM_INITDIALOG, setting up" << endl;

		// Fill the edit box with default port
		SetDlgItemText(hDlg, IDC_EDIT_PORT, _T("1243"));

		// Set the app icon
		if (hIcon)
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);

		// Prepare Winsock
		//  if it fails, not much sense in starting up further.
		WSADATA wsaData;
		if (WSAStartup((1, 1), &wsaData) != 0) {
			ErrorBox(hDlg, _T("WSAStartup"));
			PostQuitMessage(1);
		}
		else {
			// TODO: show some info about WSAData on the status page
			fLog << "Started up WSAData" << endl; // << wsaData << endl;

			/* wVersion = %hhu.%hhu (max: %hhu.%hhu)\n\tDescription = %s\n\tSystem Status = %s\n\tMax Sockets = %hu, UDP Dg = %hu\n",
				wsaData.wVersion & 0xFF, wsaData.wVersion >> 8,
				wsaData.wHighVersion & 0xFF, wsaData.wHighVersion >> 8,
				wsaData.szDescription, wsaData.szSystemStatus, wsaData.iMaxSockets, wsaData.iMaxUdpDg); */
		}

		return TRUE;  // use the default keyboard focus
	}

	case WM_DESTROY:
		fLog << "WM_DESTROY, shutting down" << endl;

		DisableListenSocket(sock_listen);
		WSACleanup();

		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_CHECK_ENABLE:

			if (HIWORD(wParam) == BN_CLICKED || HIWORD(wParam) == BN_DOUBLECLICKED)
			{

				HWND hEnable = GetDlgItem(hDlg, IDC_CHECK_ENABLE);
				HWND hPort = GetDlgItem(hDlg, IDC_EDIT_PORT);

				fLog << "Checkbox clicked / double-clicked" << endl;

				if (IsDlgButtonChecked(hDlg, IDC_CHECK_ENABLE) == BST_CHECKED)
				{
					// user clicked the enable button - get some info and try to start listening
					fLog << "ENABLING" << endl;

					TCHAR lpPort[6];
					GetDlgItemText(hDlg, IDC_EDIT_PORT, (LPTSTR)&lpPort, 6);

					// let's go
					sock_listen = EnableListenSocket(hDlg, StrToInt(lpPort), true);
					if (sock_listen != INVALID_SOCKET) {

						// Success!
						fLog << "Socket opened and listening: socket = " << sock_listen << endl;

						// Socket bound and listening.  Update the status window accordingly.
						SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("Socket listening for incoming traffic."));

						// disable text entry for port
						EnableWindow(hPort, FALSE);

						// a success... start packet logging too
						pLog.open("SLIPGateway.pcap", ios::out | ios::binary | ios::trunc);
						const struct {
							unsigned int magic;
							unsigned short major, minor;
							unsigned int reserved1, reserved2;
							unsigned int snapsize;
							unsigned int capture;
						} pcapHeader = {
							0xA1B2C3D4,
							2, 4,
							0, 0,
							65535,
							101
						};
						pLog.write((char*)&pcapHeader, sizeof(pcapHeader));
					}
					else {
						fLog << "Failed to open listen socket." << endl;

						// re-enable the checkbox if error, try again!
						SendMessage(hEnable, BM_SETCHECK, BST_UNCHECKED, 0);
					}
				}
				else {
					fLog << "DISABLING" << endl;

					// close everything down
					DisableListenSocket(sock_listen);
					sock_listen = INVALID_SOCKET;

					// stop logging packets
					pLog.close();

					SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("SLIPGateway is not active."));

					// let user enter port again
					EnableWindow(hPort, TRUE);
				}
			}

			return TRUE;

		case IDC_BUTTON_QUIT:
			fLog << "Quit button" << endl;
			if (MessageBox(hDlg, TEXT("Close the program?"), TEXT("Close"),
				MB_ICONQUESTION | MB_YESNO) == IDYES)
				PostQuitMessage(0);

			return TRUE;
		}

		break;

		/*
			case WM_CLOSE:
				DestroyWindow(hDlg);
				return TRUE;
		*/

	case WM_SOCKET_LISTEN:
		fLog << "WM_SOCKET_LISTEN message:" << endl;

		if (!HandleListenSocket(hDlg, wParam, lParam)) {
			// some kind of fatal error in listen socket
			sock_listen = INVALID_SOCKET;

			// stop logging packets
			pLog.close();

			SetDlgItemText(hDlg, IDC_LABEL_STATUS, _T("SLIPGateway is not active."));

			// let user enter port again
			SendMessage(GetDlgItem(hDlg, IDC_CHECK_ENABLE), BM_SETCHECK, BST_UNCHECKED, 0);
			EnableWindow(GetDlgItem(hDlg, IDC_EDIT_PORT), TRUE);
		}

		return TRUE;

	case WM_SOCKET_LOCAL:
		//		fLog << "WM_SOCKET_LOCAL message:" << endl;

		HandleLocalSocket(hDlg, wParam, lParam);

		return TRUE;

	case WM_SOCKET_REMOTE_UDP:
		//		fLog << "WM_SOCKET_REMOTE_UDP message:" << endl;

		HandleRemoteUDP(hDlg, wParam, lParam);

		return TRUE;

	case WM_SOCKET_REMOTE_TCP:
		//		fLog << "WM_SOCKET_REMOTE_TCP message:" << endl;

		HandleRemoteTCP(hDlg, wParam, lParam);

		return TRUE;
	}

	return FALSE;
}

// Entry point
int APIENTRY _tWinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPTSTR	 lpCmdLine,
	int	   nCmdShow)
{
	fLog.open("SLIPGateway.log");
	fLog << "Starting up..." << endl;

	srand(GetTickCount());

	// load the app icon, it's used in a few places
	hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SLIPGATEWAY));
	fLog << "App icon handle = " << hIcon << endl;

	// create the application dialog
	const HWND hWnd = CreateDialog(hInstance,
		MAKEINTRESOURCE(IDD_SLIPGATEWAY),
		NULL,
		DialogProc);
	fLog << "Create dialog hWnd = " << hWnd << endl;

	// main loop - try the dialog message handler, then call dlgproc otherwise
	BOOL bRet;
	MSG msg;
	while ((bRet = GetMessage(&msg, 0, 0, 0)) != 0) {
		// this indicates an error in GetMessage
		if (bRet == -1)
		{
			ErrorBox(hWnd, _T("GetMessage"), GetLastError());
			fLog.close();
			return -1;
		}

		// 
		if (!IsDialogMessage(hWnd, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	fLog << "GetMessage returned 0, exiting" << endl;
	fLog.close();

	return msg.wParam;
}
