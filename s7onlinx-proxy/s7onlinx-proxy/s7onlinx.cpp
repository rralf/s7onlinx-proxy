#include <fstream>
#include <ctime>
#include <sstream>
#include <memory>

#include <stdio.h>
#include <tchar.h>

#include <windows.h>
#include "pcap.h"

using namespace std;

#pragma comment (linker, "/export:CloseElConnection=s7onlinx_.CloseElConnection,@3")
#pragma comment (linker, "/export:OnlDll_CheckDevOpen=s7onlinx_.OnlDll_CheckDevOpen,@4")
#pragma comment (linker, "/export:OnlDll_IsSimulationOn=s7onlinx_.OnlDll_IsSimulationOn,@5")
#pragma comment (linker, "/export:OnlDll_SimulationOnOff=s7onlinx_.OnlDll_SimulationOnOff,@6")
#pragma comment (linker, "/export:OnlDll_SimulationOnOffCheck=s7onlinx_.OnlDll_SimulationOnOffCheck,@7")
#pragma comment (linker, "/export:OnlDll_SimulationOnOffSetMsg=s7onlinx_.OnlDll_SimulationOnOffSetMsg,@8")
#pragma comment (linker, "/export:OpenElConnection=s7onlinx_.OpenElConnection,@9")
#pragma comment (linker, "/export:SCI_conv_time=s7onlinx_.SCI_conv_time,@1")
#pragma comment (linker, "/export:SCI_time=s7onlinx_.SCI_time,@2")
#pragma comment (linker, "/export:SCP_close=s7onlinx_.SCP_close,@10")
#pragma comment (linker, "/export:SCP_get_dev_list=s7onlinx_.SCP_get_dev_list,@11")
#pragma comment (linker, "/export:SCP_get_dev_listW=s7onlinx_.SCP_get_dev_listW,@12")
#pragma comment (linker, "/export:SCP_get_errno=s7onlinx_.SCP_get_errno,@13")
#pragma comment (linker, "/export:SCP_open=s7onlinx_.SCP_open,@14")
#pragma comment (linker, "/export:SCP_openW=s7onlinx_.SCP_openW,@15")
#pragma comment (linker, "/export:SCP_open_async=s7onlinx_.SCP_open_async,@16")
// We want to redirect these functions
//#pragma comment (linker, "/export:SCP_receive=s7onlinx_.SCP_receive,@17")
//#pragma comment (linker, "/export:SCP_send=s7onlinx_.SCP_send,@18")
#pragma comment (linker, "/export:SetSinecHWnd=s7onlinx_.SetSinecHWnd,@19")
#pragma comment (linker, "/export:SetSinecHWndMsg=s7onlinx_.SetSinecHWndMsg,@20")

HINSTANCE	original = 0;
FARPROC     original_send = { 0 };
FARPROC     original_receive = { 0 };

unsigned int receive_count = 0;
unsigned int send_count = 0;

int proxy_session_number = 0;

ofstream logfile;

const char location[] = "C:\\Temp\\";
const char logfile_name[] = "s7onlinx-log.txt";
const char recvcap_filename[] = "recv.pcap";
const char sendcap_filename[] = "send.pcap";
const char amalgamation_filename[] = "amalgamation.pcap";

string absolute_logfile_name;
string absolute_recvcap_filename;
string absolute_sendcap_filename;
string absolute_amalgamationcap_filename;

unique_ptr<Pcap> pcap_send = nullptr;
unique_ptr<Pcap> pcap_recv = nullptr;
unique_ptr<Pcap> pcap_amalgamation = nullptr;

int fileExists(const string& filename)
{
	const TCHAR* file = filename.c_str();
	WIN32_FIND_DATA FindFileData;
	HANDLE handle = FindFirstFile(file, &FindFileData);
	int found = handle != INVALID_HANDLE_VALUE;
	if (found)
	{
		FindClose(handle);
	}
	return found;
}

void determine_proxy_session() {
	// I <3 lambdas.
	auto genfn = [] (const char* name) -> string {
		ostringstream out;
		out << location << proxy_session_number << '-' << name;
		return out.str();
	};

	while (fileExists(genfn(logfile_name))) {
		++proxy_session_number;
	}

	absolute_logfile_name = genfn(logfile_name);
	absolute_recvcap_filename = genfn(recvcap_filename);
	absolute_sendcap_filename = genfn(sendcap_filename);
	absolute_amalgamationcap_filename = genfn(amalgamation_filename);
}

template <class T>
void log(const T& t) {
	const int BUFFERSIZE = 80;
	char timebuffer[BUFFERSIZE];
	
	auto time = std::time(nullptr);
	struct tm tm;
	localtime_s(&tm, &time);
	strftime(timebuffer, BUFFERSIZE, "%Y-%m-%d %H:%M:%S", &tm);

	logfile << timebuffer << " -- " << t << endl;
	logfile.flush();
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH) {
		original = LoadLibraryA("s7onlinx_.dll");
		if (original == 0) {
			return false;
		}

		original_send = GetProcAddress(original, "SCP_send");
		original_receive = GetProcAddress(original, "SCP_receive");

		determine_proxy_session();

		logfile.open(absolute_logfile_name, ofstream::out);

		if (logfile.fail()) {
			return false;
		}

		pcap_send = unique_ptr<Pcap>(new Pcap(absolute_sendcap_filename));
		pcap_recv = unique_ptr<Pcap>(new Pcap(absolute_recvcap_filename));
		pcap_amalgamation = unique_ptr<Pcap>(new Pcap(absolute_amalgamationcap_filename));

		log("Proxy initialized");

	} else if (reason == DLL_PROCESS_DETACH) {
		log("Proxy shutdown");
		FreeLibrary(original);
	}

	return true;
}

extern "C" int __stdcall proxy_SCP_send(int handle, UWORD length, char* data)
{
	typedef int(__stdcall *pS)(int, UWORD, char*);
	pS pps = (pS)original_send;
	int retval = pps(handle, length, data); // original call
	uint16_t ulength = *(uint16_t*)(data + 16);
	
	// Drop the packet if it has less 4 Byte User Data
	if (length < 0x50 || ulength < 4 || data[0x50] != 0x72)
		return retval;


	ostringstream message;
	message << "Packet Send #" << ++send_count << "Length: " << (int)length << " User Length: " << (int)ulength << " Return Code: " << retval;
	log(message.str());

	Packet p = encapsulate_tpkt(data + 0x50, ulength);
	pcap_send->writePacket(p);
	pcap_amalgamation->writePacket(p);

	return retval;
}

extern "C" int __stdcall proxy_SCP_receive(int handle, UWORD timeout, UWORD* data_len, UWORD length, char* data)
{
	typedef int(__stdcall *pS)(int, UWORD, UWORD*, UWORD, char*);
	pS pps = (pS)original_receive;
	int retval = pps(handle, timeout, data_len, length, data); // original call
	uint16_t ulength = *(uint16_t*)(data + 16);

	// Drop the packet if it has less 4 Byte User Data
	if (length < 0x50 || ulength < 4 || data[0x50] != 0x72)
		return retval;

	ostringstream message;
	message << "Packet Rcv #" << ++receive_count << " Lenth: " << (int)length << " User Length: " << (int)ulength << " Data_Len: " << (int)*data_len << " Return Code: " << retval;
	log(message.str());

	Packet p = encapsulate_tpkt(data + 0x50, ulength);
	pcap_recv->writePacket(p);
	pcap_amalgamation->writePacket(p);
	return retval;
}