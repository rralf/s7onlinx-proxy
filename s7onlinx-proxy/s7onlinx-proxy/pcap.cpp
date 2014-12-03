#include <cstdint>

#include <Windows.h>

#include "pcap.h"

// Damn Micro$oft does not have gettimeofday....
static const unsigned __int64 epoch = ((unsigned __int64)116444736000000000ULL);
int gettimeofday(struct timeval * tp, struct timezone * tzp) {
	FILETIME    file_time;
	SYSTEMTIME  system_time;
	ULARGE_INTEGER ularge;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;

	tp->tv_sec = (long)((ularge.QuadPart - epoch) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);

	return 0;
}

int timeval_substract(struct timeval *result, struct timeval *t2, struct timeval *t1) {
	long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
	result->tv_sec = diff / 1000000;
	result->tv_usec = diff % 1000000;

	return (diff<0);
}

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

Pcap::Pcap(const std::string& filename) : handle(nullptr)
{
	fopen_s(&handle, filename.c_str(), "wb");

	pcap_hdr_t hdr;
	hdr.magic_number = 0xa1b2c3d4;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535*4;
	hdr.network = 147;

	gettimeofday(&capstart, nullptr);

	fwrite(&hdr, sizeof(pcap_hdr_t), 1, handle);
}

Pcap::~Pcap()
{
	if (handle) {
		fclose(handle);
	}
}

void Pcap::writePacket(const Packet& p) {
	std::lock_guard<std::mutex> l(writeMutex);

	pcaprec_hdr_t hdr;

	struct timeval now;
	gettimeofday(&now, nullptr);

	timeval_substract(&now, &now, &capstart);
	
	hdr.incl_len = hdr.orig_len = p.size();
	hdr.ts_sec = now.tv_sec;
	hdr.ts_usec = now.tv_usec;

	fwrite(&hdr, sizeof(pcaprec_hdr_t), 1, handle);
	fwrite(p.data(), p.size(), 1, handle);
}

Packet encapsulate_tpkt(const char* src, size_t length) {
	size_t sum = 7 + length;
	Packet retval(sum);

	retval[0] = 0x03;
	retval[1] = 0x00;
	retval[2] = (sum >> 8) & 0xff;
	retval[3] = (sum >> 0) & 0xff;


	retval[4] = 0x02;
	retval[5] = 0xf0;
	retval[6] = 0x80;

	memcpy(retval.data() + 7, src, length);

	return retval;
}