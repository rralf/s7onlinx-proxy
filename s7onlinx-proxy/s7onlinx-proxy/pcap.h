#pragma once

#include <vector>
#include <string>
#include <cstdio>
#include <ctime>
#include <mutex>

typedef std::vector<unsigned char> Packet;

Packet encapsulate_tpkt(const char* src, size_t length);

class Pcap
{
public:
	Pcap(const std::string& filename);
	virtual ~Pcap();

	void writePacket(const Packet& p);

private:
	FILE* handle;
	struct timeval capstart;

	std::mutex writeMutex;
};

