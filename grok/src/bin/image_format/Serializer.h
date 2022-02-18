#pragma once

#include "grk_apps_config.h"
#include "grok.h"
#include "IFileIO.h"
#include "FileStreamIO.h"

#ifdef GROK_HAVE_URING
#include "FileUringIO.h"
#endif

#include <cstdint>

struct Serializer
{
	Serializer(void);
	void init(grk_image* image);
	void serializeRegisterClientCallback(grk_serialize_callback reclaim_callback, void* user_data);
	grk_serialize_callback getSerializerReclaimCallback(void);
	void* getSerializerReclaimUserData(void);
#ifndef _WIN32
	int getFd(void);
#endif
	bool open(std::string name, std::string mode);
	bool close(void);
	size_t write(uint8_t* buf, size_t size);
	uint64_t seek(int64_t off, int32_t whence);
	uint32_t getNumPooledRequests(void);
	uint64_t getOffset(void);
#ifdef GROK_HAVE_URING
	void initPooledRequest(void);
#else
	void incrementPooled(void);
#endif
	bool allPooledRequestsComplete(void);

  private:
#ifndef _WIN32
#ifdef GROK_HAVE_URING
	FileUringIO uring;
	GrkSerializeBuf scheduled_;
#endif
	int getMode(std::string mode);
	int fd_;
#else
	FileStreamIO fileStreamIO;
#endif
	uint32_t numPooledRequests_;
	uint32_t maxPooledRequests_;
	bool asynchActive_;
	uint64_t off_;
	grk_serialize_callback reclaim_callback_;
	void* reclaim_user_data_;
};
