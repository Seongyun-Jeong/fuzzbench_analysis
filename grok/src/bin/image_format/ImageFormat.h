/*
 *    Copyright (C) 2016-2022 Grok Image Compression Inc.
 *
 *    This source code is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This source code is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "IImageFormat.h"
#include "IFileIO.h"
#include "BufferPool.h"
#include "Serializer.h"

#include <mutex>

const uint32_t reclaimSize = 5;

class ImageFormat : public IImageFormat
{
  public:
	ImageFormat();
	virtual ~ImageFormat();
	void serializeRegisterClientCallback(grk_serialize_callback reclaim_callback,
										 void* user_data) override;
	void serializeReclaimBuffer(grk_serialize_buf buffer);
	void serializeRegisterApplicationClient(void);
#ifndef GROK_HAVE_URING
	void reclaim(grk_serialize_buf pixels);
#endif
	virtual bool encodeInit(grk_image* image, const std::string& filename,
							uint32_t compressionLevel) override;
	bool encodePixels(grk_serialize_buf pixels) override;
	virtual bool encodeFinish(void) override;
	uint32_t getEncodeState(void) override;
	bool openFile(void);

  protected:
	virtual bool encodePixelsCore(grk_serialize_buf pixels);
	virtual bool encodePixelsCoreWrite(grk_serialize_buf pixels);
	bool open(std::string fname, std::string mode);
	uint64_t write(GrkSerializeBuf buffer);
	bool read(uint8_t* buf, size_t len);
	bool seek(int64_t pos, int whence);
	uint32_t maxY(uint32_t rows);
	int getMode(const char* mode);
	void scaleComponent(grk_image_comp* component, uint8_t precision);

	void allocPalette(grk_color* color, uint8_t num_channels, uint16_t num_entries);
	void copy_icc(grk_image* dest, uint8_t* iccbuf, uint32_t icclen);
	void create_meta(grk_image* img);
	bool validate_icc(GRK_COLOR_SPACE colourSpace, uint8_t* iccbuf, uint32_t icclen);

	bool allComponentsSanityCheck(grk_image* image, bool equalPrecision);
	bool isFinalOutputSubsampled(grk_image* image);
	bool isChromaSubsampled(grk_image* image);
	bool areAllComponentsSameSubsampling(grk_image* image);
	bool isHeaderEncoded(void);

	grk_image* image_;
	IFileIO* fileIO_;
	FILE* fileStream_;
	std::string fileName_;
	uint32_t compressionLevel_;

	bool useStdIO_;
	uint32_t encodeState;
	mutable std::mutex encodePixelmutex;
	BufferPool pool;
	Serializer serializer;
};
