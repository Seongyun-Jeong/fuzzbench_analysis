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
 *
 *    This source code incorporates work covered by the BSD 2-clause license.
 *    Please see the LICENSE file in the root directory for details.
 *
 */

#pragma once
#include "grk_includes.h"
#include <queue>
#include <mutex>

namespace grk
{
/*
 * Tile structure.
 *
 * Tile bounds are in canvas coordinates, and are equal to the
 * full, non-windowed, unreduced tile dimensions,
 * while the component dimensions are reduced
 * if there is a resolution reduction.
 *
 */
struct Tile : public grkRectU32
{
	Tile();
	~Tile();
	uint16_t numcomps;
	TileComponent* comps;
	double distortion;
	double layerDistoration[maxCompressLayersGRK];
	uint64_t numProcessedPackets;
	uint64_t numDecompressedPackets;
};

struct PacketTracker
{
	PacketTracker();
	~PacketTracker();
	void init(uint32_t numcomps, uint32_t numres, uint64_t numprec, uint32_t numlayers);
	void clear(void);
	void packet_encoded(uint32_t comps, uint32_t res, uint64_t prec, uint32_t layer);
	bool is_packet_encoded(uint32_t comps, uint32_t res, uint64_t prec, uint32_t layer);

  private:
	uint8_t* bits;

	uint32_t numcomps_;
	uint32_t numres_;
	uint64_t numprec_;
	uint32_t numlayers_;

	uint64_t get_buffer_len(uint32_t numcomps, uint32_t numres, uint64_t numprec,
							uint32_t numlayers);
	uint64_t index(uint32_t comps, uint32_t res, uint64_t prec, uint32_t layer);
};

/**
 Tile processor for decompression and compression
 */

struct TileProcessor
{
	explicit TileProcessor(uint16_t index, CodeStream* codeStream, IBufferedStream* stream,
						   bool isCompressor, bool isWholeTileDecompress);
	~TileProcessor();
	bool init(void);
	bool allocWindowBuffers(const GrkImage* outputImage);
	void deallocBuffers();
	bool preCompressTile(void);
	bool canWritePocMarker(void);
	bool writeTilePartT2(uint32_t* tileBytesWritten);
	bool doCompress(void);
	bool decompressT1(void);
	bool decompressT2(SparseBuffer* srcBuf);
	bool decompressT2T1(TileCodingParams* tcp, GrkImage* outputImage, bool doPost);
	bool ingestUncompressedData(uint8_t* p_src, uint64_t src_length);
	bool needsRateControl();
	void ingestImage();
	bool prepareSodDecompress(CodeStreamDecompress* codeStream);
	void generateImage(GrkImage* src_image, Tile* src_tile);
	GrkImage* getImage(void);
	void release(void);
	void setCorruptPacket(void);
	PacketTracker* getPacketTracker(void);
	grkRectU32 getUnreducedTileWindow(void);
	TileCodingParams* getTileCodingParams(void);
	uint8_t getMaxNumDecompressResolutions(void);
	IBufferedStream* getStream(void);
	uint32_t getPreCalculatedTileLen(void);
	bool canPreCalculateTileLen(void);

	uint16_t getIndex(void) const;
	void incrementIndex(void);

	/** Compression Only
	 *  true for first POC tile part, otherwise false*/
	bool first_poc_tile_part_;
	/** Compressing Only
	 *  index of tile part being currently coding.
	 *  tilePartIndexCounter_ holds the total number of tile parts encoded thus far
	 *  while the compressor is compressing the current tile part.*/
	uint8_t tilePartIndexCounter_;
	// Decompressing Only
	uint32_t tilePartDataLength;
	/** Compression Only
	 *  Current packet iterator number */
	uint32_t pino;
	Tile* tile;
	GrkImage* headerImage;
	grk_plugin_tile* current_plugin_tile;
	// true if whole tile will be decoded; false if tile window will be decoded
	bool wholeTileDecompress;
	CodingParams* cp_;
	PacketLengthCache packetLengthCache;

  private:
	/** index of tile being currently compressed/decompressed */
	uint16_t tileIndex_;
	// Compressing only - track which packets have already been written
	// to the code stream
	PacketTracker packetTracker_;
	IBufferedStream* stream_;
	bool corrupt_packet_;
	/** position of the tile part flag in progression order*/
	uint32_t newTilePartProgressionPosition;
	// coding/decoding parameters for this tile
	TileCodingParams* tcp_;
	bool isWholeTileDecompress(uint32_t compno);
	bool needsMctDecompress(uint32_t compno);
	bool mctDecompress();
	bool dcLevelShiftDecompress();
	bool dcLevelShiftCompress();
	bool mct_encode();
	bool dwt_encode();
	void t1_encode();
	bool encodeT2(uint32_t* packet_bytes_written);
	bool rateAllocate(uint32_t* allPacketBytes);
	bool layerNeedsRateControl(uint32_t layno);
	bool makeSingleLosslessLayer();
	void makeLayerFinal(uint32_t layno);
	bool pcrdBisectSimple(uint32_t* p_data_written);
	void makeLayerSimple(uint32_t layno, double thresh, bool finalAttempt);
	bool pcrdBisectFeasible(uint32_t* p_data_written);
	void makeLayerFeasible(uint32_t layno, uint16_t thresh, bool finalAttempt);
	bool truncated;
	GrkImage* image_;
	bool isCompressor_;
	grkRectU32 unreducedTileWindow;
	uint32_t preCalculatedTileLen;
};

} // namespace grk
