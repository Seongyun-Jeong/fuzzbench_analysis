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
 *    This source code incorporates work covered by the BSD 2-clause license.
 *    Please see the LICENSE file in the root directory for details.
 *
 */

#include "grk_apps_config.h"
#include <filesystem>

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif /* _WIN32 */

#include "grk_decompress.h"

#include "common.h"
#include "grok.h"
#include "RAWFormat.h"
#include "PNMFormat.h"
#include "PGXFormat.h"
#include "BMPFormat.h"
#ifdef GROK_HAVE_LIBJPEG
#include "JPEGFormat.h"
#endif
#ifdef GROK_HAVE_LIBTIFF
#include "TIFFFormat.h"
#endif
#ifdef GROK_HAVE_LIBPNG
#include "PNGFormat.h"
#endif
#include "convert.h"

#include <lcms2.h>
#include "grk_string.h"
#include <climits>
#include <string>
#define TCLAP_NAMESTARTSTRING "-"
#include "tclap/CmdLine.h"
#include <chrono>
#include "spdlog/sinks/basic_file_sink.h"
#include "exif.h"

namespace grk
{
void exit_func()
{
	grk_plugin_stop_batch_decompress();
}

#ifdef _WIN32
BOOL sig_handler(DWORD signum)
{
	switch(signum)
	{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			exit_func();
			return (TRUE);

		default:
			return FALSE;
	}
}
#else
void sig_handler(int signum)
{
	GRK_UNUSED(signum);
	exit_func();
}
#endif

void setUpSignalHandler()
{
#ifdef _WIN32
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE);
#else
	struct sigaction sa;
	sa.sa_handler = &sig_handler;
	sigfillset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, nullptr);
#endif
}

static void decompress_help_display(void)
{
	fprintf(stdout,
			"grk_decompress - decompress JPEG 2000 codestream to various image formats.\n"
			"This utility has been compiled against libgrokj2k v%s.\n\n",
			grk_version());

	fprintf(stdout, "-----------\n"
					"Parameters:\n"
					"-----------\n"
					"\n"
					"  [-y | -ImgDir] <directory> \n"
					"	Compressed image file directory\n"
					"  [-O | -OutFor] <PBM|PGM|PPM|PNM|PAM|PGX|PNG|BMP|TIF|RAW|RAWL>\n"
					"    REQUIRED only if [ImgDir] option is used\n"
					"	Output format for decompressed images.\n");
	fprintf(stdout, "  [-i | -InputFile] <compressed file>\n"
					"    REQUIRED only if [ImgDir] option is not specified\n"
					"    Currently accepts J2K and JP2 files. The file type\n"
					"    is identified by parsing the beginning of the file.\n");
	fprintf(stdout, "  [-o | -OutputFile] <decompressed file>\n"
					"    REQUIRED\n"
					"    Currently accepts formats specified above (see OutFor option)\n"
					"    Binary data is written to the file (not ascii). If a PGX\n"
					"    filename is given, there will be as many output files as there are\n"
					"    components: an index starting from 0 will then be appended to the\n"
					"    output filename, just before the \"pgx\" extension. If a PGM filename\n"
					"    is given and there are more than one component, only the first component\n"
					"    will be written to the file.\n");
	fprintf(stdout, "  [-a | -OutDir] <output directory>\n"
					"    Output directory where decompressed files will be stored.\n");
	fprintf(stdout, "  [-g | -PluginPath] <plugin path>\n"
					"    Path to T1 plugin.\n");
	fprintf(stdout, "  [-H | -num_threads] <number of threads>\n"
					"    Number of threads used by libgrokj2k library.\n");
	fprintf(stdout,
			"  [-c|-Compression] <compression method>\n"
			"	Compress output image data. Currently, this option is only applicable when\n"
			"	output format is set to TIF. Possible values are:\n"
			"	{NONE, LZW,JPEG, PACKBITS. ZIP,LZMA,ZSTD,WEBP}. Default value is NONE.\n");
	fprintf(stdout, "   [L|-CompressionLevel] <compression level>\n"
					"    \"Quality\" of compression. Currently only implemented for PNG format.\n"
					"	Default value is set to 9 (Z_BEST_COMPRESSION).\n"
					"	Other options are 0 (Z_NO_COMPRESSION) and 1 (Z_BEST_SPEED)\n");
	fprintf(stdout, "  [-t | -TileInfo] <tile index>\n"
					"    Index of tile to be decompressed\n");
	fprintf(
		stdout,
		"  [-d | -DecodeWindow] <x0,y0,x1,y1>\n"
		"    Top left-hand corner and bottom right-hand corner of window to be decompressed.\n");
	fprintf(stdout, "  [-r | -Reduce] <reduce factor>\n"
					"    Set the number of highest resolution levels to be discarded. The\n"
					"    image resolution is effectively divided by 2 to the power of the\n"
					"    number of discarded levels. The reduce factor is limited by the\n"
					"    smallest total number of decomposition levels among tiles.\n"
					"  [-l | -Layer] <number of quality layers to decompress>\n"
					"    Set the maximum number of quality layers to decompress. If there are\n"
					"    fewer quality layers than the specified number, all the quality layers\n"
					"    are decompressed.\n");
	fprintf(stdout, "  [-p | -Precision] <comp 0 precision>[C|S][,<comp 1 precision>[C|S][,...]]\n"
					"    OPTIONAL\n"
					"    Force the precision (bit depth) of components.\n");
	fprintf(stdout,
			"There shall be at least 1 value. There is no limit to the number of values\n"
			"(comma separated, values whose count exceeds component count will be ignored).\n"
			"    If there are fewer values than components, the last value is used for remaining "
			"components.\n"
			"    If 'C' is specified (default), values are clipped.\n"
			"    If 'S' is specified, values are scaled.\n"
			"    A 0 value can be specified (meaning original bit depth).\n");
	fprintf(stdout, "  [-f | -force-rgb]\n"
					"    Force output image colorspace to RGB\n"
					"  [-u | -upsample]\n"
					"    components will be upsampled to image size\n"
					"  [-s | -split-pnm]\n"
					"    Split output components to different files when writing to PNM\n");
	fprintf(
		stdout,
		"  [-X | -XML] <xml file name> \n"
		"    Store XML metadata to file. File name will be set to \"xml file name\" + \".xml\"\n");
	fprintf(stdout, "  [-W | -logfile] <log file name>\n"
					"    log to file. File name will be set to \"log file name\"\n");
	fprintf(stdout, "\n");
}

void GrkDecompress::printTiming(uint32_t num_images, std::chrono::duration<double> elapsed)
{
	if(!num_images)
		return;
	std::string temp = (num_images > 1) ? "ms/image" : "ms";
	spdlog::info("decompress time: {} {}", (elapsed.count() * 1000) / (double)num_images, temp);
}

bool GrkDecompress::parsePrecision(const char* option, grk_decompress_parameters* parameters)
{
	const char* remaining = option;
	bool result = true;

	/* reset */
	if(parameters->precision)
	{
		free(parameters->precision);
		parameters->precision = nullptr;
	}
	parameters->numPrecision = 0U;

	for(;;)
	{
		int prec;
		char mode;
		char comma;
		int count;

		count = sscanf(remaining, "%d%c%c", &prec, &mode, &comma);
		if(count == 1)
		{
			mode = 'C';
			count++;
		}
		if((count == 2) || (mode == ','))
		{
			if(mode == ',')
				mode = 'C';
			comma = ',';
			count = 3;
		}
		if(count == 3)
		{
			if((prec < 1) || (prec > 32))
			{
				spdlog::error("Invalid precision {} in precision option {}", prec, option);
				result = false;
				break;
			}
			if((mode != 'C') && (mode != 'S'))
			{
				spdlog::error("Invalid precision mode %c in precision option {}", mode, option);
				result = false;
				break;
			}
			if(comma != ',')
			{
				spdlog::error("Invalid character %c in precision option {}", comma, option);
				result = false;
				break;
			}

			if(parameters->precision == nullptr)
			{
				/* first one */
				parameters->precision = (grk_precision*)malloc(sizeof(grk_precision));
				if(parameters->precision == nullptr)
				{
					spdlog::error("Could not allocate memory for precision option");
					result = false;
					break;
				}
			}
			else
			{
				uint32_t new_size = parameters->numPrecision + 1U;
				grk_precision* new_prec;

				if(new_size == 0U)
				{
					spdlog::error("Could not allocate memory for precision option");
					result = false;
					break;
				}

				new_prec = (grk_precision*)realloc(parameters->precision,
												   new_size * sizeof(grk_precision));
				if(new_prec == nullptr)
				{
					spdlog::error("Could not allocate memory for precision option");
					result = false;
					break;
				}
				parameters->precision = new_prec;
			}

			parameters->precision[parameters->numPrecision].prec = (uint8_t)prec;
			switch(mode)
			{
				case 'C':
					parameters->precision[parameters->numPrecision].mode = GRK_PREC_MODE_CLIP;
					break;
				case 'S':
					parameters->precision[parameters->numPrecision].mode = GRK_PREC_MODE_SCALE;
					break;
				default:
					break;
			}
			parameters->numPrecision++;

			remaining = strchr(remaining, ',');
			if(remaining == nullptr)
			{
				break;
			}
			remaining += 1;
		}
		else
		{
			spdlog::error("Could not parse precision option {}", option);
			result = false;
			break;
		}
	}

	return result;
}

int GrkDecompress::loadImages(grk_dircnt* dirptr, char* imgdirpath)
{
	int i = 0;

	for(const auto& entry : std::filesystem::directory_iterator(imgdirpath))
	{
		strcpy(dirptr->filename[i], entry.path().filename().string().c_str());
		i++;
	}

	return 0;
}
char GrkDecompress::nextFile(const std::string inputFile, grk_img_fol* inputFolder,
							 grk_img_fol* outFolder, grk_decompress_parameters* parameters)
{
	spdlog::info("File: \"{}\"", inputFile.c_str());
	std::string infilename = inputFolder->imgdirpath + std::string(pathSeparator()) + inputFile;
	if(!grk::jpeg2000_file_format(infilename.c_str(),
								  (GRK_SUPPORTED_FILE_FMT*)&parameters->decod_format) ||
	   parameters->decod_format == GRK_UNK_FMT)
		return 1;
	if(grk::strcpy_s(parameters->infile, sizeof(parameters->infile), infilename.c_str()) != 0)
		return 1;

	auto temp_ofname = inputFile;
	auto pos = inputFile.find(".");
	if(pos != std::string::npos)
		temp_ofname = inputFile.substr(0, pos);
	if(inputFolder->set_out_format)
	{
		std::string outfilename = outFolder->imgdirpath + std::string(pathSeparator()) +
								  temp_ofname + "." + inputFolder->out_format;
		if(grk::strcpy_s(parameters->outfile, sizeof(parameters->outfile), outfilename.c_str()) !=
		   0)
			return 1;
	}

	return 0;
}

class GrokOutput : public TCLAP::StdOutput
{
  public:
	virtual void usage(TCLAP::CmdLineInterface& c)
	{
		GRK_UNUSED(c);
		decompress_help_display();
	}
};

/**
 * Convert compression string to compression code. (use TIFF codes)
 */
uint32_t GrkDecompress::getCompressionCode(const std::string& compressionString)
{
	if(compressionString == "NONE")
		return 0;
	else if(compressionString == "LZW")
		return 5;
	else if(compressionString == "JPEG")
		return 7;
	else if(compressionString == "PACKBITS")
		return 32773;
	else if(compressionString == "ZIP")
		return 8;
	else if(compressionString == "LZMA")
		return 34925;
	else if(compressionString == "ZSTD")
		return 50000;
	else if(compressionString == "WEBP")
		return 50001;
	else
		return UINT_MAX;
}

int GrkDecompress::parseCommandLine(int argc, char** argv, DecompressInitParams* initParams)
{
	grk_decompress_parameters* parameters = &initParams->parameters;
	grk_img_fol* inputFolder = &initParams->inputFolder;
	grk_img_fol* outFolder = &initParams->outFolder;
	char* pluginPath = initParams->pluginPath;
	try
	{
		TCLAP::CmdLine cmd("grk_decompress command line", ' ', grk_version());

		// set the output
		GrokOutput output;
		cmd.setOutput(&output);

		TCLAP::ValueArg<std::string> logfileArg("W", "logfile", "Log file", false, "", "string",
												cmd);

		TCLAP::ValueArg<std::string> imgDirArg("y", "ImgDir", "Image Directory", false, "",
											   "string", cmd);
		TCLAP::ValueArg<std::string> outDirArg("a", "OutDir", "Output Directory", false, "",
											   "string", cmd);
		TCLAP::ValueArg<std::string> outForArg("O", "OutFor", "Output Format", false, "", "string",
											   cmd);

		TCLAP::SwitchArg forceRgbArg("f", "force-rgb", "Force RGB", cmd);
		TCLAP::SwitchArg upsampleArg("u", "upsample", "Upsample", cmd);
		TCLAP::SwitchArg splitPnmArg("s", "split-pnm", "Split PNM", cmd);
		TCLAP::ValueArg<std::string> pluginPathArg("g", "PluginPath", "Plugin path", false, "",
												   "string", cmd);
		TCLAP::ValueArg<uint32_t> numThreadsArg("H", "num_threads", "Number of threads", false, 0,
												"unsigned integer", cmd);
		TCLAP::ValueArg<std::string> inputFileArg("i", "InputFile", "Input file", false, "",
												  "string", cmd);
		TCLAP::ValueArg<std::string> outputFileArg("o", "OutputFile", "Output file", false, "",
												   "string", cmd);
		TCLAP::ValueArg<uint32_t> reduceArg("r", "Reduce", "Reduce resolutions", false, 0,
											"unsigned integer", cmd);
		TCLAP::ValueArg<uint16_t> layerArg("l", "Layer", "Layer", false, 0, "unsigned integer",
										   cmd);
		TCLAP::ValueArg<uint32_t> tileArg("t", "TileInfo", "Input tile index", false, 0,
										  "unsigned integer", cmd);
		TCLAP::ValueArg<std::string> precisionArg("p", "Precision", "Force precision", false, "",
												  "string", cmd);
		TCLAP::ValueArg<std::string> decodeRegionArg("d", "DecodeRegion", "Decompress Region",
													 false, "", "string", cmd);
		TCLAP::ValueArg<std::string> compressionArg("c", "Compression", "Compression Type", false,
													"", "string", cmd);
		TCLAP::ValueArg<uint32_t> compressionLevelArg("L", "CompressionLevel", "Compression Level",
													  false, UINT_MAX, "unsigned integer", cmd);
		TCLAP::ValueArg<uint32_t> durationArg("z", "Duration", "Duration in seconds", false, 0,
											  "unsigned integer", cmd);

		TCLAP::ValueArg<int32_t> deviceIdArg("G", "DeviceId", "Device ID", false, 0, "integer",
											 cmd);

		TCLAP::SwitchArg xmlArg("X", "XML", "XML metadata", cmd);
		TCLAP::SwitchArg transferExifTagsArg("V", "TransferExifTags", "Transfer Exif tags", cmd);

		// Kernel build flags:
		// 1 indicates build binary, otherwise load binary
		// 2 indicates generate binaries
		TCLAP::ValueArg<uint32_t> kernelBuildOptionsArg("k", "KernelBuild", "Kernel build options",
														false, 0, "unsigned integer", cmd);

		TCLAP::ValueArg<uint32_t> repetitionsArg(
			"e", "Repetitions",
			"Number of compress repetitions, for either a folder or a single file", false, 0,
			"unsigned integer", cmd);

		TCLAP::SwitchArg verboseArg("v", "verbose", "Verbose", cmd);
		cmd.parse(argc, argv);

		initParams->transferExifTags = transferExifTagsArg.isSet();

		parameters->verbose_ = verboseArg.isSet();
		bool useStdio = inputFileArg.isSet() && outForArg.isSet() && !outputFileArg.isSet();
		// disable verbose mode so we don't write info or warnings to stdout
		if(useStdio)
			parameters->verbose_ = false;
		if(!parameters->verbose_)
			spdlog::set_level(spdlog::level::level_enum::err);

		if(logfileArg.isSet())
		{
			auto file_logger = spdlog::basic_logger_mt("grk_decompress", logfileArg.getValue());
			spdlog::set_default_logger(file_logger);
		}

		parameters->serialize_xml = xmlArg.isSet();
		parameters->force_rgb = forceRgbArg.isSet();
		if(upsampleArg.isSet())
		{
			if(reduceArg.isSet())
				spdlog::warn("Cannot upsample when reduce argument set. Ignoring");
			else
				parameters->upsample = true;
		}
		parameters->split_pnm = splitPnmArg.isSet();
		if(compressionArg.isSet())
		{
			uint32_t comp = getCompressionCode(compressionArg.getValue());
			if(comp == UINT_MAX)
				spdlog::warn("Unrecognized compression {}. Ignoring", compressionArg.getValue());
			else
				parameters->compression = comp;
		}
		if(compressionLevelArg.isSet())
			parameters->compressionLevel = compressionLevelArg.getValue();
		// process
		if(inputFileArg.isSet())
		{
			const char* infile = inputFileArg.getValue().c_str();
			// for debugging purposes, set to false
			bool checkFile = true;

			if(checkFile)
			{
				if(!jpeg2000_file_format(infile,
										 (GRK_SUPPORTED_FILE_FMT*)&parameters->decod_format))
				{
					spdlog::error("Unable to open file {} for decoding.", infile);
					return 1;
				}
				switch(parameters->decod_format)
				{
					case GRK_J2K_FMT:
						break;
					case GRK_JP2_FMT:
						break;
					default:
						spdlog::error("Unknown input file format: {} \n"
									  "        Known file formats are *.j2k, *.jp2 or *.jpc",
									  infile);
						return 1;
				}
			}
			else
			{
				parameters->decod_format = GRK_J2K_FMT;
			}
			if(grk::strcpy_s(parameters->infile, sizeof(parameters->infile), infile) != 0)
			{
				spdlog::error("Path is too long");
				return 1;
			}
		}
		if(outForArg.isSet())
		{
			char outformat[50];
			const char* of = outForArg.getValue().c_str();
			sprintf(outformat, ".%s", of);
			inputFolder->set_out_format = true;
			parameters->cod_format = (GRK_SUPPORTED_FILE_FMT)get_file_format(outformat);
			switch(parameters->cod_format)
			{
				case GRK_PGX_FMT:
					inputFolder->out_format = "pgx";
					break;
				case GRK_PXM_FMT:
					inputFolder->out_format = "ppm";
					break;
				case GRK_BMP_FMT:
					inputFolder->out_format = "bmp";
					break;
				case GRK_JPG_FMT:
					inputFolder->out_format = "jpg";
					break;
				case GRK_TIF_FMT:
					inputFolder->out_format = "tif";
					break;
				case GRK_RAW_FMT:
					inputFolder->out_format = "raw";
					break;
				case GRK_RAWL_FMT:
					inputFolder->out_format = "rawl";
					break;
				case GRK_PNG_FMT:
					inputFolder->out_format = "png";
					break;
				default:
					spdlog::error("Unknown output format image {} [only *.png, *.pnm, *.pgm, "
								  "*.ppm, *.pgx, *.bmp, *.tif, *.jpg, *.jpeg, *.raw or *.rawl]",
								  outformat);
					return 1;
			}
		}
		if(outputFileArg.isSet())
		{
			const char* outfile = outputFileArg.getValue().c_str();
			parameters->cod_format = (GRK_SUPPORTED_FILE_FMT)get_file_format(outfile);
			switch(parameters->cod_format)
			{
				case GRK_PGX_FMT:
				case GRK_PXM_FMT:
				case GRK_BMP_FMT:
				case GRK_TIF_FMT:
				case GRK_RAW_FMT:
				case GRK_RAWL_FMT:
				case GRK_PNG_FMT:
				case GRK_JPG_FMT:
					break;
				default:
					spdlog::error(
						"Unknown output format image {} [only *.png, *.pnm, *.pgm, *.ppm, *.pgx, "
						"*.bmp, *.tif, *.tiff, *jpg, *jpeg, *.raw or *rawl]",
						outfile);
					return 1;
			}
			if(grk::strcpy_s(parameters->outfile, sizeof(parameters->outfile), outfile) != 0)
			{
				spdlog::error("Path is too long");
				return 1;
			}
		}
		else
		{
			// check for possible output to STDOUT
			if(!imgDirArg.isSet())
			{
				bool toStdout =
					outForArg.isSet() &&
					grk::supportedStdioFormat((GRK_SUPPORTED_FILE_FMT)parameters->cod_format);
				if(!toStdout)
				{
					spdlog::error("Missing output file");
					return 1;
				}
			}
		}
		if(outDirArg.isSet())
		{
			if(outFolder)
			{
				outFolder->imgdirpath = (char*)malloc(strlen(outDirArg.getValue().c_str()) + 1);
				strcpy(outFolder->imgdirpath, outDirArg.getValue().c_str());
				outFolder->set_imgdir = true;
			}
		}

		if(imgDirArg.isSet())
		{
			inputFolder->imgdirpath = (char*)malloc(strlen(imgDirArg.getValue().c_str()) + 1);
			strcpy(inputFolder->imgdirpath, imgDirArg.getValue().c_str());
			inputFolder->set_imgdir = true;
		}

		if(reduceArg.isSet())
		{
			if(reduceArg.getValue() >= GRK_J2K_MAXRLVLS)
				spdlog::warn("Resolution level reduction %d must be strictly less than the "
							 "maximum number of resolutions %u. Ignoring",
							 reduceArg.getValue(), GRK_J2K_MAXRLVLS);
			else
				parameters->core.reduce = (uint8_t)reduceArg.getValue();
		}
		if(layerArg.isSet())
			parameters->core.max_layers = layerArg.getValue();
		parameters->singleTileDecompress = tileArg.isSet();
		if(tileArg.isSet())
			parameters->tileIndex = (uint16_t)tileArg.getValue();
		if(precisionArg.isSet() && !parsePrecision(precisionArg.getValue().c_str(), parameters))
			return 1;
		if(numThreadsArg.isSet())
			parameters->numThreads = numThreadsArg.getValue();
		if(decodeRegionArg.isSet())
		{
			size_t size_optarg = (size_t)strlen(decodeRegionArg.getValue().c_str()) + 1U;
			char* ROI_values = (char*)malloc(size_optarg);
			if(ROI_values == nullptr)
			{
				spdlog::error("Couldn't allocate memory");
				return 1;
			}
			ROI_values[0] = '\0';
			memcpy(ROI_values, decodeRegionArg.getValue().c_str(), size_optarg);
			/*printf("ROI_values = %s [%d / %d]\n", ROI_values, strlen(ROI_values), size_optarg );
			 */
			int rc = parseWindowBounds(ROI_values, &parameters->dw_x0, &parameters->dw_y0,
									   &parameters->dw_x1, &parameters->dw_y1);
			free(ROI_values);
			if(rc)
				return 1;
		}

		if(pluginPathArg.isSet() && pluginPath)
			strcpy(pluginPath, pluginPathArg.getValue().c_str());
		if(repetitionsArg.isSet())
			parameters->repeats = repetitionsArg.getValue();
		if(kernelBuildOptionsArg.isSet())
			parameters->kernelBuildOptions = kernelBuildOptionsArg.getValue();
		if(deviceIdArg.isSet())
			parameters->deviceId = deviceIdArg.getValue();
		if(durationArg.isSet())
			parameters->duration = durationArg.getValue();
	}
	catch(TCLAP::ArgException& e) // catch any exceptions
	{
		std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}
#if 0
    case 'h': 			/* display an help description */
        decompress_help_display();
        return 1;
#endif

	/* check for possible errors */
	if(inputFolder->set_imgdir)
	{
		if(!(parameters->infile[0] == 0))
		{
			spdlog::error("options -ImgDir and -i cannot be used together.");
			return 1;
		}
		if(!inputFolder->set_out_format)
		{
			spdlog::error("When -ImgDir is used, -OutFor <FORMAT> must be used.");
			spdlog::error("Only one format allowed.\n"
						  "Valid format are PGM, PPM, PNM, PGX, BMP, TIF and RAW.");
			return 1;
		}
		if(!((parameters->outfile[0] == 0)))
		{
			spdlog::error("options -ImgDir and -o cannot be used together.");
			return 1;
		}
	}
	else
	{
		if(parameters->decod_format == GRK_UNK_FMT)
		{
			if((parameters->infile[0] == 0) || (parameters->outfile[0] == 0))
			{
				spdlog::error("Required parameters are missing\n"
							  "Example: {} -i image.j2k -o image.pgm",
							  argv[0]);
				spdlog::error("   Help: {} -h", argv[0]);
				return 1;
			}
		}
	}
	return 0;
}
void GrkDecompress::setDefaultParams(grk_decompress_parameters* parameters)
{
	if(parameters)
	{
		memset(parameters, 0, sizeof(grk_decompress_parameters));
		grk_decompress_set_default_params(&(parameters->core));
		parameters->deviceId = 0;
		parameters->repeats = 1;
		parameters->compressionLevel = GRK_DECOMPRESS_COMPRESSION_LEVEL_DEFAULT;
	}
}

void GrkDecompress::destoryParams(grk_decompress_parameters* parameters)
{
	if(parameters)
	{
		free(parameters->precision);
		parameters->precision = nullptr;
	}
}

void MycmsLogErrorHandlerFunction(cmsContext ContextID, cmsUInt32Number ErrorCode, const char* Text)
{
	GRK_UNUSED(ContextID);
	GRK_UNUSED(ErrorCode);
	spdlog::warn(" LCMS error: {}", Text);
}

static int decompress_callback(grk_plugin_decompress_callback_info* info);

// returns 0 for failure, 1 for success, and 2 if file is not suitable for decoding
int GrkDecompress::decompress(const std::string& fileName, DecompressInitParams* initParams)
{
	if(initParams->inputFolder.set_imgdir)
	{
		if(nextFile(fileName, &initParams->inputFolder,
					initParams->outFolder.set_imgdir ? &initParams->outFolder
													 : &initParams->inputFolder,
					&initParams->parameters))
		{
			return 2;
		}
	}
	grk_plugin_decompress_callback_info info;
	memset(&info, 0, sizeof(grk_plugin_decompress_callback_info));
	info.decod_format = GRK_UNK_FMT;
	info.decompress_flags = GRK_DECODE_ALL;
	info.decompressor_parameters = &initParams->parameters;
	info.user_data = this;
	info.cod_format = (GRK_SUPPORTED_FILE_FMT)(info.cod_format != GRK_UNK_FMT
												   ? info.cod_format
												   : info.decompressor_parameters->cod_format);
	info.header_info.decompressFormat = info.cod_format;
	info.header_info.forceRGB = info.decompressor_parameters->force_rgb;
	info.header_info.upsample = info.decompressor_parameters->upsample;
	info.header_info.precision = info.decompressor_parameters->precision;
	info.header_info.numPrecision = info.decompressor_parameters->numPrecision;
	info.header_info.splitByComponent = info.decompressor_parameters->split_pnm;
	if(preProcess(&info))
	{
		grk_object_unref(info.codec);
		return 0;
	}
	if(postProcess(&info))
	{
		grk_object_unref(info.codec);
		return 0;
	}
#ifdef GROK_HAVE_EXIFTOOL
	if(initParams->transferExifTags && initParams->parameters.decod_format == GRK_JP2_FMT)
		transferExifTags(initParams->parameters.infile, initParams->parameters.outfile);
#endif
	grk_object_unref(info.codec);
	info.codec = nullptr;
	return 1;
}

int GrkDecompress::pluginMain(int argc, char** argv, DecompressInitParams* initParams)
{
	grk_dircnt* dirptr = nullptr;
	int32_t success = 0;
	uint32_t numDecompressed = 0;
	bool isBatch = false;
	std::chrono::time_point<std::chrono::high_resolution_clock> start;

	cmsSetLogErrorHandler(MycmsLogErrorHandlerFunction);
	setDefaultParams(&initParams->parameters);
	if(parseCommandLine(argc, argv, initParams) == 1)
		return EXIT_FAILURE;
#ifdef GROK_HAVE_LIBTIFF
	tiffSetErrorAndWarningHandlers(initParams->parameters.verbose_);
#endif
#ifdef GROK_HAVE_LIBPNG
	pngSetVerboseFlag(initParams->parameters.verbose_);
#endif
	initParams->initialized = true;
	// loads plugin but does not actually create codec
	if(!grk_initialize(initParams->pluginPath, initParams->parameters.numThreads))
	{
		success = 1;
		goto cleanup;
	}
	// create codec
	grk_plugin_init_info initInfo;
	initInfo.deviceId = initParams->parameters.deviceId;
	initInfo.verbose = initParams->parameters.verbose_;
	if(!grk_plugin_init(initInfo))
	{
		success = 1;
		goto cleanup;
	}
	isBatch = initParams->inputFolder.imgdirpath && initParams->outFolder.imgdirpath;
	if((grk_plugin_get_debug_state() & GRK_PLUGIN_STATE_DEBUG))
		isBatch = false;
	if(isBatch)
	{
		// initialize batch
		setUpSignalHandler();
		success = grk_plugin_init_batch_decompress(initParams->inputFolder.imgdirpath,
												   initParams->outFolder.imgdirpath,
												   &initParams->parameters, decompress_callback);
		// start batch
		if(success)
			success = grk_plugin_batch_decompress();
		// if plugin successfully begins batch compress, then wait for batch to complete
		if(success == 0)
		{
			uint32_t slice = 100; // ms
			uint32_t slicesPerSecond = 1000 / slice;
			uint32_t seconds = initParams->parameters.duration;
			if(!seconds)
				seconds = UINT_MAX;
			for(uint32_t i = 0U; i < seconds * slicesPerSecond; ++i)
			{
				batch_sleep(1);
				if(grk_plugin_is_batch_complete())
				{
					break;
				}
			}
			grk_plugin_stop_batch_decompress();
		}
	}
	else
	{
		start = std::chrono::high_resolution_clock::now();
		if(!initParams->inputFolder.set_imgdir)
		{
			success = grk_plugin_decompress(&initParams->parameters, decompress_callback);
		}
		else
		{
			for(const auto& entry :
				std::filesystem::directory_iterator(initParams->inputFolder.imgdirpath))
			{
				if(nextFile(entry.path().filename().string(), &initParams->inputFolder,
							initParams->outFolder.imgdirpath ? &initParams->outFolder
															 : &initParams->inputFolder,
							&initParams->parameters))
				{
					continue;
				}
				success = grk_plugin_decompress(&initParams->parameters, decompress_callback);
				if(success != 0)
					goto cleanup;
				numDecompressed++;
				if(success != 0)
					break;
			}
		}
		printTiming(numDecompressed, std::chrono::high_resolution_clock::now() - start);
	}
cleanup:
	if(dirptr)
	{
		free(dirptr->filename_buf);
		free(dirptr->filename);
		free(dirptr);
	}
	return success;
}

int decompress_callback(grk_plugin_decompress_callback_info* info)
{
	int rc = -1;
	// GRK_DECODE_T1 flag specifies full decompress on CPU, so
	// we don't need to initialize the decompressor in this case
	if(info->decompress_flags & GRK_DECODE_T1)
	{
		info->init_decompressors_func = nullptr;
	}
	if(info->decompress_flags & GRK_PLUGIN_DECODE_CLEAN)
	{
		if(info->stream)
			grk_object_unref(info->stream);
		info->stream = nullptr;
		grk_object_unref(info->codec);
		info->codec = nullptr;
		if(info->image && !info->plugin_owns_image)
			info->image = nullptr;
		rc = 0;
	}
	auto decompressor = (GrkDecompress*)info->user_data;
	if(info->decompress_flags & (GRK_DECODE_HEADER | GRK_DECODE_T1 | GRK_DECODE_T2))
	{
		rc = decompressor->preProcess(info);
		if(rc)
			return rc;
	}
	if(info->decompress_flags & GRK_DECODE_POST_T1)
		rc = decompressor->postProcess(info);
	return rc;
}

enum grk_stream_type
{
	GRK_FILE_STREAM,
	GRK_MAPPED_FILE_STREAM
};

grk_stream_type stream_type = GRK_MAPPED_FILE_STREAM;

static void cleanUpFile(const char* outfile)
{
	if(!outfile)
		return;

	bool allocated = false;
	char* p = actual_path(outfile, &allocated);
	GRK_UNUSED(remove)(p);
	if(allocated)
		free(p);
}

static void grkSerializeRegisterClientCallback(grk_serialize_callback reclaim_callback,
											   void* serialize_user_data, void* reclaim_user_data)
{
	if(!serialize_user_data || !reclaim_user_data)
		return;
	auto imageFormat = (IImageFormat*)serialize_user_data;

	imageFormat->serializeRegisterClientCallback(reclaim_callback, reclaim_user_data);
}

static bool grkSerializeBufferCallback(grk_serialize_buf buffer, void* user_data)
{
	if(!user_data)
		return false;
	auto imageFormat = (IImageFormat*)user_data;

	return imageFormat->encodePixels(buffer);
}

bool GrkDecompress::encodeHeader(grk_plugin_decompress_callback_info* info)
{
	if(!storeToDisk)
		return true;
	if(!encodeInit(info))
		return false;
	if(!imageFormat->encodeHeader())
	{
		spdlog::error("Encode header failed.");
		return false;
	}

	return true;
}

bool GrkDecompress::encodeInit(grk_plugin_decompress_callback_info* info)
{
	if(!storeToDisk)
		return true;
	auto parameters = info->decompressor_parameters;
	const char* outfile = info->decompressor_parameters->outfile[0]
							  ? info->decompressor_parameters->outfile
							  : info->output_file_name;
	auto cod_format =
		(GRK_SUPPORTED_FILE_FMT)(info->cod_format != GRK_UNK_FMT ? info->cod_format
																 : parameters->cod_format);
	auto outfileStr = outfile ? std::string(outfile) : "";
	uint32_t compressionLevel = 0;
	if(cod_format == GRK_TIF_FMT)
		compressionLevel = parameters->compression;
	else if(cod_format == GRK_JPG_FMT || cod_format == GRK_PNG_FMT)
		compressionLevel = parameters->compressionLevel;
	if(!imageFormat->encodeInit(info->image, outfileStr, compressionLevel))
	{
		spdlog::error("Outfile {} not generated", outfileStr);
		return false;
	}

	return true;
}

// return: 0 for success, non-zero for failure
int GrkDecompress::preProcess(grk_plugin_decompress_callback_info* info)
{
	if(!info)
		return 1;
	bool failed = true;
	bool useMemoryBuffer = false;
	auto parameters = info->decompressor_parameters;
	if(!parameters)
		return 1;
	auto infile = info->input_file_name ? info->input_file_name : parameters->infile;
	int decod_format =
		info->decod_format != GRK_UNK_FMT ? info->decod_format : parameters->decod_format;
	const char* outfile = info->decompressor_parameters->outfile[0]
							  ? info->decompressor_parameters->outfile
							  : info->output_file_name;
	auto cod_format =
		(GRK_SUPPORTED_FILE_FMT)(info->cod_format != GRK_UNK_FMT ? info->cod_format
																 : parameters->cod_format);
	switch(cod_format)
	{
		case GRK_PXM_FMT:
			imageFormat = new PNMFormat(parameters->split_pnm);
			break;
		case GRK_PGX_FMT:
			imageFormat = new PGXFormat();
			break;
		case GRK_BMP_FMT:
			imageFormat = new BMPFormat();
			break;
#ifdef GROK_HAVE_LIBTIFF
		case GRK_TIF_FMT:
			imageFormat = new TIFFFormat();
			break;
#endif
		case GRK_RAW_FMT:
			imageFormat = new RAWFormat(true);
			break;
		case GRK_RAWL_FMT:
			imageFormat = new RAWFormat(false);
			break;
#ifdef GROK_HAVE_LIBJPEG
		case GRK_JPG_FMT:
			imageFormat = new JPEGFormat();
			break;
#endif
#ifdef GROK_HAVE_LIBPNG
		case GRK_PNG_FMT:
			imageFormat = new PNGFormat();
			break;
#endif
		default:
			spdlog::error("Unsupported output format {}", convertFileFmtToString(info->cod_format));
			goto cleanup;
			break;
	}
	parameters->core.serialize_buffer_callback = grkSerializeBufferCallback;
	parameters->core.serialize_user_data = imageFormat;
	parameters->core.serialize_register_client_callback = grkSerializeRegisterClientCallback;

	// 1. initialize
	if(!info->stream)
	{
		if(useMemoryBuffer)
		{
			// Reading value from file
			auto in = fopen(infile, "r");
			if(in)
			{
				GRK_FSEEK(in, 0L, SEEK_END);
				int64_t sz = GRK_FTELL(in);
				if(sz == -1)
				{
					spdlog::error("grk_decompress: ftell error from file {}", sz, infile);
					goto cleanup;
				}
				rewind(in);
				auto memoryBuffer = new uint8_t[(size_t)sz];
				size_t ret = fread(memoryBuffer, 1, (size_t)sz, in);
				if(ret != (size_t)sz)
				{
					spdlog::error("grk_decompress: error reading {} bytes from file {}", sz,
								  infile);
					goto cleanup;
				}
				int rc = fclose(in);
				if(rc)
				{
					spdlog::error("grk_decompress: error closing file {}", infile);
					goto cleanup;
				}
				if(ret == (size_t)sz)
					info->stream =
						grk_stream_create_mem_stream(memoryBuffer, (size_t)sz, true, true);
				else
				{
					spdlog::error("grk_decompress: failed to create memory stream for file {}",
								  infile);
					goto cleanup;
				}
			}
			else
			{
				goto cleanup;
			}
		}
		else
		{
			if(stream_type == GRK_MAPPED_FILE_STREAM)
				info->stream = grk_stream_create_mapped_file_stream(infile, true);
			else
				info->stream = grk_stream_create_file_stream(infile, 1024 * 1024, true);
		}
	}
	if(!info->stream)
	{
		spdlog::error("grk_decompress: failed to create a stream from file {}", infile);
		goto cleanup;
	}
	if(!info->codec)
	{
		switch(decod_format)
		{
			case GRK_J2K_FMT: { /* JPEG 2000 code stream */
				info->codec = grk_decompress_create(GRK_CODEC_J2K, info->stream);
				break;
			}
			case GRK_JP2_FMT: { /* JPEG 2000 compressed image data */
				info->codec = grk_decompress_create(GRK_CODEC_JP2, info->stream);
				break;
			}
			default:
				spdlog::error("grk_decompress: unknown decode format {}", decod_format);
				goto cleanup;
		}
		grk_set_msg_handlers(parameters->verbose_ ? infoCallback : nullptr, nullptr,
							 parameters->verbose_ ? warningCallback : nullptr, nullptr,
							 errorCallback, nullptr);

		if(!grk_decompress_init(info->codec, &(parameters->core)))
		{
			spdlog::error("grk_decompress: failed to set up the decompressor");
			goto cleanup;
		}
	}
	// 2. read header
	if(info->decompress_flags & GRK_DECODE_HEADER)
	{
		// Read the main header of the code stream (j2k) and also JP2 boxes (jp2)
		if(!grk_decompress_read_header(info->codec, &info->header_info))
		{
			spdlog::error("grk_decompress: failed to read the header");
			goto cleanup;
		}
		info->image = grk_decompress_get_composited_image(info->codec);

		// do not allow odd top left window coordinates for SYCC
		if(info->image->color_space == GRK_CLRSPC_SYCC)
		{
			bool adjustX = (info->decompressor_parameters->dw_x0 != info->full_image_x0) &&
						   (info->decompressor_parameters->dw_x0 & 1);
			bool adjustY = (info->decompressor_parameters->dw_y0 != info->full_image_y0) &&
						   (info->decompressor_parameters->dw_y0 & 1);
			if(adjustX || adjustY)
			{
				spdlog::error(
					"grk_decompress: Top left-hand window coordinates that do not coincide\n"
					"with respective top left-hand image coordinates must be even");
				goto cleanup;
			}
		}

		// store XML to file
		if(info->header_info.xml_data && info->header_info.xml_data_len &&
		   parameters->serialize_xml)
		{
			std::string xmlFile = std::string(parameters->outfile) + ".xml";
			auto fp = fopen(xmlFile.c_str(), "wb");
			if(!fp)
			{
				spdlog::error("grk_decompress: unable to open file {} for writing xml to",
							  xmlFile.c_str());
				goto cleanup;
			}
			if(fwrite(info->header_info.xml_data, 1, info->header_info.xml_data_len, fp) !=
			   info->header_info.xml_data_len)
			{
				spdlog::error("grk_decompress: unable to write all xml data to file {}",
							  xmlFile.c_str());
				fclose(fp);
				goto cleanup;
			}
			if(!grk::safe_fclose(fp))
			{
				spdlog::error("grk_decompress: error closing file {}", infile);
				goto cleanup;
			}
		}
		if(info->init_decompressors_func)
			return info->init_decompressors_func(&info->header_info, info->image);
	}
	if(info->image)
	{
		info->full_image_x0 = info->image->x0;
		info->full_image_y0 = info->image->y0;
	}
	// header-only decompress
	if(info->decompress_flags == GRK_DECODE_HEADER)
		goto cleanup;
	// 3. decompress
	if(info->tile)
		info->tile->decompress_flags = info->decompress_flags;
	// limit to 16 bit precision
	for(uint32_t i = 0; i < info->image->numcomps; ++i)
	{
		if(info->image->comps[i].prec > 16)
		{
			spdlog::error("grk_decompress: Precision = {} not supported:",
						  info->image->comps[i].prec);
			goto cleanup;
		}
	}
	if(!grk_decompress_set_window(info->codec, parameters->dw_x0, parameters->dw_y0,
								  parameters->dw_x1, parameters->dw_y1))
	{
		spdlog::error("grk_decompress: failed to set the decompressed area");
		goto cleanup;
	}
	if(!encodeInit(info))
		return false;

	// decompress all tiles
	if(!parameters->singleTileDecompress)
	{
		if(!(grk_decompress(info->codec, info->tile) && grk_decompress_end(info->codec)))
			goto cleanup;
	}
	// or, decompress one particular tile
	else
	{
		if(!grk_decompress_tile(info->codec, parameters->tileIndex))
		{
			spdlog::error("grk_decompress: failed to decompress tile");
			goto cleanup;
		}
	}
	if(!encodeHeader(info))
		goto cleanup;
	failed = false;
cleanup:
	grk_object_unref(info->stream);
	info->stream = nullptr;
	if(failed)
	{
		cleanUpFile(outfile);
		info->image = nullptr;
		delete imageFormat;
		imageFormat = nullptr;
	}

	return failed ? 1 : 0;
}

/*
 Post-process decompressed image and store in selected image format
 */
int GrkDecompress::postProcess(grk_plugin_decompress_callback_info* info)
{
	if(!info)
		return -1;
	auto fmt = imageFormat;
	bool failed = true;
	bool imageNeedsDestroy = false;
	auto image = info->image;
	const char* infile = info->decompressor_parameters->infile[0]
							 ? info->decompressor_parameters->infile
							 : info->input_file_name;
	const char* outfile = info->decompressor_parameters->outfile[0]
							  ? info->decompressor_parameters->outfile
							  : info->output_file_name;
	if(image->meta)
	{
		if(image->meta->xmp_buf)
		{
			bool canStoreXMP = (info->decompressor_parameters->cod_format == GRK_TIF_FMT ||
								info->decompressor_parameters->cod_format == GRK_PNG_FMT);
			if(!canStoreXMP)
			{
				spdlog::warn(" Input file `{}` contains XMP meta-data,\nbut the file format for "
							 "output file `{}` does not support storage of this data.",
							 infile, outfile);
			}
		}
		if(image->meta->iptc_buf)
		{
			bool canStoreIPTC_IIM = (info->decompressor_parameters->cod_format == GRK_TIF_FMT);
			if(!canStoreIPTC_IIM)
			{
				spdlog::warn(
					" Input file `{}` contains legacy IPTC-IIM meta-data,\nbut the file format "
					"for output file `{}` does not support storage of this data.",
					infile, outfile);
			}
		}
	}
	if(storeToDisk)
	{
		auto outfileStr = outfile ? std::string(outfile) : "";
		if(!fmt->encodePixels())
		{
			spdlog::error("Outfile {} not generated", outfileStr);
			goto cleanup;
		}
		if(!fmt->encodeFinish())
		{
			spdlog::error("Outfile {} not generated", outfileStr);
			goto cleanup;
		}
	}
	failed = false;
cleanup:
	grk_object_unref(info->stream);
	info->stream = nullptr;
	grk_object_unref(info->codec);
	info->codec = nullptr;
	if(image && imageNeedsDestroy)
	{
		grk_object_unref(&image->obj);
		info->image = nullptr;
	}
	delete imageFormat;
	imageFormat = nullptr;
	if(failed)
		cleanUpFile(outfile);

	return failed ? 1 : 0;
}
int GrkDecompress::main(int argc, char** argv)
{
	int rc = EXIT_SUCCESS;
	uint32_t numDecompressed = 0;
	DecompressInitParams initParams;
	try
	{
		// try to decompress with plugin
		int plugin_rc = pluginMain(argc, argv, &initParams);

		// return immediately if either
		// initParams was not initialized (something was wrong with command line params)
		// or
		// plugin was successful
		if(!initParams.initialized)
		{
			rc = EXIT_FAILURE;
			goto cleanup;
		}
		if(plugin_rc == EXIT_SUCCESS)
		{
			rc = EXIT_SUCCESS;
			goto cleanup;
		}
		auto start = std::chrono::high_resolution_clock::now();
		for(uint32_t i = 0; i < initParams.parameters.repeats; ++i)
		{
			std::string filename;
			if(!initParams.inputFolder.set_imgdir)
			{
				if(decompress(filename, &initParams) == 1)
				{
					numDecompressed++;
				}
				else
				{
					rc = EXIT_FAILURE;
					goto cleanup;
				}
			}
			else
			{
				for(const auto& entry :
					std::filesystem::directory_iterator(initParams.inputFolder.imgdirpath))
				{
					if(decompress(entry.path().filename().string(), &initParams) == 1)
						numDecompressed++;
				}
			}
		}
		printTiming(numDecompressed, std::chrono::high_resolution_clock::now() - start);
	}
	catch(std::bad_alloc& ba)
	{
		GRK_UNUSED(ba);
		spdlog::error("Out of memory. Exiting.");
		rc = 1;
		goto cleanup;
	}
cleanup:
	destoryParams(&initParams.parameters);
	grk_deinitialize();
	return rc;
}
GrkDecompress::GrkDecompress() : storeToDisk(true), imageFormat(nullptr) {}
GrkDecompress::~GrkDecompress(void)
{
	delete imageFormat;
	imageFormat = nullptr;
}

} // namespace grk

int main(int argc, char** argv)
{
	grk::GrkDecompress decomp;
	return decomp.main(argc, argv);
}
