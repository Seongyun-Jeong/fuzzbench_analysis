## World's Leading Open Source JPEG 2000 Codec

[![badge-license]][link-license]

<span>
 <a href="https://jpeg.org/jpeg2000/index.html" target="_blank">
  <img src="https://jpeg.org/images/jpeg2000-logo.svg" width=200, height=200 />
 </a>
</span>
<p>


### Features

* support for new **High Throughput JPEG 2000 (HTJ2K)** standard
* fast random-access sub-image decoding using `TLM` and `PLT` markers
* full encode/decode support for `ICC` colour profiles
* full encode/decode support for `XML`,`IPTC`, `XMP` and `EXIF` meta-data
* full encode/decode support for `monochrome`, `sRGB`, `palette`, `YCC`, `extended YCC`, `CIELab` and `CMYK` colour spaces
* full encode/decode support for `JPEG`,`PNG`,`BMP`,`TIFF`,`RAW`,`PNM` and `PAM` image formats
* full encode/decode support for 1-16 bit precision images

### Performance

Below is a benchmark comparing time and memory performance for **Kakadu 8.05**, **Grok 9.7** and **OpenJPEG 2.5** on the following workflows:

1. decompress full [large single-tiled image of Mars](http://hirise-pds.lpl.arizona.edu/PDS/RDR/ESP/ORB_011200_011299/ESP_011277_1825/ESP_011277_1825_RED.JP2) to TIF output
1. decompress region {1000,1000,5000,5000} from [large single-tiled image of Mars](http://hirise-pds.lpl.arizona.edu/PDS/RDR/ESP/ORB_011200_011299/ESP_011277_1825/ESP_011277_1825_RED.JP2) to TIF output
1. decompress full [large multi-tiled Pleiades image](https://l3harrisgeospatial-webcontent.s3.amazonaws.com/MM_Samples/Pleiades_ORTHO_UTM_BUNDLE.zip) to TIF output.
1. decompress full [large multi-tiled Pleiades image](https://l3harrisgeospatial-webcontent.s3.amazonaws.com/MM_Samples/Pleiades_ORTHO_UTM_BUNDLE.zip) to PGM output.

#### Benchmark Details

* test system : 24 core / 48 thread `AMD Threadripper`
running `Ubuntu 21.04` with `5.11` Linux kernel
* codecs were configured to use all 48 threads
* file cache was cleared between runs using `$ sudo sysctl vm.drop_caches=3`
* open source codecs were built in release mode using `GCC 11`

#### Results

| Test  | Kakadu             | Grok                 | OpenJPEG           |
| :---- | :-----             | :------:             | --------:          |
| 1     | 9.81 s / 0.05 GB   | 17.0 s / 13.1 GB     | 17.8 s / 13.1 GB   |
| 2     | 0.12 s             | 0.25 s / 0.4 GB      | 1.4 s  / 2 GB      |
| 3     | 4.99 s / 0.1 GB    | 3.97 s / 1.8 GB      | 10.8 s / 4.3 GB    |
| 4     | 4.19 s / 0.1 GB    | 4.37 s / 2.0 GB      | 45.7 s / 4.3 GB    |

### Library Details

* [INSTALL](https://github.com/GrokImageCompression/grok/blob/master/INSTALL.md)
* [WIKI](https://github.com/GrokImageCompression/grok/wiki)
* [LICENSE][link-license]

### Current Build Status
[![badge-actions]][link-actions]
[![badge-msvc-build]][link-msvc-build]
[![badge-oss-fuzz]][link-oss-fuzz]  

[badge-license]: https://img.shields.io/badge/License-AGPL%20v3-blue.svg
[link-license]: https://github.com/GrokImageCompression/grok/blob/master/LICENSE
[badge-actions]: https://github.com/GrokImageCompression/grok/actions/workflows/cmake.yml/badge.svg?branch=master
[link-actions]: https://github.com/GrokImageCompression/grok/actions
[badge-msvc-build]: https://ci.appveyor.com/api/projects/status/github/GrokImageCompression/grok?branch=master&svg=true
[link-msvc-build]: https://ci.appveyor.com/project/boxerab/grok/branch/master
[badge-oss-fuzz]: https://oss-fuzz-build-logs.storage.googleapis.com/badges/grok.svg
[link-oss-fuzz]: https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:grok
