//***************************************************************************/
// This software is released under the 2-Clause BSD license, included
// below.
//
// Copyright (c) 2019, Aous Naman 
// Copyright (c) 2019, Kakadu Software Pty Ltd, Australia
// Copyright (c) 2019, The University of New South Wales, Australia
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//***************************************************************************/
// This file is part of the OpenJPH software implementation.
// File: ojph_arch.h
// Author: Aous Naman
// Date: 28 August 2019
//***************************************************************************/


#ifndef OJPH_ARCH_H
#define OJPH_ARCH_H

#include <cstdio>
#include <cstdint>
#ifdef _MSC_VER
#define _USE_MATH_DEFINES // for C++
#endif
#include <cmath>

#include "ojph_defs.h"

namespace ojph {
  #ifdef _MSC_VER
    #define OJPH_COMPILER_MSVC
  #elif (defined __GNUC__)
    #define OJPH_COMPILER_GNUC
  #endif

  #ifdef OJPH_COMPILER_MSVC
  #include <intrin.h>
  #endif

  static inline ui32 population_count(ui32 val)
  {
  #ifdef OJPH_COMPILER_MSVC
    return (ui32)__popcnt(val);
  #elif (defined OJPH_COMPILER_GNUC)
    return (ui32)__builtin_popcount(val);
  #else
    val -= ((val >> 1) & 0x55555555);
    val = (((val >> 2) & 0x33333333) + (val & 0x33333333));
    val = (((val >> 4) + val) & 0x0f0f0f0f);
    val += (val >> 8);
    val += (val >> 16);
    return (int)(val & 0x0000003f);
  #endif
  }

  /////////////////////////////////////////////////////////////////////////////
#ifdef OJPH_COMPILER_MSVC
  #pragma intrinsic(_BitScanReverse)
#endif
  static inline ui32 count_leading_zeros(ui32 val)
  {
  #ifdef OJPH_COMPILER_MSVC
    unsigned long result = 0;
    _BitScanReverse(&result, val);
    return 31 ^ (ui32)result;
  #elif (defined OJPH_COMPILER_GNUC)
    return (ui32)__builtin_clz(val);
  #else
    val |= (val >> 1);
    val |= (val >> 2);
    val |= (val >> 4);
    val |= (val >> 8);
    val |= (val >> 16);
    return 32 - population_count(val);
  #endif
  }

  ////////////////////////////////////////////////////////////////////////////
  // constants
  ////////////////////////////////////////////////////////////////////////////
  const ui32 byte_alignment = 32; //32 bytes == 256 bits
  const ui32 log_byte_alignment = 31 - count_leading_zeros(byte_alignment);
  const ui32 object_alignment = 8;

  ////////////////////////////////////////////////////////////////////////////
  // finds the size such that it is a multiple of byte_alignment
  template <typename T, int N>
  size_t calc_aligned_size(size_t size) {
    size = size * sizeof(T) + N - 1;
    size &= ~((1ULL << (31 - count_leading_zeros(N))) - 1);
    size >>= (31 - count_leading_zeros(sizeof(T)));
    return size;
  }

  ////////////////////////////////////////////////////////////////////////////
  // moves the pointer to first address that is a multiple of byte_alignment
  template <typename T, int N>
  inline T *align_ptr(T *ptr) {
    intptr_t p = reinterpret_cast<intptr_t>(ptr);
    p += N - 1;
    p &= ~((intptr_t)(1ULL << (31 - count_leading_zeros(N))) - 1);
    return reinterpret_cast<T *>(p);
  }

}

#endif // !OJPH_ARCH_H
