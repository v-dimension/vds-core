// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_SUPPORT_CLEANSE_H
#define VDS_SUPPORT_CLEANSE_H

#include <stdlib.h>
#include <stdarg.h>

void memory_cleanse(void *ptr, size_t len);

#define var_clean(...) _var_clean(sizeof(*(_va_first(__VA_ARGS__))), __VA_ARGS__, NULL)
#define _va_first(first, ...) first

inline static void _var_clean(size_t size, ...)
{
    va_list args;
    va_start(args, size);
    for (void *ptr = va_arg(args, void *); ptr; ptr = va_arg(args, void *)) memory_cleanse(ptr, size);
    va_end(args);
}

#endif // VDS_SUPPORT_CLEANSE_H
