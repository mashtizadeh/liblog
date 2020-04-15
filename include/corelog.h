/*
 * Copyright (c) 2012-2020 Ali Mashtizadeh
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header Magic:
 * mCOR ELOG Star tHdr
 *
 * Entry Magic:
 * CRLG
 *
 */

#define CORELOG_VERSION_MAJOR   1
#define CORELOG_VERSION_MINOR   0

#define CORELOG_HEADER_MAGIC0   0x6D434F52
#define CORELOG_HEADER_MAGIC1   0x454C4F47
#define CORELOG_HEADER_MAGIC2   0x53746172
#define CORELOG_HEADER_MAGIC3   0x74486472

typedef struct CoreLog_Header
{
    uint32_t    magic[4];
    uint16_t    majorVersion;
    uint16_t    minorVersion;
    uint32_t    length;
    uint32_t    free;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    alignment;
    // uint32_t lock;
    uint8_t     name[32];
} CoreLog_Header;

#define CORELOG_ENTRY_MAGIC     0x43524C47

#define CORELOG_FLAG_TYPEMASK   0x0F
#define CORELOG_FLAG_INVALID    0x00
#define CORELOG_FLAG_LOG        0x01
#define CORELOG_FLAG_WARNING    0x02
#define CORELOG_FLAG_ALERT      0x03
#define CORELOG_FLAG_HEXDUMP    0x04
#define CORELOG_FLAG_BACKTRACE  0x05
#define CORELOG_FLAG_STACKDUMP  0x06
#define CORELOG_FLAG_OUTOFBAND  0x07
#define CORELOG_FLAG_PINNED     0x40
#define CORELOG_FLAG_VALID      0x80

typedef struct CoreLog_Entry
{
    uint32_t    magic;
    uint8_t     flags;
    uint8_t     logLevel;
    uint16_t    length;
    uint64_t    time;
} CoreLog_Entry;

int CoreLog_Init(void *buf, uint32_t bytes, const char *name);
void CoreLog_Destroy(void);
void CoreLog_Log(int logLevel, const char *fmtstr, ...);
void CoreLog_Warning(const char *fmtstr, ...);
void CoreLog_Alert(const char *fmtstr, ...);
void CoreLog_BinaryDump(int logLevel, const void *buf, int len);
void CoreLog_Backtrace(int depth);
void CoreLog_Stackdump(int depth);
void CoreLog_Flush(void);

#ifdef __cplusplus
}
#endif

