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

#include <sys/types.h>
#include <sys/time.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <corelog.h>

/*
 * CoreLog
 *
 * CoreLog is an in memory logging tool used only when your application
 * coredumps. We provide the corelog command line tool to extract your
 * log and pretty print it. We provide a handful of useful services:
 *  - Log, Warning, Alert Messages
 *  - Stack Dumps
 *  - Hex Dumps
 *  - Out of Band (i.e. corelog failures)
 *
 * Requirements include that the CoreLog's data should be readable by the
 * command line tool at any point.
 *
 * Output Formatting:
 * YYYY-MM-DD HH:MM:SS.mmmm LOG(level): msg
 * YYYY-MM-DD HH:MM:SS.mmmm WARNING: msg
 * YYYY-MM-DD HH:MM:SS.mmmm ALERT: msg
 * YYYY-MM-DD HH:MM:SS.mmmm HEXDUMP(level): 0xSTARTADDRESS: description
 * 0000: XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |XXXXXXXXXXXXXXXX|
 * ...
 * nnnn: XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |XXXXXXXXXXXXXXXX|
 *
 * TODO:
 *  - Stackdumps (use elf/stubs data to extract eip's and stack layout).
 *  - Break locks when we timeout.
 *  - Allow us to skip regions of your log that have been pinned or have
 *    never been marked valid by a crashed thread.
 *  - Allow multiple seperate corelog instances.
 *  - Have the user allocate and free memory this makes corelog platform
 *    independent.
 *
 */

#define MAX_MSGSIZE             1024
#define MIN_CLEARSPACE          (10 * MAX_MSGSIZE)

// Lock
CoreLog_Header *header;
char *buf;

int
CoreLog_Init(void *bufToUse, uint32_t bytes, const char *name)
{
    uint32_t alignedHeader;

    // Read environment
    header = (CoreLog_Header *)bufToUse;

#ifdef LOG
    LOG(0, "CoreLog_Init(%016llx, %x)", (uintptr_t)bufToUse, bytes);
#endif

    // Zero the buffer just in case
    memset(bufToUse, 0, bytes);

    // Write magic and version info
    header->magic[0] = CORELOG_HEADER_MAGIC0;
    header->magic[1] = CORELOG_HEADER_MAGIC1;
    header->magic[2] = CORELOG_HEADER_MAGIC2;
    header->magic[3] = CORELOG_HEADER_MAGIC3;
    header->majorVersion = CORELOG_VERSION_MAJOR;
    header->minorVersion = CORELOG_VERSION_MINOR;

    // setup head, and tail
    header->head = 0;
    header->tail = 0;
    strncpy((char *)&(header->name), name, 31);
    header->name[31] = '\0';

    /*
     * I'm making some assumptions that the entries are 64 bits long.
     * Thus all allocations will be 64 bit aligned so we can always
     * ensure that the entry structure won't be broken across a boundry.
     */
    assert(sizeof(CoreLog_Entry) == 16);
    header->alignment = sizeof(CoreLog_Entry);

    /*
     * The buffer should be aligned to the same alignment boundry.
     */
    alignedHeader = (sizeof(*header) + sizeof(CoreLog_Entry) - 1)
                     /sizeof(CoreLog_Entry) * sizeof(CoreLog_Entry);
    buf = (char *)bufToUse + alignedHeader;
    header->length = bytes - alignedHeader;
    header->free = bytes - alignedHeader;

    return 0;
}

void
CoreLog_Destroy(void)
{
#ifdef LOG
    LOG(0, "CoreLog_Destroy()\n");
#endif

    memset((char *)header, 0, sizeof(CoreLog_Header));

    header = 0;
    buf = 0;
}

void
CoreLog_FreeBuffer(void)
{
    CoreLog_Entry *entry;
    uint32_t alignedLength;
    int space = 0;

    // Take lock

    // Start clearing the log
    while (space < MIN_CLEARSPACE)
    {
        // Find the new entry
        entry = (CoreLog_Entry *)(buf + header->tail);
        assert(entry->magic == CORELOG_ENTRY_MAGIC);
        // XXX: wait until valid

        // Calculate the actual length
        alignedLength = (entry->length + 2*sizeof(*entry) - 1)/sizeof(*entry)
                         * sizeof(*entry);
        space += alignedLength;

#ifdef LOG
        LOG(0, "CoreLog_FreeBuffer(): entry->length: %08x, alignedLength: %08x",
                entry->length, alignedLength);
#endif

        // Zero the buffer
        memset(entry, 0, (header->tail + alignedLength > header->length) ? header->length - header->tail : alignedLength);
        if (header->tail + alignedLength > header->length)
        {
            memset(buf, 0, alignedLength - header->length + header->tail);
        }

        // Calculate the new tail
        header->tail = (header->tail + alignedLength) % header->length;
    }

    header->free += space;

    // Release lock
}

CoreLog_Entry *
CoreLog_AllocBuffer(const void *data, int len)
{
    uint32_t start, alignedLength;
    CoreLog_Entry *entry;

    // Header and Buffer must be valid
    assert(header != 0);
    assert(buf != 0);

    alignedLength = (len + 2*sizeof(*entry) - 1)/sizeof(*entry)
                     * sizeof(*entry);

    // Lock

    // Make sure there is free space
    if (header->free < alignedLength) {
        CoreLog_FreeBuffer();
    }
    header->free -= alignedLength;

    // Alloc space (free if needed and timeout if we cant free a large chunk)
    start = header->head;
    header->head = (header->head + alignedLength) % header->length;

#ifdef LOG
    LOG(0, "CoreLog_AllocBuffer(): entry: %08x, payload: %08x, " \
           "entry->length: %08x, alignedLength: %08x",
           start, start + sizeof(*entry), len, alignedLength);
#endif

    // Unlock

    // Setup Entry
    entry = (CoreLog_Entry *)(buf + start);
    entry->magic = CORELOG_ENTRY_MAGIC;
    entry->length = len;
    assert(entry->flags == CORELOG_FLAG_INVALID);
    start += sizeof(*entry);

    // Copy Buffer
    memcpy(buf + start, data,
           (start + len > header->length) ? header->length - start : len);
    if (start + len > header->length)
    {
        memcpy(buf, data + header->length - start,
               len - header->length + start);
    }

    return entry;
}

static inline uint64_t
CoreLogGetTimestamp()
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void
CoreLog_Log(int logLevel, const char *fmtstr, ...)
{
    int n;
    va_list ap;
    char buffer[MAX_MSGSIZE];
    CoreLog_Entry *entry;

    va_start(ap, fmtstr);
    n = vsnprintf((char *)&buffer, MAX_MSGSIZE, fmtstr, ap);
    va_end(ap);

    if (n > 0)
    {
        /*
         * Note that vsnprintf will return the number of bytes not
         * includeing the NULL terminator. Thus, we add one here.
         */
        n = n > MAX_MSGSIZE ? MAX_MSGSIZE : (n + 1);
        entry = CoreLog_AllocBuffer((void *)&buffer, n);
        entry->logLevel = logLevel;
        entry->flags = CORELOG_FLAG_LOG | CORELOG_FLAG_VALID;
        entry->time = CoreLogGetTimestamp();
    }
}

/*
 * CoreLog_Warning
 *
 *      Prints a warning to the log.
 */
void
CoreLog_Warning(const char *fmtstr, ...)
{
    int n;
    va_list ap;
    char buffer[MAX_MSGSIZE];
    CoreLog_Entry *entry;

    va_start(ap, fmtstr);
    n = vsnprintf((char *)&buffer, MAX_MSGSIZE, fmtstr, ap);
    va_end(ap);

    if (n > 0)
    {
        /*
         * Note that vsnprintf will return the number of bytes not
         * includeing the NULL terminator. Thus, we add one here.
         */
        n = n > MAX_MSGSIZE ? MAX_MSGSIZE : (n + 1);
        entry = CoreLog_AllocBuffer((void *)&buffer, n);
        entry->logLevel = 0;
        entry->flags = CORELOG_FLAG_WARNING | CORELOG_FLAG_VALID;
        entry->time = CoreLogGetTimestamp();
    }
}

void
CoreLog_Alert(const char *fmtstr, ...)
{
}

/*
 * CoreLog_BinaryDump
 *
 *      Dumps a binary blob into the corelog.
 */
void
CoreLog_BinaryDump(int logLevel, const void *data, int len)
{
    CoreLog_Entry *entry;
    
    entry = CoreLog_AllocBuffer(data, len);
    entry->logLevel = logLevel;
    entry->flags = CORELOG_FLAG_HEXDUMP | CORELOG_FLAG_VALID;
    entry->time = CoreLogGetTimestamp();
}

/*
 * CoreLog_Backtrace
 *
 *      Dumps a backtrace into the corelog.
 */
void
CoreLog_Backtrace(int depth)
{
    CoreLog_Entry *entry;

    entry = CoreLog_AllocBuffer((void *)0, 0);
    entry->logLevel = 0;
    entry->flags = CORELOG_FLAG_BACKTRACE | CORELOG_FLAG_VALID;
    entry->time = CoreLogGetTimestamp();
    assert(false);
}

/*
 * CoreLog_Stackdump
 *
 *      Dumps a the stack data into the corelog.
 */
void
CoreLog_Stackdump(int depth)
{
    CoreLog_Entry *entry;

    entry = CoreLog_AllocBuffer((void *)0, 0);
    entry->logLevel = 0;
    entry->flags = CORELOG_FLAG_STACKDUMP | CORELOG_FLAG_VALID;
    entry->time = CoreLogGetTimestamp();
    assert(false);
}

void
CoreLog_Flush(void)
{
}

