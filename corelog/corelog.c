/*
 * Copyright (c) 2009-2020 Ali Mashtizadeh
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <corelog.h>

char *buf;
uint64_t len;

#define MAX_MSGSIZE 1024
#define ROUNDUP(a,b) (((a) + (b) - 1)/(b) * (b))

bool IsValidCoreLog(CoreLog_Header *hdr)
{
    char name[32];

    if ((hdr->magic[0] != CORELOG_HEADER_MAGIC0)
        || (hdr->magic[1] != CORELOG_HEADER_MAGIC1)
        || (hdr->magic[2] != CORELOG_HEADER_MAGIC2)
        || (hdr->magic[3] != CORELOG_HEADER_MAGIC3))
    {
        printf("CoreLog magic does not match or is corrupt.\n");
        return false;
    }

    if (hdr->length > ((char *)hdr - buf + len))
    {
        printf("CoreLog seems to extend past the file boundry.\n");
        return false;
    }

    if (hdr->free > hdr->length)
    {
        printf("CoreLog free bytes seems corrupt.\n");
        return false;
    }

    if (hdr->head > hdr->length || hdr->tail > hdr->length)
    {
        printf("CoreLog head or tail extends past the length of the log.\n");
        return false;
    }

    memcpy(&name, &hdr->name, 31);
    name[31] = '\0';

    printf("Dumping log \"%s\"\n", &name[0]);
    return true;
}

bool IsValidEntry(CoreLog_Entry *e)
{
    if (e->magic != CORELOG_ENTRY_MAGIC)
    {
        printf("Entry magic not set.\n");
        return false;
    }

    if ((e->flags & CORELOG_FLAG_VALID) == 0)
    {
        printf("Entry not valid.\n");
        return false;
    }

    return true;
}

int LogPrintDate(uint64_t ts, char *buf, int len)
{
    int n;
    time_t sec = ts / 1000;
    time_t msec = ts % 1000;

    n = strftime(buf, len, "%Y-%m-%d %H:%M:%S", localtime(&sec));

    buf += n;
    len -= n;
    n += snprintf(buf, len, ".%03ld ", msec);

    return n;
}

/*
 * PrintEntry
 *
 *      Prints a single log entry and returns the length that the
 *      entry has consumed.
 *
 *      XXX: This function needs to be made safe from corrupt logs.
 */
uint32_t PrintEntry(CoreLog_Header *hdr, CoreLog_Entry *e)
{
    uint32_t alignedOffset = ROUNDUP(sizeof(*e), hdr->alignment);
    char *buf = (char *)e + alignedOffset;
    int n = 2 * MAX_MSGSIZE;
    int offset = 0;
    char buffer[2 * MAX_MSGSIZE];

    switch (e->flags & CORELOG_FLAG_TYPEMASK)
    {
        case CORELOG_FLAG_INVALID:
            assert(false);
            break;
        case CORELOG_FLAG_LOG:
            offset += LogPrintDate(e->time, (char *)&buffer, 2 * MAX_MSGSIZE);
            snprintf((char *)&buffer + offset, n - offset, "LOG(%d): %s",
                     e->logLevel, buf);
            printf("%s", (char *)&buffer);
            break;
        case CORELOG_FLAG_WARNING:
            offset += LogPrintDate(e->time, (char *)&buffer, 2 * MAX_MSGSIZE);
            snprintf((char *)&buffer + offset, n - offset, "WARNING: %s", buf);
            printf("%s", (char *)&buffer);
            break;
        case CORELOG_FLAG_ALERT:
            offset += LogPrintDate(e->time, (char *)&buffer, 2 * MAX_MSGSIZE);
            snprintf((char *)&buffer + offset, n - offset, "ALERT: %s", buf);
            printf("%s", (char *)&buffer);
            break;
        case CORELOG_FLAG_HEXDUMP:
            break;
        case CORELOG_FLAG_BACKTRACE:
        case CORELOG_FLAG_STACKDUMP:
        case CORELOG_FLAG_OUTOFBAND:
        default:
            assert(false);
    }

    return alignedOffset + ROUNDUP(e->length, hdr->alignment);
}

void ScanCoreLog(CoreLog_Header *hdr)
{
    uint32_t alignedHdrLen = ROUNDUP(sizeof(CoreLog_Header), hdr->alignment);
    char *buf;
    uint32_t tail = hdr->tail;

    buf = ((char *)hdr) + alignedHdrLen;
    while (tail != hdr->head)
    {
        if (IsValidEntry((CoreLog_Entry *)(buf + tail)))
        {
            tail += PrintEntry(hdr, (CoreLog_Entry *)(buf + tail));
        } else {
            printf("Invalid entry encountered.");
            return;
        }
    }
}

void FindCoreLog(void)
{
    int i;

    for (i = 0; i < (len - 4); i++)
    {
        if (*(uint32_t *)(buf + i) == CORELOG_HEADER_MAGIC0) {
            printf("Possible CoreLog found @ %08x\n", i);
            if (IsValidCoreLog((CoreLog_Header *)(buf + i))) {
                ScanCoreLog((CoreLog_Header *)(buf + i));
            }
        }
    }
}

void usage(void)
{
    printf("corelog [COREDUMP]\n");
}

int main(int argc,char *argv[])
{
    int fd;
    off_t end;

    if (argc != 2) {
        usage();
        return 0;
    }

    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("failed to open file: %d\n", errno);
        return 0;
    }

    end = lseek(fd, 0, SEEK_END);
    if (end < 0) {
        printf("failed to seek to the end of the file: %d\n", errno);
        return 0;
    }
    len = end;

    buf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) {
        printf("failed to map buffer: %d\n", errno);
        return 0;
    }

    FindCoreLog();

    return 0;
}

