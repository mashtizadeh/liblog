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

#ifdef __linux__
#undef _GNU_SOURCE
#include <features.h>
#endif

#ifdef __USE_GNU
#error
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <cinttypes>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <signal.h>
#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif

#ifdef __MACH__
#include <mach/mach.h>
#include <mach/clock.h>
#endif

#ifdef HAVE_EXECINFO
#include <execinfo.h>
#endif /* HAVE_EXECINFO */

#include <string>
#include <vector>
#include <list>
#include <map>
#include <iostream>
#include <fstream>
#include <mutex>
#include <stdexcept>

#include <debug.h>

using namespace std;

/********************************************************************
 *
 *
 * Logging
 *
 *
 ********************************************************************/

static bool logInitialized = false;
static std::fstream logStream;
static std::mutex logLock;
static std::map<void *,std::function<void(const std::string&)>> logOutputs = {};

void
get_timespec(struct timespec *ts)
{
#ifdef __MACH__
    clock_serv_t clk;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &clk);
    clock_get_time(clk, &mts);
    mach_port_deallocate(mach_task_self(), clk);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

static uint64_t
getthreadid()
{
#if defined(__FreeBSD__)
    return (uint64_t)pthread_getthreadid_np();
#elif defined(__linux__)
    /* Should use gettid() but WSL doens't have it */
    return (uint64_t)pthread_self();
#else
#error "Unsupported platform"
#endif
}

#define MAX_LOG         (1000)

/*
 * Formats the log entries and append them to the log.  Messages are written to 
 * stderr if they are urgent enough (depending on build).  This function must 
 * not log, throw exceptions, or use our ASSERT, PANIC, NOT_IMPLEMENTED macros.
 */
void
Debug_Log(int level, const char *fmt, ...)
{
    va_list ap;
    char buf[MAX_LOG];
    size_t off;

#if !defined(CELESTIS_DEBUG)
    if (level > LEVEL_MSG)
        return;
#endif /* DEBUG */

    time_t curTime;
    time(&curTime);
    off = strftime(buf, 32, "%Y-%m-%d %H:%M:%S ", localtime(&curTime));

    snprintf(buf + off, MAX_LOG - off, "%" PRIu64 " ", getthreadid());
    off = strlen(buf);

    switch (level) {
        case LEVEL_SYS:
            break;
        case LEVEL_ERR:
            strncat(buf, "ERROR: ", MAX_LOG - off);
            break;
        case LEVEL_WRN:
            strncat(buf, "WARNING: ", MAX_LOG - off);
            break;
        case LEVEL_MSG:
            strncat(buf, "MESSAGE: ", MAX_LOG - off);
            break;
        case LEVEL_LOG:
            strncat(buf, "LOG: ", MAX_LOG - off);
            break;
        case LEVEL_DBG:
            strncat(buf, "DEBUG: ", MAX_LOG - off);
            break;
        case LEVEL_VRB:
            strncat(buf, "VERBOSE: ", MAX_LOG - off);
            break;
    }

    off = strlen(buf);

    va_start(ap, fmt);
    vsnprintf(buf + off, MAX_LOG - off, fmt, ap);
    va_end(ap);

    logLock.lock();

#ifdef CELESTIS_DEBUG
    if (level <= LEVEL_MSG)
        cerr << buf;
#else /* RELEASE or PERF */
    if (level <= LEVEL_ERR)
        cerr << buf + off;
#endif

    if (logInitialized) {
        if (logStream.is_open()) {
            logStream.write(buf, strlen(buf));

            // Disabled on release builds for performance reasons
#ifdef CELESTIS_DEBUG
            logStream.flush();
#endif
        }

        for (auto &f : logOutputs) {
            f.second(buf);
        }
    }

    logLock.unlock();
}

void
Debug_Perror(const char *str, int err)
{
    char buf[64];

    (void)strerror_r(err, buf, sizeof(buf));

    Debug_Log(LEVEL_ERR, "%s: %s\n", str, buf);
}

static void
Debug_Terminate() {
#ifdef HAVE_EXECINFO
    const size_t MAX_FRAMES = 128;
    int num;
    void *array[MAX_FRAMES];
    char **names;
#endif /* HAVE_EXECINFO */

    auto exc = std::current_exception();
    if (exc) {
        try {
	    rethrow_exception(exc);
        } catch (std::exception const &e) {
	    Debug_Log(LEVEL_SYS, "Caught unhandled exception: %s\n", e.what());
        } catch (...) {
	    Debug_Log(LEVEL_SYS, "Caught unhandled exception: (unknown type)");
        }
    } else {
	Debug_Log(LEVEL_SYS, "Caught unhandled exception: (unable to determine)\n");
    }

#ifdef HAVE_EXECINFO
    num = backtrace(array, MAX_FRAMES);
    names = backtrace_symbols(array, num);
    Debug_Log(LEVEL_SYS, "Backtrace:\n");
    for (int i = 0; i < num; i++) {
        if (names != NULL)
            Debug_Log(LEVEL_SYS, "[%d] %s\n", i, names[i]);
        else
            Debug_Log(LEVEL_SYS, "[%d] [0x%p]\n", i, array[i]);
    }
    free(names);
#else
    Debug_Log(LEVEL_SYS, "Backtrace not support not included in this build\n");
#endif /* HAVE_EXECINFO */

    abort();
}

static void
Debug_SigHandler(int signum)
{
#ifdef HAVE_EXECINFO
    const size_t MAX_FRAMES = 128;
    int num;
    void *array[MAX_FRAMES];
    char **names;
#endif /* HAVE_EXECINFO */

    Debug_Log(LEVEL_SYS, "Signal Caught: %d\n", signum);

#ifdef HAVE_EXECINFO
    num = backtrace(array, MAX_FRAMES);
    names = backtrace_symbols(array, num);
    Debug_Log(LEVEL_SYS, "Backtrace:\n");
    for (int i = 0; i < num; i++) {
        if (names != NULL)
            Debug_Log(LEVEL_SYS, "[%d] %s\n", i, names[i]);
        else
            Debug_Log(LEVEL_SYS, "[%d] [0x%p]\n", i, array[i]);
    }
    free(names);
#else
    Debug_Log(LEVEL_SYS, "Backtrace not support not included in this build\n");
#endif /* HAVE_EXECINFO */

    abort();
}

int
Debug_OpenLog(const string &logPath) {
    if (logPath == "")
        return -1;

    std::set_terminate(Debug_Terminate);
    signal(SIGBUS, Debug_SigHandler);
    signal(SIGSEGV, Debug_SigHandler);
    signal(SIGILL, Debug_SigHandler);

    logStream.open(logPath.c_str(), fstream::in | fstream::out | fstream::app);
    if (!logStream.is_open()) {
        printf("Could not open logfile: %s\n", logPath.c_str());
        return -1;
    }

    logInitialized = true;

    return 0;
}

/*
 * Pretty print hex data
 */
void
Debug_PrintHex(const std::string &data, off_t off, size_t limit)
{
    const size_t row_size = 16;
    bool stop = false;

    for (size_t row = 0; !stop; row++) {
        size_t ix = row * row_size;
        if (ix >= data.length()) {
            break;
        }

        printf("%08lx  ", row * row_size);
        for (size_t col = 0; col < row_size; col++) { 
            size_t ix = row * row_size + col;
            if ((limit != 0 && ix >= limit) || ix >= data.length()) {
                stop = true;
                for (; col < row_size; col++) {
                    printf("   ");
                }
                break;
            }
            ix += off;

            printf("%02X ", (unsigned char)data[ix]);
        }
        printf("  |");

        for (size_t col = 0; col < row_size; col++) { 
            size_t ix = row * row_size + col;
            if ((limit != 0 && ix >= limit) || ix >= data.length()) {
                stop = true;
                for (; col < row_size; col++) {
                    printf(" ");
                }
                break;
            }
            ix += off;

            unsigned char c = (unsigned char)data[ix];
            if (c >= 0x20 && c < 0x7F)
                printf("%c", c);
            else
                putchar('.');
        }
        printf("|");
        printf("\n");
    }
}

/*
 * Print a backtrace
 */
void
Debug_PrintBacktrace()
{
    const size_t MAX_FRAMES = 128;
    void *array[MAX_FRAMES];

#ifdef HAVE_EXECINFO
    int num = backtrace(array, MAX_FRAMES);
    char **names = backtrace_symbols(array, num);
    for (int i = 0; i < num; i++) {
        fprintf(stderr, "%s\n", names[i]);
    }
    free(names);
#else
    fprintf(stderr, "backtrace not support not included in this build\n");
#endif /* HAVE_EXECINFO */
}

void
Debug_LogBacktrace()
{
    const size_t MAX_FRAMES = 128;
    void *array[MAX_FRAMES];

#ifdef HAVE_EXECINFO
    int num = backtrace(array, MAX_FRAMES);
    char **names = backtrace_symbols(array, num);
    for (int i = 0; i < num; i++) {
        LOG("%s", names[i]);
    }
    free(names);
#else
    LOG("backtrace not support not included in this build\n");
#endif /* HAVE_EXECINFO */
}

