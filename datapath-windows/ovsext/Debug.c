/*
 * Copyright (c) 2014 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "precomp.h"

#include "Debug.h"
#include <evntrace.h>            /* TRACE_LEVEL_* (winmeta.h is user-mode only) */
#include <TraceLoggingProvider.h>

#ifdef DBG
#define OVS_DBG_DEFAULT  OVS_DBG_INFO
#else
#define OVS_DBG_DEFAULT  OVS_DBG_ERROR
#endif

UINT32  ovsLogFlags = 0xffffffff;
UINT32  ovsLogLevel = OVS_DBG_DEFAULT;
BUILD_ASSERT(OVS_DBG_LAST < 31); /* 'ovsLogLevel' is 32 bits. */

#define OVS_LOG_BUFFER_SIZE 384

/*
 * TraceLogging provider for capturing driver logs without a kernel debugger.
 * Decodes self-describing (no TMF/PDB needed) with stock tools:
 *   wpr -start <profile> / tracelog / logman, read with WPA / tracefmt / PerfView.
 * The DbgPrintEx sink below is retained for the in-debugger dev loop.
 */
TRACELOGGING_DEFINE_PROVIDER(
    g_OvsTraceLoggingProvider,
    "Dbosoft.OVS.Ovsext",
    /* {b2d1f6a4-9c3e-4f7a-a15b-6d8e2c4f7093} */
    (0xb2d1f6a4, 0x9c3e, 0x4f7a, 0xa1, 0x5b, 0x6d, 0x8e, 0x2c, 0x4f, 0x70, 0x93));

/*
 * Map the driver's DPFLTR-style severity (lower == more severe) to the ETW
 * level scale (higher == more verbose) so ETW session level filtering behaves
 * intuitively.
 */
static __inline UCHAR
OvsLogEtwLevel(UINT32 level)
{
    switch (level) {
    case OVS_DBG_ERROR: return TRACE_LEVEL_ERROR;
    case OVS_DBG_WARN:  return TRACE_LEVEL_WARNING;
    case OVS_DBG_TRACE: return TRACE_LEVEL_INFORMATION;
    case OVS_DBG_INFO:  return TRACE_LEVEL_INFORMATION;
    default:            return TRACE_LEVEL_VERBOSE;
    }
}

NTSTATUS
OvsTraceLoggingRegister(VOID)
{
    return TraceLoggingRegister(g_OvsTraceLoggingProvider);
}

VOID
OvsTraceLoggingUnregister(VOID)
{
    TraceLoggingUnregister(g_OvsTraceLoggingProvider);
}

/*
 * --------------------------------------------------------------------------
 * OvsLog --
 *  Utility function to log to the Windows debug console (DbgPrintEx, gated by
 *  ovsLogLevel/ovsLogFlags for the in-debugger dev loop) and to the ETW
 *  TraceLogging provider (gated independently by the listening session, so a
 *  production capture can collect levels the debug console is configured to
 *  drop). The module bitmask rides as the "Module" payload field for
 *  post-capture per-subsystem filtering.
 * --------------------------------------------------------------------------
 */

/*
 * TraceLoggingLevel() must be a compile-time constant (it is baked into the
 * static event descriptor), so the runtime level is dispatched to a per-level
 * write. The field set is identical across levels.
 */
#define OVS_ETW_WRITE(_lvl)                                              \
    TraceLoggingWrite(g_OvsTraceLoggingProvider, "OvsLog",              \
        TraceLoggingLevel(_lvl),                                        \
        TraceLoggingUInt32(level, "OvsLevel"),                          \
        TraceLoggingUInt32(flag, "Module"),                             \
        TraceLoggingString(funcName, "Function"),                       \
        TraceLoggingUInt32(line, "Line"),                               \
        TraceLoggingString(buf, "Message"))

VOID
OvsLog(UINT32 level,
       UINT32 flag,
       CHAR *funcName,
       UINT32 line,
       CHAR *format,
       ...)
{
    va_list args;
    CHAR buf[OVS_LOG_BUFFER_SIZE];
    BOOLEAN dbgWanted = (level <= ovsLogLevel && (ovsLogFlags & flag) != 0);
    UCHAR etwLevel = OvsLogEtwLevel(level);
    BOOLEAN etwWanted = TraceLoggingProviderEnabled(g_OvsTraceLoggingProvider,
                                                    etwLevel, 0);

    if (!dbgWanted && !etwWanted) {
        return;
    }

    buf[0] = 0;
    va_start(args, format);
    RtlStringCbVPrintfA(buf, sizeof (buf), format, args);
    va_end(args);

    if (dbgWanted) {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, level, "%s:%lu %s\n",
                   funcName, line, buf);
    }

    if (etwWanted) {
        switch (etwLevel) {
        case TRACE_LEVEL_ERROR:       OVS_ETW_WRITE(TRACE_LEVEL_ERROR); break;
        case TRACE_LEVEL_WARNING:     OVS_ETW_WRITE(TRACE_LEVEL_WARNING); break;
        case TRACE_LEVEL_INFORMATION: OVS_ETW_WRITE(TRACE_LEVEL_INFORMATION); break;
        default:                      OVS_ETW_WRITE(TRACE_LEVEL_VERBOSE); break;
        }
    }
}
