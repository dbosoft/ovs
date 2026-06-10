/*
 * Copyright (c) 2026 dbosoft GmbH
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
#include "Registry.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_INIT
#include "Debug.h"

/*
 * Read the driver-global configuration from <service key>\Parameters. The
 * service key absolute path is the registryPath the I/O manager hands to
 * DriverEntry; the values live under its Parameters subkey by convention.
 *
 * RTL_QUERY_REGISTRY_DIRECT writes straight into the target global; seeding
 * DefaultData with the current value makes an absent value a no-op, so the
 * compile-time defaults stand on a clean install. TYPECHECK rejects a value of
 * the wrong type rather than mis-coercing it.
 */
NTSTATUS
OvsReadDriverConfig(PUNICODE_STRING registryPath)
{
    static const WCHAR paramsSuffix[] = L"\\Parameters";
    WCHAR path[512];
    USHORT chars;
    ULONG defLevel, defMask;
    RTL_QUERY_REGISTRY_TABLE table[3];
    NTSTATUS status;

    if (registryPath == NULL || registryPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    chars = registryPath->Length / sizeof(WCHAR);
    if ((SIZE_T)chars + RTL_NUMBER_OF(paramsSuffix) > RTL_NUMBER_OF(path)) {
        OVS_LOG_WARN("registry path too long (%u chars); using log defaults",
                     chars);
        return STATUS_BUFFER_OVERFLOW;
    }

    /* Build a NUL-terminated "<registryPath>\Parameters". */
    RtlCopyMemory(path, registryPath->Buffer, registryPath->Length);
    RtlCopyMemory(&path[chars], paramsSuffix, sizeof(paramsSuffix));

    defLevel = ovsLogLevel;
    defMask = ovsLogFlags;

    RtlZeroMemory(table, sizeof(table));

    table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK;
    table[0].Name = L"LogLevel";
    table[0].EntryContext = &ovsLogLevel;
    table[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_DWORD;
    table[0].DefaultData = &defLevel;
    table[0].DefaultLength = sizeof(ULONG);

    table[1].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK;
    table[1].Name = L"LogModuleMask";
    table[1].EntryContext = &ovsLogFlags;
    table[1].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_DWORD;
    table[1].DefaultData = &defMask;
    table[1].DefaultLength = sizeof(ULONG);

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, path, table,
                                    NULL, NULL);
    /*
     * A missing Parameters key is expected (default install) and still leaves
     * the DIRECT targets at their seeded defaults, so treat that as "no
     * overrides". Any other failure means a present-but-malformed value (e.g. a
     * wrong type rejected by TYPECHECK) aborted the whole query and discarded
     * even the valid sibling value; surface it so a field misconfiguration is
     * not silently mistaken for a clean install.
     */
    if (!NT_SUCCESS(status)) {
        ovsLogLevel = defLevel;
        ovsLogFlags = defMask;
        if (status != STATUS_OBJECT_NAME_NOT_FOUND) {
            OVS_LOG_WARN("registry log config rejected (status 0x%08x); "
                         "using defaults", status);
        }
    }

    /* Clamp to the valid OVS_DBG_* range; a bad value must not be honoured. */
    if (ovsLogLevel > OVS_DBG_LOUD) {
        ovsLogLevel = OVS_DBG_LOUD;
    }

    OVS_LOG_INFO("log config applied: level=%u moduleMask=0x%08x",
                 ovsLogLevel, ovsLogFlags);

    return STATUS_SUCCESS;
}
