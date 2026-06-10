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
 * Read one REG_DWORD knob from the Parameters key into *target, keeping the
 * passed-in default (the current global) when the value is absent or rejected.
 *
 * RTL_QUERY_REGISTRY_DIRECT writes straight into the target; seeding
 * DefaultData with the current value makes an absent value a no-op, so the
 * compile-time defaults stand on a clean install. TYPECHECK rejects a value of
 * the wrong type rather than mis-coercing it. Each knob is queried on its own
 * so a malformed value cannot discard a valid sibling.
 */
static VOID
OvsReadLogDword(PCWSTR path, PCWSTR name, UINT32 *target)
{
    UINT32 def = *target;
    RTL_QUERY_REGISTRY_TABLE table[2];
    NTSTATUS status;

    RtlZeroMemory(table, sizeof(table));
    table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK;
    table[0].Name = (PWSTR)name;
    table[0].EntryContext = target;
    table[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_DWORD;
    table[0].DefaultData = &def;
    table[0].DefaultLength = sizeof(ULONG);

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, (PWSTR)path, table,
                                    NULL, NULL);
    /*
     * A missing value/key is expected (default install) and leaves the DIRECT
     * target at the seeded default. Any other failure means a present-but-
     * malformed value (e.g. a wrong type rejected by TYPECHECK); restore the
     * default and surface it so a field misconfiguration is not silently
     * mistaken for "not set".
     */
    if (!NT_SUCCESS(status)) {
        *target = def;
        if (status != STATUS_OBJECT_NAME_NOT_FOUND) {
            OVS_LOG_WARN("registry value '%S' rejected (status 0x%08x); "
                         "keeping default 0x%x", name, status, def);
        }
    }
}

/*
 * Read the driver-global configuration from <service key>\Parameters. The
 * service key absolute path is the registryPath the I/O manager hands to
 * DriverEntry; the values live under its Parameters subkey by convention.
 *
 * Best-effort and non-fatal: any failure leaves the compile-time logging
 * defaults in place, so there is no status for the caller to act on.
 */
VOID
OvsReadDriverConfig(PUNICODE_STRING registryPath)
{
    static const WCHAR paramsSuffix[] = L"\\Parameters";
    WCHAR path[512];
    USHORT chars;

    if (registryPath == NULL || registryPath->Buffer == NULL) {
        return;
    }

    chars = registryPath->Length / sizeof(WCHAR);
    if ((SIZE_T)chars + RTL_NUMBER_OF(paramsSuffix) > RTL_NUMBER_OF(path)) {
        OVS_LOG_WARN("registry path too long (%u chars); using log defaults",
                     chars);
        return;
    }

    /* Build a NUL-terminated "<registryPath>\Parameters". */
    RtlCopyMemory(path, registryPath->Buffer, registryPath->Length);
    RtlCopyMemory(&path[chars], paramsSuffix, sizeof(paramsSuffix));

    /* Each knob is read independently: a bad value falls back on its own. */
    OvsReadLogDword(path, L"LogLevel", &ovsLogLevel);
    OvsReadLogDword(path, L"LogModuleMask", &ovsLogFlags);

    /* Clamp to the valid OVS_DBG_* range; a bad value must not be honoured. */
    if (ovsLogLevel > OVS_DBG_LOUD) {
        ovsLogLevel = OVS_DBG_LOUD;
    }

    OVS_LOG_INFO("log config applied: level=%u moduleMask=0x%08x",
                 ovsLogLevel, ovsLogFlags);
}
