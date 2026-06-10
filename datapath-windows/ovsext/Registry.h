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

#ifndef __REGISTRY_H_
#define __REGISTRY_H_ 1

/*
 * Driver-global configuration read once from the service Parameters key
 * (HKLM\SYSTEM\CurrentControlSet\Services\DBO_OVSE\Parameters) at load.
 *
 * Currently the diagnostics/logging knobs:
 *   LogLevel       REG_DWORD  max OVS_DBG_* level emitted (0=Error..4=Loud)
 *   LogModuleMask  REG_DWORD  per-module OVS_DBG_* enable bitmask
 *
 * Each knob defaults to the compile-time value when absent, so a clean install
 * behaves identically to one with no Parameters key. Best-effort and non-fatal
 * (failures leave the defaults in place). Must be called at PASSIVE_LEVEL (it
 * touches the registry); never read config on the datapath.
 */
VOID OvsReadDriverConfig(PUNICODE_STRING registryPath);

#endif /* __REGISTRY_H_ */
