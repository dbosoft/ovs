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

/*
 * This file contains the implementation of the management functionality of the
 * OVS.
 */

#include "precomp.h"
#include "Conntrack.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "Meter.h"
#include "Flow.h"
#include "IpHelper.h"
#include "Oid.h"
#include "IpFragment.h"
#include "Ip6Fragment.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_SWITCH
#include "Debug.h"

POVS_SWITCH_CONTEXT gOvsSwitchContext;
UINT64 ovsTimeIncrementPerTick;

extern NDIS_HANDLE gOvsExtDriverHandle;
extern NDIS_HANDLE gOvsExtDriverObject;
extern PDEVICE_OBJECT gOvsDeviceObject;

/*
 * Datapath registry: each attached Hyper-V switch is a datapath, addressed by
 * its datapath number (dpNo), which is the slot index in 'gOvsDatapaths'.
 * 'gOvsDatapathLock' serializes registration, lookup and the reference taken
 * during lookup. 'gOvsSwitchContext' points at the default (first) datapath,
 * which still backs the paths that have no dp_ifindex of their own.
 */
#define OVS_MAX_DATAPATHS 16
POVS_SWITCH_CONTEXT gOvsDatapaths[OVS_MAX_DATAPATHS];
NDIS_SPIN_LOCK     gOvsDatapathLock;

/*
 * Upper bound (milliseconds) that OvsDeleteSwitch waits for in-flight switch
 * references to drain before tearing down the vport lists. References are all
 * per-operation and bounded, so the drain normally completes well within this;
 * the cap only prevents a wedged accessor from hanging driver teardown.
 */
#define OVS_SWITCH_TEARDOWN_DRAIN_MAX_MS 10000

/*
 * The upcall pid hash maps a globally-unique handle pid to its open instance.
 * Pids are allocated from a single driver-wide counter, so the hash is a
 * driver-global resource (lifetime = driver load), not per-switch: this keeps
 * it intact when the default datapath detaches and 'gOvsSwitchContext' is
 * promoted to another datapath. See User.c.
 */
PLIST_ENTRY        gOvsPidHashArray;
NDIS_SPIN_LOCK     gOvsPidHashLock;

static NDIS_STATUS OvsCreateSwitch(NDIS_HANDLE ndisFilterHandle,
                                   POVS_SWITCH_CONTEXT *switchContextOut);
static NDIS_STATUS OvsInitSwitchContext(POVS_SWITCH_CONTEXT switchContext);
static VOID OvsDeleteSwitch(POVS_SWITCH_CONTEXT switchContext);
static VOID OvsUninitSwitchContext(POVS_SWITCH_CONTEXT switchContext);
static NDIS_STATUS OvsActivateSwitch(POVS_SWITCH_CONTEXT switchContext);


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterAttach function.
 *
 *  This function allocates the switch context, and initializes its necessary
 *  members.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtAttach(NDIS_HANDLE ndisFilterHandle,
             NDIS_HANDLE filterDriverContext,
             PNDIS_FILTER_ATTACH_PARAMETERS attachParameters)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    NDIS_FILTER_ATTRIBUTES ovsExtAttributes;
    POVS_SWITCH_CONTEXT switchContext = NULL;

    UNREFERENCED_PARAMETER(filterDriverContext);

    OVS_LOG_TRACE("Enter: ndisFilterHandle %p", ndisFilterHandle);

    ASSERT(filterDriverContext == (NDIS_HANDLE)gOvsExtDriverObject);
    if (attachParameters->MiniportMediaType != NdisMedium802_3) {
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    if (gOvsExtDriverHandle == NULL) {
        OVS_LOG_TRACE("Exit: OVSEXT driver is not loaded.");
        ASSERT(FALSE);
        goto cleanup;
    }

    status = OvsCreateSwitch(ndisFilterHandle, &switchContext);
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup;
    }
    ASSERT(switchContext);

    /*
     * Register the switch context with NDIS so NDIS can pass it back to the
     * FilterXXX callback functions as the 'FilterModuleContext' parameter.
     */
    RtlZeroMemory(&ovsExtAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
    ovsExtAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    ovsExtAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
    ovsExtAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    ovsExtAttributes.Flags = 0;

    NDIS_DECLARE_FILTER_MODULE_CONTEXT(OVS_SWITCH_CONTEXT);
    status = NdisFSetAttributes(ndisFilterHandle, switchContext, &ovsExtAttributes);
    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_ERROR("Failed to set attributes.");
        goto cleanup;
    }

    /* Setup the state machine. */
    switchContext->controlFlowState = OvsSwitchAttached;
    switchContext->dataFlowState = OvsSwitchPaused;

    OvsRegisterDatapath(switchContext);

cleanup:
    if (status != NDIS_STATUS_SUCCESS) {
        if (switchContext != NULL) {
            OvsDeleteSwitch(switchContext);
        }
    }
    OVS_LOG_TRACE("Exit: status %x", status);

    return status;
}


/*
 * --------------------------------------------------------------------------
 *  This function allocated the switch context, and initializes its necessary
 *  members.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsCreateSwitch(NDIS_HANDLE ndisFilterHandle,
                POVS_SWITCH_CONTEXT *switchContextOut)
{
    NDIS_STATUS status;
    POVS_SWITCH_CONTEXT switchContext;
    NDIS_SWITCH_CONTEXT hostSwitchContext;
    NDIS_SWITCH_OPTIONAL_HANDLERS hostSwitchHandler;

    OVS_LOG_TRACE("Enter: Create switch object");

    switchContext = (POVS_SWITCH_CONTEXT) OvsAllocateMemoryWithTag(
        sizeof(OVS_SWITCH_CONTEXT), OVS_SWITCH_POOL_TAG);
    if (switchContext == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto create_switch_done;
    }
    RtlZeroMemory(switchContext, sizeof(OVS_SWITCH_CONTEXT));

    /* Initialize the switch. */
    hostSwitchHandler.Header.Type = NDIS_OBJECT_TYPE_SWITCH_OPTIONAL_HANDLERS;
    hostSwitchHandler.Header.Size = NDIS_SIZEOF_SWITCH_OPTIONAL_HANDLERS_REVISION_1;
    hostSwitchHandler.Header.Revision = NDIS_SWITCH_OPTIONAL_HANDLERS_REVISION_1;

    status = NdisFGetOptionalSwitchHandlers(ndisFilterHandle,
                                            &hostSwitchContext,
                                            &hostSwitchHandler);
    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_ERROR("OvsExtAttach: Extension is running in "
                      "non-switch environment.");
        OvsFreeMemoryWithTag(switchContext, OVS_SWITCH_POOL_TAG);
        goto create_switch_done;
    }

    switchContext->NdisFilterHandle = ndisFilterHandle;
    switchContext->NdisSwitchContext = hostSwitchContext;
    RtlCopyMemory(&switchContext->NdisSwitchHandlers, &hostSwitchHandler,
                  sizeof(NDIS_SWITCH_OPTIONAL_HANDLERS));

    status = OvsInitSwitchContext(switchContext);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsFreeMemoryWithTag(switchContext, OVS_SWITCH_POOL_TAG);
        switchContext = NULL;
        goto create_switch_done;
    }

    *switchContextOut = switchContext;

create_switch_done:
    OVS_LOG_TRACE("Exit: switchContext: %p status: %#lx",
                  switchContext, status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterDetach function.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtDetach(NDIS_HANDLE filterModuleContext)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;

    OVS_LOG_TRACE("Enter: filterModuleContext %p", filterModuleContext);

    ASSERT(switchContext->dataFlowState == OvsSwitchPaused);
    switchContext->controlFlowState = OvsSwitchDetached;
    KeMemoryBarrier();
    while(switchContext->pendingOidCount > 0) {
        NdisMSleep(1000);
    }
    OvsDeleteSwitch(switchContext);

    /* This completes the cleanup, and a new attach can be handled now. */

    OVS_LOG_TRACE("Exit: OvsDetach Successfully");
}


/*
 * --------------------------------------------------------------------------
 *  This function deletes the switch by freeing all memory previously allocated.
 *  XXX need synchronization with other path.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeleteSwitch(POVS_SWITCH_CONTEXT switchContext)
{
    UINT32 dpNo = (UINT32) -1;

    OVS_LOG_TRACE("Enter: switchContext:%p", switchContext);

    if (switchContext)
    {
        dpNo = switchContext->dpNo;

        /*
         * Remove the switch from the datapath registry FIRST, so no new path
         * (userspace IOCTL lookup, IpHelper route walk, WFP tunnel classify)
         * can reach it once teardown begins. Then wait for any in-flight
         * reference holders to drain back to the owning baseline (refCount == 1)
         * before tearing down the vport lists: every cross-thread accessor takes
         * a transient reference (OvsAcquireSwitchContext / OvsAcquireDatapathBy*),
         * so refCount == 1 means nobody else is walking the lists, which makes
         * the lock-free OvsClearAllSwitchVports safe. All such references are
         * per-operation (released before any IRP is pended), so this terminates;
         * the bound is a backstop against a wedged accessor (logged, not hung).
         */
        OvsUnregisterDatapath(switchContext);

        ULONG drainMs = 0;
        KeMemoryBarrier();
        while (switchContext->refCount > 1 &&
               drainMs < OVS_SWITCH_TEARDOWN_DRAIN_MAX_MS) {
            NdisMSleep(1000);  /* 1 ms */
            drainMs++;
            KeMemoryBarrier();
        }
        if (switchContext->refCount > 1) {
            OVS_LOG_WARN("Switch %p teardown proceeding with %d reference(s) "
                         "still held after %u ms", switchContext,
                         switchContext->refCount - 1, drainMs);
        }

        OvsClearAllSwitchVports(switchContext);
        OvsUninitSwitchContext(switchContext);
    }
    OVS_LOG_TRACE("Exit: deleted switch %p  dpNo: %d", switchContext, dpNo);
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterRestart function.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtRestart(NDIS_HANDLE filterModuleContext,
              PNDIS_FILTER_RESTART_PARAMETERS filterRestartParameters)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    BOOLEAN switchActive;

    UNREFERENCED_PARAMETER(filterRestartParameters);

    OVS_LOG_TRACE("Enter: filterModuleContext %p",
                  filterModuleContext);

    /* Activate the switch if this is the first restart. */
    if (!switchContext->isActivated && !switchContext->isActivateFailed) {
        status = OvsQuerySwitchActivationComplete(switchContext,
                                                  &switchActive);
        if (status != NDIS_STATUS_SUCCESS) {
            switchContext->isActivateFailed = TRUE;
            status = NDIS_STATUS_RESOURCES;
            goto cleanup;
        }

        if (switchActive) {
            status = OvsActivateSwitch(switchContext);

            if (status != NDIS_STATUS_SUCCESS) {
                OVS_LOG_WARN("Failed to activate switch, dpNo:%d",
                             switchContext->dpNo);
                status = NDIS_STATUS_RESOURCES;
                goto cleanup;
            }
        }
    }

    ASSERT(switchContext->dataFlowState == OvsSwitchPaused);
    switchContext->dataFlowState = OvsSwitchRunning;

cleanup:
    OVS_LOG_TRACE("Exit: Restart switch:%p, dpNo: %d, status: %#x",
                  switchContext, switchContext->dpNo, status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterPause function
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtPause(NDIS_HANDLE filterModuleContext,
            PNDIS_FILTER_PAUSE_PARAMETERS pauseParameters)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;

    UNREFERENCED_PARAMETER(pauseParameters);
    OVS_LOG_TRACE("Enter: filterModuleContext %p",
                  filterModuleContext);

    switchContext->dataFlowState = OvsSwitchPaused;
    KeMemoryBarrier();
    while(switchContext->pendingOidCount > 0) {
        NdisMSleep(1000);
    }

    OVS_LOG_TRACE("Exit: OvsExtPause Successfully");
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
OvsInitSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    int i;
    NTSTATUS status;

    OVS_LOG_TRACE("Enter: switchContext: %p", switchContext);

    switchContext->dispatchLock =
        NdisAllocateRWLock(switchContext->NdisFilterHandle);

    switchContext->portNoHashArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->ovsPortNameHashArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->portIdHashArray= (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->tunnelVportsArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    status = OvsAllocateFlowTable(&switchContext->datapath, switchContext);

    if (status == NDIS_STATUS_SUCCESS) {
        status = OvsInitBufferPool(switchContext);
    }
    if (status != NDIS_STATUS_SUCCESS ||
        switchContext->dispatchLock == NULL ||
        switchContext->portNoHashArray == NULL ||
        switchContext->ovsPortNameHashArray == NULL ||
        switchContext->portIdHashArray== NULL ||
        switchContext->tunnelVportsArray == NULL) {
        if (switchContext->dispatchLock) {
            NdisFreeRWLock(switchContext->dispatchLock);
        }
        if (switchContext->portNoHashArray) {
            OvsFreeMemoryWithTag(switchContext->portNoHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }
        if (switchContext->ovsPortNameHashArray) {
            OvsFreeMemoryWithTag(switchContext->ovsPortNameHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }
        if (switchContext->portIdHashArray) {
            OvsFreeMemoryWithTag(switchContext->portIdHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }

        if (switchContext->tunnelVportsArray) {
            OvsFreeMemory(switchContext->tunnelVportsArray);
        }

        OvsDeleteFlowTable(&switchContext->datapath);
        OvsCleanupBufferPool(switchContext);

        OVS_LOG_TRACE("Exit: Failed to init switchContext");
        return NDIS_STATUS_RESOURCES;
    }

    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        InitializeListHead(&switchContext->ovsPortNameHashArray[i]);
        InitializeListHead(&switchContext->portIdHashArray[i]);
        InitializeListHead(&switchContext->portNoHashArray[i]);
        InitializeListHead(&switchContext->tunnelVportsArray[i]);
    }

    switchContext->isActivated = FALSE;
    switchContext->isActivateFailed = FALSE;
    switchContext->refCount = 1;
    ovsTimeIncrementPerTick = KeQueryTimeIncrement() / 10000;

    OVS_LOG_TRACE("Exit: Succesfully initialized switchContext: %p",
                  switchContext);
    return NDIS_STATUS_SUCCESS;
}

static VOID
OvsUninitSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    OvsReleaseSwitchContext(switchContext);
}

/*
 * --------------------------------------------------------------------------
 *  Frees up the contents of and also the switch context.
 * --------------------------------------------------------------------------
 */
static VOID
OvsDeleteSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    OVS_LOG_TRACE("Enter: Delete switchContext:%p", switchContext);

    /* We need to do cleanup for tunnel port here. */
    ASSERT(switchContext->numHvVports == 0);
    ASSERT(switchContext->numNonHvVports == 0);

    NdisFreeRWLock(switchContext->dispatchLock);
    switchContext->dispatchLock = NULL;
    OvsFreeMemoryWithTag(switchContext->ovsPortNameHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->ovsPortNameHashArray = NULL;
    OvsFreeMemoryWithTag(switchContext->portIdHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->portIdHashArray = NULL;
    OvsFreeMemoryWithTag(switchContext->portNoHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->portNoHashArray = NULL;
    OvsFreeMemory(switchContext->tunnelVportsArray);
    switchContext->tunnelVportsArray = NULL;
    OvsDeleteFlowTable(&switchContext->datapath);
    OvsCleanupBufferPool(switchContext);

    OvsFreeMemoryWithTag(switchContext, OVS_SWITCH_POOL_TAG);
    OVS_LOG_TRACE("Exit: Delete switchContext: %p", switchContext);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
OvsReleaseSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    if (switchContext == NULL) {
        return;
    }

    if (InterlockedDecrement(&switchContext->refCount) == 0) {
        OvsDeleteSwitchContext(switchContext);
    }
}

/*
 *  Returns the default datapath's switch context with a reference held (release
 *  it with OvsReleaseSwitchContext), or NULL if no datapath is registered. Used
 *  by request paths that carry no dp_ifindex of their own.
 */
POVS_SWITCH_CONTEXT
OvsAcquireSwitchContext(VOID)
{
    POVS_SWITCH_CONTEXT switchContext;

    NdisAcquireSpinLock(&gOvsDatapathLock);
    switchContext = gOvsSwitchContext;
    if (switchContext != NULL) {
        InterlockedIncrement(&switchContext->refCount);
    }
    NdisReleaseSpinLock(&gOvsDatapathLock);

    return switchContext;
}

/*
 * --------------------------------------------------------------------------
 *  Datapath registry: maps a datapath number (dpNo) to its switch context.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsInitDatapathRegistry(VOID)
{
    UINT32 i;

    NdisAllocateSpinLock(&gOvsDatapathLock);
    RtlZeroMemory(gOvsDatapaths, sizeof gOvsDatapaths);

    /* The upcall pid hash is driver-global (see the declaration comment). */
    gOvsPidHashArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_PID_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    if (gOvsPidHashArray == NULL) {
        /* gOvsDatapathLock is owned by OvsCleanupDatapathRegistry, which runs on
         * the failed-OvsInit cleanup path; do not free it here (double-free). */
        return NDIS_STATUS_RESOURCES;
    }
    for (i = 0; i < OVS_MAX_PID_ARRAY_SIZE; i++) {
        InitializeListHead(&gOvsPidHashArray[i]);
    }
    NdisAllocateSpinLock(&gOvsPidHashLock);

    return NDIS_STATUS_SUCCESS;
}

VOID
OvsCleanupDatapathRegistry(VOID)
{
    if (gOvsPidHashArray != NULL) {
        NdisFreeSpinLock(&gOvsPidHashLock);
        OvsFreeMemoryWithTag(gOvsPidHashArray, OVS_SWITCH_POOL_TAG);
        gOvsPidHashArray = NULL;
    }
    NdisFreeSpinLock(&gOvsDatapathLock);
}

VOID
OvsRegisterDatapath(POVS_SWITCH_CONTEXT switchContext)
{
    UINT32 i;

    NdisAcquireSpinLock(&gOvsDatapathLock);
    for (i = 0; i < OVS_MAX_DATAPATHS; i++) {
        if (gOvsDatapaths[i] == NULL) {
            gOvsDatapaths[i] = switchContext;
            switchContext->dpNo = i;
            break;
        }
    }
    if (i == OVS_MAX_DATAPATHS) {
        OVS_LOG_ERROR("Datapath registry full, cannot register %p",
                      switchContext);
        ASSERT(FALSE);
    } else if (gOvsSwitchContext == NULL) {
        gOvsSwitchContext = switchContext;
    }
    NdisReleaseSpinLock(&gOvsDatapathLock);
}

VOID
OvsUnregisterDatapath(POVS_SWITCH_CONTEXT switchContext)
{
    UINT32 i;

    NdisAcquireSpinLock(&gOvsDatapathLock);
    for (i = 0; i < OVS_MAX_DATAPATHS; i++) {
        if (gOvsDatapaths[i] == switchContext) {
            gOvsDatapaths[i] = NULL;
            break;
        }
    }
    if (gOvsSwitchContext == switchContext) {
        /*
         * The default datapath is detaching: promote the next live datapath so
         * 'gOvsSwitchContext' never dangles while any datapath remains (the
         * dp_ifindex-less request/packet paths anchor on it). The detaching slot
         * was cleared above, so the scan never re-selects it. NULL only when no
         * datapath is left. The pid hash is global, so promotion is safe.
         */
        gOvsSwitchContext = NULL;
        for (i = 0; i < OVS_MAX_DATAPATHS; i++) {
            if (gOvsDatapaths[i] != NULL) {
                gOvsSwitchContext = gOvsDatapaths[i];
                break;
            }
        }
    }
    NdisReleaseSpinLock(&gOvsDatapathLock);

    /*
     * Removing the context from the registry stops new lookups from finding it.
     * The owning reference is dropped by the OvsUninitSwitchContext that follows
     * in OvsDeleteSwitch; in-flight lookups that already hold a reference keep
     * the context alive until they release it.
     */
}

/*
 *  Returns the switch context for datapath number 'dpNo' with a reference held
 *  (release it with OvsReleaseSwitchContext), or NULL if no such datapath
 *  exists.
 */
POVS_SWITCH_CONTEXT
OvsAcquireDatapathByNumber(UINT32 dpNo)
{
    POVS_SWITCH_CONTEXT switchContext = NULL;

    NdisAcquireSpinLock(&gOvsDatapathLock);
    if (dpNo < OVS_MAX_DATAPATHS && gOvsDatapaths[dpNo] != NULL) {
        switchContext = gOvsDatapaths[dpNo];
        InterlockedIncrement(&switchContext->refCount);
    }
    NdisReleaseSpinLock(&gOvsDatapathLock);

    return switchContext;
}

POVS_SWITCH_CONTEXT
OvsAcquireNextDatapath(UINT32 startSlot, UINT32 *nextSlot)
{
    POVS_SWITCH_CONTEXT switchContext = NULL;
    UINT32 i;

    NdisAcquireSpinLock(&gOvsDatapathLock);
    for (i = startSlot; i < OVS_MAX_DATAPATHS; i++) {
        if (gOvsDatapaths[i] != NULL) {
            switchContext = gOvsDatapaths[i];
            InterlockedIncrement(&switchContext->refCount);
            *nextSlot = i + 1;
            break;
        }
    }
    NdisReleaseSpinLock(&gOvsDatapathLock);

    return switchContext;
}

/*
 * --------------------------------------------------------------------------
 *  This function activates the switch by initializing it with all the runtime
 *  state. First it queries all of the MAC addresses set as custom switch policy
 *  to allow sends from, and adds tme to the property list. Then it queries the
 *  NIC list and verifies it can support all of the NICs currently connected to
 *  the switch, and adds the NICs to the NIC list.
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
OvsActivateSwitch(POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status;

    ASSERT(!switchContext->isActivated);

    switchContext->isActivated = TRUE;

    OVS_LOG_TRACE("Enter: activate switch %p, dpNo: %ld",
                  switchContext, switchContext->dpNo);

    OvsCaptureSwitchName(switchContext);

    status = OvsAddConfiguredSwitchPorts(switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_WARN("Failed to add configured switch ports");
        goto cleanup;

    }
    status = OvsInitConfiguredSwitchNics(switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_WARN("Failed to add configured vports");
        OvsClearAllSwitchVports(switchContext);
        goto cleanup;
    }

cleanup:
    if (status != NDIS_STATUS_SUCCESS) {
        switchContext->isActivated = FALSE;
    }

    OVS_LOG_TRACE("Exit: activate switch:%p, isActivated: %s, status = %lx",
                  switchContext,
                  (switchContext->isActivated ? "TRUE" : "FALSE"), status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterNetPnPEvent function.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtNetPnPEvent(NDIS_HANDLE filterModuleContext,
                  PNET_PNP_EVENT_NOTIFICATION netPnPEvent)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;

    OVS_LOG_TRACE("Enter: filterModuleContext: %p, NetEvent: %d",
                  filterModuleContext, (netPnPEvent->NetPnPEvent).NetEvent);
    /*
     * NetEventSwitchActivate provides an asynchronous notification of
     * the switch completing activation.
     */
    if (netPnPEvent->NetPnPEvent.NetEvent == NetEventSwitchActivate) {
        ASSERT(switchContext->isActivated == FALSE);
        if (switchContext->isActivated == FALSE) {
            status = OvsActivateSwitch(switchContext);
            OVS_LOG_TRACE("OvsExtNetPnPEvent: activated switch: %p "
                          "status: %s", switchContext,
                          status ? "TRUE" : "FALSE");
        }
    } else if (netPnPEvent->NetPnPEvent.NetEvent == NetEventFilterPreDetach) {
        switchContext->dataFlowState = OvsSwitchPaused;
        KeMemoryBarrier();
    }

    status = NdisFNetPnPEvent(switchContext->NdisFilterHandle,
                              netPnPEvent);
    OVS_LOG_TRACE("Exit: OvsExtNetPnPEvent");

    return status;
}
