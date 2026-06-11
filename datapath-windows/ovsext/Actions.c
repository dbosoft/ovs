/*
 * Copyright (c) 2014, 2016 VMware, Inc.
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

#include "Actions.h"
#include "Conntrack.h"
#include "Crc32c.h"
#include "Debug.h"
#include "Event.h"
#include "Flow.h"
#include "Gre.h"
#include "Jhash.h"
#include "Meter.h"
#include "Mpls.h"
#include "NetProto.h"
#include "Offload.h"
#include "PacketIO.h"
#include "Recirc.h"
#include "Switch.h"
#include "User.h"
#include "Vport.h"
#include "Vxlan.h"
#include "Geneve.h"
#include "IpFragment.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_ACTION

#define OVS_DEST_PORTS_ARRAY_MIN_SIZE 2

typedef struct _OVS_ACTION_STATS {
    UINT64 rxGre;
    UINT64 txGre;
    UINT64 rxVxlan;
    UINT64 txVxlan;
    UINT64 rxGeneve;
    UINT64 txGeneve;
    UINT64 flowMiss;
    UINT64 flowUserspace;
    UINT64 txTcp;
    UINT32 failedFlowMiss;
    UINT32 noVport;
    UINT32 failedFlowExtract;
    UINT32 noResource;
    UINT32 noCopiedNbl;
    UINT32 failedEncap;
    UINT32 failedDecap;
    UINT32 cannotGrowDest;
    UINT32 zeroActionLen;
    UINT32 failedChecksum;
    UINT32 deferredActionsQueueFull;
    UINT32 deferredActionsExecLimit;
    UINT32 explicitDrop;
} OVS_ACTION_STATS, *POVS_ACTION_STATS;

OVS_ACTION_STATS ovsActionStats;

/*
 * --------------------------------------------------------------------------
 * OvsInitForwardingCtx --
 *     Function to init/re-init the 'ovsFwdCtx' context as the actions pipeline
 *     is being executed.
 *
 * Result:
 *     NDIS_STATUS_SUCCESS on success
 *     Other NDIS_STATUS upon failure. Upon failure, it is safe to call
 *     OvsCompleteNBLForwardingCtx(), since 'ovsFwdCtx' has been initialized
 *     enough for OvsCompleteNBLForwardingCtx() to do its work.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsInitForwardingCtx(OvsForwardingContext *ovsFwdCtx,
                     POVS_SWITCH_CONTEXT switchContext,
                     PNET_BUFFER_LIST curNbl,
                     UINT32 srcVportNo,
                     ULONG sendFlags,
                     PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail,
                     OvsCompletionList *completionList,
                     OVS_PACKET_HDR_INFO *layers,
                     BOOLEAN resetTunnelInfo)
{
    ASSERT(ovsFwdCtx);
    ASSERT(switchContext);
    ASSERT(curNbl);
    ASSERT(fwdDetail);

    /*
     * Set values for curNbl and switchContext so upon failures, we have enough
     * information to do cleanup.
     */
    ovsFwdCtx->curNbl = curNbl;
    ovsFwdCtx->switchContext = switchContext;
    ovsFwdCtx->completionList = completionList;
    ovsFwdCtx->fwdDetail = fwdDetail;

    if (fwdDetail->NumAvailableDestinations > 0) {
        /*
         * XXX: even though MSDN says GetNetBufferListDestinations() returns
         * NDIS_STATUS, the header files say otherwise.
         */
        switchContext->NdisSwitchHandlers.GetNetBufferListDestinations(
            switchContext->NdisSwitchContext, curNbl,
            &ovsFwdCtx->destinationPorts);

        ASSERT(ovsFwdCtx->destinationPorts);
        /* Ensure that none of the elements are consumed yet. */
        ASSERT(ovsFwdCtx->destinationPorts->NumElements ==
               fwdDetail->NumAvailableDestinations);
    } else {
        ovsFwdCtx->destinationPorts = NULL;
    }
    ovsFwdCtx->destPortsSizeIn = fwdDetail->NumAvailableDestinations;
    ovsFwdCtx->destPortsSizeOut = 0;
    ovsFwdCtx->srcVportNo = srcVportNo;
    ovsFwdCtx->sendFlags = sendFlags;
    if (layers) {
        ovsFwdCtx->layers = *layers;
    } else {
        RtlZeroMemory(&ovsFwdCtx->layers, sizeof ovsFwdCtx->layers);
    }
    if (resetTunnelInfo) {
        ovsFwdCtx->tunnelTxNic = NULL;
        ovsFwdCtx->tunnelRxNic = NULL;
        RtlZeroMemory(&ovsFwdCtx->tunKey, sizeof ovsFwdCtx->tunKey);
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoFragmentNbl --
 *     Utility function to Fragment nbl based on mru.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsDoFragmentNbl(OvsForwardingContext *ovsFwdCtx, UINT16 mru)
{
    PNET_BUFFER_LIST fragNbl = NULL;
    fragNbl = OvsFragmentNBL(ovsFwdCtx->switchContext,
                             ovsFwdCtx->curNbl,
                             &(ovsFwdCtx->layers),
                             mru, 0, TRUE);

   if (fragNbl != NULL) {
        OvsCompleteNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl, TRUE);
        ovsFwdCtx->curNbl = fragNbl;
    } else {
        OVS_LOG_INFO("Fragment NBL failed for MRU = %u", mru);
    }
}

/*
 * --------------------------------------------------------------------------
 * OvsDetectTunnelRxPkt --
 *     Utility function for an RX packet to detect its tunnel type.
 *
 * Result:
 *  True  - if the tunnel type was detected.
 *  False - if not a tunnel packet or tunnel type not supported.
 * --------------------------------------------------------------------------
 */
static __inline BOOLEAN
OvsDetectTunnelRxPkt(OvsForwardingContext *ovsFwdCtx,
                     const OvsFlowKey *flowKey)
{
    POVS_VPORT_ENTRY tunnelVport = NULL;

    /* XXX: we should also check for the length of the UDP payload to pick
     * packets only if they are at least VXLAN header size.
     */

     /*
      * For some of the tunnel types such as GRE, the dstPort is not applicable
      * since GRE does not have a L4 port. We use '0' for convenience.
      */

    if ((flowKey->l2.dlType == htons(ETH_TYPE_IPV4) &&
        !flowKey->ipKey.nwFrag) ||
        (flowKey->l2.dlType == htons(ETH_TYPE_IPV6) &&
        !flowKey->ipv6Key.nwFrag)) {
        UINT16 dstPort = 0;
        uint8_t nwProto = 0;
        if (flowKey->l2.dlType == htons(ETH_TYPE_IPV6)) {
            dstPort = htons(flowKey->ipv6Key.l4.tpDst);
            nwProto = flowKey->ipv6Key.nwProto;
         } else if (flowKey->l2.dlType == htons(ETH_TYPE_IPV4)) {
            dstPort = htons(flowKey->ipKey.l4.tpDst);
            nwProto = flowKey->ipKey.nwProto;
        }
        ASSERT(nwProto != IPPROTO_GRE || dstPort == 0);

        tunnelVport =
            OvsFindTunnelVportByDstPortAndNWProto(ovsFwdCtx->switchContext,
                                                  dstPort, nwProto);
        if (tunnelVport) {
            switch(tunnelVport->ovsType) {
            case OVS_VPORT_TYPE_VXLAN:
                ovsActionStats.rxVxlan++;
                break;
            case OVS_VPORT_TYPE_GENEVE:
                ovsActionStats.rxGeneve++;
                break;
            case OVS_VPORT_TYPE_GRE:
                ovsActionStats.rxGre++;
                break;
            }
        }
    }

    // We might get tunnel packets even before the tunnel gets initialized.
    if (tunnelVport) {
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
        ovsFwdCtx->tunnelRxNic = tunnelVport;
        return TRUE;
    }

    return FALSE;
}

/*
 * --------------------------------------------------------------------------
 * OvsDetectTunnelPkt --
 *     Utility function to detect if a packet is to be subjected to
 *     tunneling (Tx) or de-tunneling (Rx). Various factors such as source
 *     port, destination port, packet contents, and previously setup tunnel
 *     context are used.
 *
 * Result:
 *  True  - If the packet is to be subjected to tunneling.
 *          In case of invalid tunnel context, the tunneling functionality is
 *          a no-op and is completed within this function itself by consuming
 *          all of the tunneling context.
 *  False - If not a tunnel packet or tunnel type not supported. Caller should
 *          process the packet as a non-tunnel packet.
 * --------------------------------------------------------------------------
 */
static __inline BOOLEAN
OvsDetectTunnelPkt(OvsForwardingContext *ovsFwdCtx,
                   const POVS_VPORT_ENTRY dstVport,
                   const OvsFlowKey *flowKey)
{
    if (OvsIsInternalVportType(dstVport->ovsType)) {
        /*
         * Rx:
         * The source of NBL during tunneling Rx could be the external
         * port or if it is being executed from userspace, the source port is
         * default port.
         */
        BOOLEAN validSrcPort =
            (OvsIsExternalVportByPortId(ovsFwdCtx->switchContext,
                 ovsFwdCtx->fwdDetail->SourcePortId)) ||
            (ovsFwdCtx->fwdDetail->SourcePortId ==
                 NDIS_SWITCH_DEFAULT_PORT_ID);

        if (validSrcPort && OvsDetectTunnelRxPkt(ovsFwdCtx, flowKey)) {
            ASSERT(ovsFwdCtx->tunnelTxNic == NULL);
            ASSERT(ovsFwdCtx->tunnelRxNic != NULL);
            return TRUE;
        }
    } else if (OvsIsTunnelVportType(dstVport->ovsType)) {
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);

        /*
         * Tx:
         * The destination port is a tunnel port. Encapsulation must be
         * performed only on packets that originate from:
         * - a VIF port
         * - a bridge-internal port (packets generated from userspace)
         * - no port.
         * - tunnel port
         * If the packet will not be encapsulated, consume the tunnel context
         * by clearing it.
         */
        if (ovsFwdCtx->srcVportNo != OVS_DPPORT_NUMBER_INVALID) {

            /* dispatchLock is held across the action pipeline by the NDIS
             * ingress path; PREfast cannot track the NDIS RW-lock across the
             * call chain (genuine false positive). */
#pragma warning(suppress: 26110)
            POVS_VPORT_ENTRY vport = OvsFindVportByPortNo(
                ovsFwdCtx->switchContext, ovsFwdCtx->srcVportNo);

            if (!vport ||
                (vport->ovsType != OVS_VPORT_TYPE_NETDEV &&
                 vport->ovsType != OVS_VPORT_TYPE_INTERNAL &&
                 !OvsIsTunnelVportType(vport->ovsType))) {
                RtlZeroMemory(&ovsFwdCtx->tunKey.dst, sizeof(ovsFwdCtx->tunKey.dst));
            }
        }

        /* Tunnel the packet only if tunnel context is set. */
        if (!OvsIphIsZero(&(ovsFwdCtx->tunKey.dst))) {
            switch(dstVport->ovsType) {
            case OVS_VPORT_TYPE_GRE:
                ovsActionStats.txGre++;
                break;
            case OVS_VPORT_TYPE_VXLAN:
                ovsActionStats.txVxlan++;
                break;
            case OVS_VPORT_TYPE_GENEVE:
               ovsActionStats.txGeneve++;
               break;
            }
            ovsFwdCtx->tunnelTxNic = dstVport;
        }

        return TRUE;
    }

    return FALSE;
}


/*
 * --------------------------------------------------------------------------
 * OvsAddPorts --
 *     Add the specified destination vport into the forwarding context. If the
 *     vport is a VIF/external port, it is added directly to the NBL. If it is
 *     a tunneling port, it is NOT added to the NBL.
 *
 * Result:
 *     NDIS_STATUS_SUCCESS on success
 *     Other NDIS_STATUS upon failure.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsAddPorts(OvsForwardingContext *ovsFwdCtx,
            OvsFlowKey *flowKey,
            NDIS_SWITCH_PORT_ID dstPortId,
            BOOLEAN preserveVLAN,
            BOOLEAN preservePriority)
{
    POVS_VPORT_ENTRY vport;
    PNDIS_SWITCH_PORT_DESTINATION fwdPort;
    NDIS_STATUS status;
    POVS_SWITCH_CONTEXT switchContext = ovsFwdCtx->switchContext;

    /*
     * We hold the dispatch lock that protects the list of vports, so vports
     * validated here can be added as destinations safely before we call into
     * NDIS.
     *
     * Some of the vports can be tunnelled ports as well in which case
     * they should be added to a separate list of tunnelled destination ports
     * instead of the VIF ports. The context for the tunnel is settable
     * in OvsForwardingContext.
     */
    /* dispatchLock held by the NDIS ingress path; PREfast cannot track the
     * NDIS RW-lock across the call chain (genuine false positive). */
#pragma warning(suppress: 26110)
    vport = OvsFindVportByPortNo(ovsFwdCtx->switchContext, dstPortId);
    if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
        /*
         * There may be some latency between a port disappearing, and userspace
         * updating the recalculated flows. In the meantime, handle invalid
         * ports gracefully.
         */
        ovsActionStats.noVport++;
        return NDIS_STATUS_SUCCESS;
    }
    ASSERT(vport->nicState == NdisSwitchNicStateConnected);
    vport->stats.txPackets++;
    vport->stats.txBytes +=
        NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));

    if (OvsDetectTunnelPkt(ovsFwdCtx, vport, flowKey)) {
        return NDIS_STATUS_SUCCESS;
    }

    if (ovsFwdCtx->destPortsSizeOut == ovsFwdCtx->destPortsSizeIn) {
        if (ovsFwdCtx->destPortsSizeIn == 0) {
            ASSERT(ovsFwdCtx->destinationPorts == NULL);
            ASSERT(ovsFwdCtx->fwdDetail->NumAvailableDestinations == 0);
            status =
                switchContext->NdisSwitchHandlers.GrowNetBufferListDestinations(
                    switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
                    OVS_DEST_PORTS_ARRAY_MIN_SIZE,
                    &ovsFwdCtx->destinationPorts);
            if (status != NDIS_STATUS_SUCCESS) {
                ovsActionStats.cannotGrowDest++;
                return status;
            }
            ovsFwdCtx->destPortsSizeIn =
                ovsFwdCtx->fwdDetail->NumAvailableDestinations;
            ASSERT(ovsFwdCtx->destinationPorts);
        } else {
            ASSERT(ovsFwdCtx->destinationPorts != NULL);
            /*
             * NumElements:
             * A ULONG value that specifies the total number of
             * NDIS_SWITCH_PORT_DESTINATION elements in the
             * NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY structure.
             *
             * NumDestinations:
             * A ULONG value that specifies the number of
             * NDIS_SWITCH_PORT_DESTINATION elements in the
             * NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY structure that
             * specify port destinations.
             *
             * NumAvailableDestinations:
             * A value that specifies the number of unused extensible switch
             * destination ports elements within an NET_BUFFER_LIST structure.
             */
            ASSERT(ovsFwdCtx->destinationPorts->NumElements ==
                   ovsFwdCtx->destPortsSizeIn);
            ASSERT(ovsFwdCtx->destinationPorts->NumDestinations ==
                   ovsFwdCtx->destPortsSizeOut -
                   ovsFwdCtx->fwdDetail->NumAvailableDestinations);
            ASSERT(ovsFwdCtx->fwdDetail->NumAvailableDestinations > 0);
            /*
             * Before we grow the array of destination ports, the current set
             * of ports needs to be committed. Only the ports added since the
             * last commit need to be part of the new update.
             */
            status = switchContext->NdisSwitchHandlers.UpdateNetBufferListDestinations(
                switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
                ovsFwdCtx->fwdDetail->NumAvailableDestinations,
                ovsFwdCtx->destinationPorts);
            if (status != NDIS_STATUS_SUCCESS) {
                ovsActionStats.cannotGrowDest++;
                return status;
            }
            ASSERT(ovsFwdCtx->destinationPorts->NumElements ==
                   ovsFwdCtx->destPortsSizeIn);
            ASSERT(ovsFwdCtx->destinationPorts->NumDestinations ==
                   ovsFwdCtx->destPortsSizeOut);
            ASSERT(ovsFwdCtx->fwdDetail->NumAvailableDestinations == 0);

            status = switchContext->NdisSwitchHandlers.GrowNetBufferListDestinations(
                switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
                ovsFwdCtx->destPortsSizeIn, &ovsFwdCtx->destinationPorts);
            if (status != NDIS_STATUS_SUCCESS) {
                ovsActionStats.cannotGrowDest++;
                return status;
            }
            ASSERT(ovsFwdCtx->destinationPorts != NULL);
            ovsFwdCtx->destPortsSizeIn <<= 1;
        }
    }

    ASSERT(ovsFwdCtx->destPortsSizeOut < ovsFwdCtx->destPortsSizeIn);
    fwdPort =
        NDIS_SWITCH_PORT_DESTINATION_AT_ARRAY_INDEX(ovsFwdCtx->destinationPorts,
                                                    ovsFwdCtx->destPortsSizeOut);

    fwdPort->PortId = vport->portId;
    fwdPort->NicIndex = vport->nicIndex;
    fwdPort->IsExcluded = 0;
    fwdPort->PreserveVLAN = preserveVLAN;
    fwdPort->PreservePriority = preservePriority;
    ovsFwdCtx->destPortsSizeOut += 1;

    return NDIS_STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 * OvsClearTunTxCtx --
 *     Utility function to clear tx tunneling context.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsClearTunTxCtx(OvsForwardingContext *ovsFwdCtx)
{
    ovsFwdCtx->tunnelTxNic = NULL;
    RtlZeroMemory(&ovsFwdCtx->tunKey.dst, sizeof(ovsFwdCtx->tunKey.dst));
}


/*
 * --------------------------------------------------------------------------
 * OvsClearTunRxCtx --
 *     Utility function to clear rx tunneling context.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsClearTunRxCtx(OvsForwardingContext *ovsFwdCtx)
{
    ovsFwdCtx->tunnelRxNic = NULL;
    RtlZeroMemory(&ovsFwdCtx->tunKey.dst, sizeof(ovsFwdCtx->tunKey.dst));
}


/*
 * --------------------------------------------------------------------------
 * OvsCompleteNBLForwardingCtx --
 *     This utility function is responsible for freeing/completing an NBL - either
 *     by adding it to a completion list or by freeing it.
 *
 * Side effects:
 *     It also resets the necessary fields in 'ovsFwdCtx'.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsCompleteNBLForwardingCtx(OvsForwardingContext *ovsFwdCtx,
                            PCWSTR dropReason)
{
    NDIS_STRING filterReason;

    RtlInitUnicodeString(&filterReason, dropReason);
    if (ovsFwdCtx->completionList) {
        OvsAddPktCompletionList(ovsFwdCtx->completionList, TRUE,
            ovsFwdCtx->fwdDetail->SourcePortId, ovsFwdCtx->curNbl, 1,
            &filterReason);
        ovsFwdCtx->curNbl = NULL;
    } else {
        /* If there is no completionList, we assume this is ovs created NBL */
        ovsFwdCtx->curNbl = OvsCompleteNBL(ovsFwdCtx->switchContext,
                                           ovsFwdCtx->curNbl, TRUE);
        ASSERT(ovsFwdCtx->curNbl == NULL);
    }
    /* XXX: these can be made debug only to save cycles. Ideally the pipeline
     * using these fields should reset the values at the end of the pipeline. */
    ovsFwdCtx->destPortsSizeOut = 0;
    ovsFwdCtx->tunnelTxNic = NULL;
    ovsFwdCtx->tunnelRxNic = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoFlowLookupOutput --
 *     Function to be used for the second stage of a tunneling workflow, ie.:
 *     - On the encapsulated packet on Tx path, to do a flow extract, flow
 *       lookup and excuting the actions.
 *     - On the decapsulated packet on Rx path, to do a flow extract, flow
 *       lookup and excuting the actions.
 *
 *     XXX: It is assumed that the NBL in 'ovsFwdCtx' is owned by OVS. This is
 *     until the new buffer management framework is adopted.
 *
 * Side effects:
 *     The NBL in 'ovsFwdCtx' is consumed.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsDoFlowLookupOutput(OvsForwardingContext* ovsFwdCtx)
{
    OvsFlowKey key = { 0 };
    OvsFlow *flow = NULL;
    UINT64 hash = 0;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    /* dispatchLock held by the NDIS ingress path; PREfast cannot track the
     * NDIS RW-lock across the call chain (genuine false positive). */
#pragma warning(suppress: 26110)
    POVS_VPORT_ENTRY vport =
        OvsFindVportByPortNo(ovsFwdCtx->switchContext, ovsFwdCtx->srcVportNo);
    if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-Dropped due to internal/tunnel port removal");
        ovsActionStats.noVport++;
        return NDIS_STATUS_SUCCESS;
    }
    ASSERT(vport->nicState == NdisSwitchNicStateConnected);

    /* Assert that in the Rx direction, key is always setup. */
    ASSERT(ovsFwdCtx->tunnelRxNic == NULL || !OvsIphIsZero(&(ovsFwdCtx->tunKey.dst)));
    status =
        OvsExtractFlow(ovsFwdCtx->curNbl, ovsFwdCtx->srcVportNo,
                       &key, &ovsFwdCtx->layers,
                       !OvsIphIsZero(&(ovsFwdCtx->tunKey.dst))? &(ovsFwdCtx->tunKey):NULL);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"OVS-Flow extract failed");
        ovsActionStats.failedFlowExtract++;
        return status;
    }

    flow = OvsLookupFlow(&ovsFwdCtx->switchContext->datapath, &key, &hash, FALSE);
    if (flow) {
        OvsFlowUsed(flow, ovsFwdCtx->curNbl, &ovsFwdCtx->layers);
        ovsFwdCtx->switchContext->datapath.hits++;
        status = OvsDoExecuteActions(ovsFwdCtx->switchContext,
                                     ovsFwdCtx->completionList,
                                     ovsFwdCtx->curNbl,
                                     ovsFwdCtx->srcVportNo,
                                     ovsFwdCtx->sendFlags,
                                     &key, &hash, &ovsFwdCtx->layers,
                                     flow->actions, flow->actionsLen);
        ovsFwdCtx->curNbl = NULL;
    } else {
        LIST_ENTRY missedPackets;
        UINT32 num = 0;
        ovsFwdCtx->switchContext->datapath.misses++;
        InitializeListHead(&missedPackets);
        status = OvsCreateAndAddPackets(NULL, 0, OVS_PACKET_CMD_MISS, vport,
                          &key,ovsFwdCtx->curNbl,
                          FALSE, &ovsFwdCtx->layers,
                          ovsFwdCtx->switchContext, &missedPackets, &num);
        if (num) {
            OvsQueuePackets(&missedPackets, num);
        }
        if (status == NDIS_STATUS_SUCCESS) {
            /* Complete the packet since it was copied to user buffer. */
            OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                L"OVS-Dropped since packet was copied to userspace");
            ovsActionStats.flowMiss++;
            status = NDIS_STATUS_SUCCESS;
        } else {
            OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                L"OVS-Dropped due to failure to queue to userspace");
            status = NDIS_STATUS_FAILURE;
            ovsActionStats.failedFlowMiss++;
        }
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsTunnelPortTx --
 *     The start function for Tx tunneling - encapsulates the packet, and
 *     outputs the packet on the PIF bridge.
 *
 * Side effects:
 *     The NBL in 'ovsFwdCtx' is consumed.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsTunnelPortTx(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    PNET_BUFFER_LIST newNbl = NULL;
    UINT32 srcVportNo;
    NDIS_SWITCH_NIC_INDEX srcNicIndex;
    NDIS_SWITCH_PORT_ID srcPortId;
    POVS_BUFFER_CONTEXT ctx;

    /*
     * Setup the source port to be the internal port to as to facilitate the
     * second OvsLookupFlow.
     */
    if (ovsFwdCtx->switchContext->countInternalVports <= 0 ||
        ovsFwdCtx->switchContext->virtualExternalVport == NULL) {
        OvsClearTunTxCtx(ovsFwdCtx);
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-Dropped since either internal or external port is absent");
        return NDIS_STATUS_FAILURE;
    }

    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(ovsFwdCtx->curNbl);
    if (ctx->mru != 0) {
        OvsDoFragmentNbl(ovsFwdCtx, ctx->mru);
    }
    OVS_FWD_INFO switchFwdInfo = { 0 };

    /* Apply the encapsulation. The encapsulation will not consume the NBL. */
    switch(ovsFwdCtx->tunnelTxNic->ovsType) {
    case OVS_VPORT_TYPE_GRE:
        status = OvsEncapGre(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                             &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                             &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    case OVS_VPORT_TYPE_VXLAN:
        status = OvsEncapVxlan(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                               &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                               &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    case OVS_VPORT_TYPE_GENEVE:
        status = OvsEncapGeneve(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                                &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                                &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    default:
        ASSERT(! "Tx: Unhandled tunnel type");
    }

    /* Reset the tunnel context so that it doesn't get used after this point. */
    OvsClearTunTxCtx(ovsFwdCtx);

    if (status == NDIS_STATUS_SUCCESS && switchFwdInfo.vport != NULL) {
        ASSERT(newNbl);
        /*
         * Save the 'srcVportNo', 'srcPortId', 'srcNicIndex' so that
         * this can be applied to the new NBL later on.
         */
        srcVportNo = switchFwdInfo.vport->portNo;
        srcPortId = switchFwdInfo.vport->portId;
        srcNicIndex = switchFwdInfo.vport->nicIndex;

        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Complete after cloning NBL for encapsulation");
        status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                      newNbl, srcVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      ovsFwdCtx->completionList,
                                      &ovsFwdCtx->layers, FALSE);
        ovsFwdCtx->curNbl = newNbl;
        /* Update the forwarding detail for the new NBL */
        ovsFwdCtx->fwdDetail->SourcePortId = srcPortId;
        ovsFwdCtx->fwdDetail->SourceNicIndex = srcNicIndex;
        status = OvsDoFlowLookupOutput(ovsFwdCtx);
        ASSERT(ovsFwdCtx->curNbl == NULL);
    } else {
        /*
         * XXX: Temporary freeing of the packet until we register a
         * callback to IP helper.
         */
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"OVS-Dropped due to encap failure");
        ovsActionStats.failedEncap++;
        status = NDIS_STATUS_SUCCESS;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsTunnelPortRx --
 *     Decapsulate the incoming NBL based on the tunnel type and goes through
 *     the flow lookup for the inner packet.
 *
 *     Note: IP checksum is validate here, but L4 checksum validation needs
 *     to be done by the corresponding tunnel types.
 *
 * Side effects:
 *     The NBL in 'ovsFwdCtx' is consumed.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsTunnelPortRx(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER_LIST newNbl = NULL;
    POVS_VPORT_ENTRY tunnelRxVport = ovsFwdCtx->tunnelRxNic;
    PCWSTR dropReason = L"OVS-dropped due to new decap packet";

    if (OvsValidateIPChecksum(ovsFwdCtx->curNbl, &ovsFwdCtx->layers)
            != NDIS_STATUS_SUCCESS) {
        ovsActionStats.failedChecksum++;
        OVS_LOG_INFO("Packet dropped due to IP checksum failure.");
        goto dropNbl;
    }

    /*
     * Decap port functions should return a new NBL if it was copied, and
     * this new NBL should be setup as the ovsFwdCtx->curNbl.
     */

    switch(tunnelRxVport->ovsType) {
    case OVS_VPORT_TYPE_GRE:
        status = OvsDecapGre(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                             &ovsFwdCtx->tunKey, &newNbl);
        break;
    case OVS_VPORT_TYPE_VXLAN:
        status = OvsDecapVxlan(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               &ovsFwdCtx->tunKey, &newNbl);
        break;
    case OVS_VPORT_TYPE_GENEVE:
        status = OvsDecapGeneve(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                &ovsFwdCtx->tunKey, &newNbl);
        break;
    default:
        OVS_LOG_ERROR("Rx: Unhandled tunnel type: %d\n",
                      tunnelRxVport->ovsType);
        ASSERT(! "Rx: Unhandled tunnel type");
        status = NDIS_STATUS_NOT_SUPPORTED;
    }

    if (status != NDIS_STATUS_SUCCESS) {
        ovsActionStats.failedDecap++;
        goto dropNbl;
    }

    /*
     * tunnelRxNic and other fields will be cleared, re-init the context
     * before usage.
      */
    OvsCompleteNBLForwardingCtx(ovsFwdCtx, dropReason);

    if (newNbl) {
        /* Decapsulated packet is in a new NBL */
        ovsFwdCtx->tunnelRxNic = tunnelRxVport;
        OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                             newNbl, tunnelRxVport->portNo, 0,
                             NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                             ovsFwdCtx->completionList,
                             &ovsFwdCtx->layers, FALSE);

        /*
         * Set the NBL's SourcePortId and SourceNicIndex to default values to
         * keep NDIS happy when we forward the packet.
         */
        ovsFwdCtx->fwdDetail->SourcePortId = NDIS_SWITCH_DEFAULT_PORT_ID;
        ovsFwdCtx->fwdDetail->SourceNicIndex = 0;

        status = OvsDoFlowLookupOutput(ovsFwdCtx);
    }
    ASSERT(ovsFwdCtx->curNbl == NULL);
    OvsClearTunRxCtx(ovsFwdCtx);

    return status;

dropNbl:
    OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-dropped due to decap failure");
    OvsClearTunRxCtx(ovsFwdCtx);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsOutputForwardingCtx --
 *     This function outputs an NBL to NDIS or to a tunneling pipeline based on
 *     the ports added so far into 'ovsFwdCtx'.
 *
 * Side effects:
 *     This function consumes the NBL - either by forwarding it successfully to
 *     NDIS, or adding it to the completion list in 'ovsFwdCtx', or freeing it.
 *
 *     Also makes sure that the list of destination ports - tunnel or otherwise is
 *     drained.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsOutputForwardingCtx(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    POVS_SWITCH_CONTEXT switchContext = ovsFwdCtx->switchContext;
    PCWSTR dropReason;
    POVS_BUFFER_CONTEXT ctx;

    /*
     * Handle the case where the some of the destination ports are tunneled
     * ports - the non-tunneled ports get a unmodified copy of the NBL, and the
     * tunneling pipeline starts when we output the packet to tunneled port.
     */
    if (ovsFwdCtx->destPortsSizeOut > 0) {
        PNET_BUFFER_LIST newNbl = NULL;
        PNET_BUFFER nb;
        UINT32 portsToUpdate =
            ovsFwdCtx->fwdDetail->NumAvailableDestinations -
            (ovsFwdCtx->destPortsSizeIn - ovsFwdCtx->destPortsSizeOut);

        ASSERT(ovsFwdCtx->destinationPorts != NULL);

        /*
         * Create a copy of the packet in order to do encap on it later. Also,
         * don't copy the offload context since the encap'd packet has a
         * different set of headers. This will change when we implement offloads
         * before doing encapsulation.
         */
        if (ovsFwdCtx->tunnelTxNic != NULL || ovsFwdCtx->tunnelRxNic != NULL) {
            POVS_BUFFER_CONTEXT oldCtx, newCtx;
            nb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
            oldCtx = (POVS_BUFFER_CONTEXT)
                NET_BUFFER_LIST_CONTEXT_DATA_START(ovsFwdCtx->curNbl);
            newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext,
                                       ovsFwdCtx->curNbl,
                                       0, 0, TRUE /*copy NBL info*/);
            if (newNbl == NULL) {
                status = NDIS_STATUS_RESOURCES;
                ovsActionStats.noCopiedNbl++;
                dropReason = L"Dropped due to failure to create NBL copy.";
                goto dropit;
            }
            newCtx = (POVS_BUFFER_CONTEXT)
                NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);
            newCtx->mru = oldCtx->mru;
        }

        /* It does not seem like we'll get here unless 'portsToUpdate' > 0. */
        ASSERT(portsToUpdate > 0);
        status = switchContext->NdisSwitchHandlers.UpdateNetBufferListDestinations(
            switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
            portsToUpdate, ovsFwdCtx->destinationPorts);
        if (status != NDIS_STATUS_SUCCESS) {
            OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
            ovsActionStats.cannotGrowDest++;
            dropReason = L"Dropped due to failure to update destinations.";
            goto dropit;
        }

        ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(ovsFwdCtx->curNbl);
        if (ctx->mru != 0) {
            OvsDoFragmentNbl(ovsFwdCtx, ctx->mru);
        }

        OvsSendNBLIngress(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                          ovsFwdCtx->sendFlags);
        /* End this pipeline by resetting the corresponding context. */
        ovsFwdCtx->destPortsSizeOut = 0;
        ovsFwdCtx->curNbl = NULL;
        if (newNbl) {
            status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                          newNbl, ovsFwdCtx->srcVportNo, 0,
                                          NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                          ovsFwdCtx->completionList,
                                          &ovsFwdCtx->layers, FALSE);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"Dropped due to resources.";
                goto dropit;
            }
        }
    }

    if (ovsFwdCtx->tunnelTxNic != NULL) {
        status = OvsTunnelPortTx(ovsFwdCtx);
        ASSERT(ovsFwdCtx->tunnelTxNic == NULL);
        ASSERT(OvsIphIsZero(&(ovsFwdCtx->tunKey.dst)));
    } else if (ovsFwdCtx->tunnelRxNic != NULL) {
        status = OvsTunnelPortRx(ovsFwdCtx);
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
        ASSERT(OvsIphIsZero(&(ovsFwdCtx->tunKey.dst)));
    }
    ASSERT(ovsFwdCtx->curNbl == NULL);

    return status;

dropit:
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx, dropReason);
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsLookupFlowOutput --
 *     Utility function for external callers to do flow extract, lookup,
 *     actions execute on a given NBL.
 *
 *     Note: If this is being used from a callback function, make sure that the
 *     arguments specified are still valid in the asynchronous context.
 *
 * Side effects:
 *     This function consumes the NBL.
 * --------------------------------------------------------------------------
 */
VOID
OvsLookupFlowOutput(POVS_SWITCH_CONTEXT switchContext,
                    VOID *compList,
                    PNET_BUFFER_LIST curNbl,
                    POVS_VPORT_ENTRY internalVport)
{
    NDIS_STATUS status;
    OvsForwardingContext ovsFwdCtx;

    /* XXX: make sure comp list was not a stack variable previously. */
    OvsCompletionList *completionList = (OvsCompletionList *)compList;

    /*
     * XXX: can internal port disappear while we are busy doing ARP resolution?
     * It could, but will we get this callback from IP helper in that case. Need
     * to check.
     */
    ASSERT(switchContext->countInternalVports > 0);
    status = OvsInitForwardingCtx(&ovsFwdCtx, switchContext, curNbl,
                                  internalVport->portNo, 0,
                                  NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl),
                                  completionList, NULL, TRUE);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                                    L"OVS-Dropped due to resources");
        return;
    }

    ASSERT(FALSE);
    /*
     * XXX: We need to acquire the dispatch lock and the datapath lock.
     */

    OvsDoFlowLookupOutput(&ovsFwdCtx);
}


/*
 * --------------------------------------------------------------------------
 * OvsOutputBeforeSetAction --
 *     Function to be called to complete one set of actions on an NBL, before
 *     we start the next one.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsOutputBeforeSetAction(OvsForwardingContext *ovsFwdCtx)
{
    PNET_BUFFER_LIST newNbl;
    NDIS_STATUS status;

    /*
     * Create a copy and work on the copy after this point. The original NBL is
     * forwarded. One reason to not use the copy for forwarding is that
     * ports have already been added to the original NBL, and it might be
     * inefficient/impossible to remove/re-add them to the copy. There's no
     * notion of removing the ports, the ports need to be marked as
     * "isExcluded". There's seems no real advantage to retaining the original
     * and sending out the copy instead.
     *
     * XXX: We are copying the offload context here. This is to handle actions
     * such as:
     * outport, pop_vlan(), outport, push_vlan(), outport
     *
     * copy size needs to include inner ether + IP + TCP, need to revisit
     * if we support IP options.
     * XXX Head room needs to include the additional encap.
     * XXX copySize check is not considering multiple NBs.
     */
    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);

    ASSERT(ovsFwdCtx->destPortsSizeOut > 0 ||
           ovsFwdCtx->tunnelTxNic != NULL || ovsFwdCtx->tunnelRxNic != NULL);

    /* Send the original packet out and save the original source port number */
    UINT32 tempVportNo = ovsFwdCtx->srcVportNo;
    status = OvsOutputForwardingCtx(ovsFwdCtx);
    ASSERT(ovsFwdCtx->curNbl == NULL);
    ASSERT(ovsFwdCtx->destPortsSizeOut == 0);
    ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
    ASSERT(ovsFwdCtx->tunnelTxNic == NULL);

    /* If we didn't make a copy, can't continue. */
    if (newNbl == NULL) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_RESOURCES;
    }

    /* Finish the remaining actions with the new NBL */
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
    } else {
        status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                      newNbl, tempVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      ovsFwdCtx->completionList,
                                      &ovsFwdCtx->layers, FALSE);
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsPopFieldInPacketBuf --
 *     Function to pop a specified field of length 'shiftLength' located at
 *     'shiftOffset' from the Ethernet header. The data on the left of the
 *     'shiftOffset' is right shifted.
 *
 *     Returns a pointer to the new start in 'bufferData'.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsPopFieldInPacketBuf(OvsForwardingContext *ovsFwdCtx,
                       UINT32 shiftOffset,
                       UINT32 shiftLength,
                       PUINT8 *bufferData)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    UINT32 packetLen, mdlLen;
    PNET_BUFFER_LIST newNbl;
    NDIS_STATUS status;

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /* copy NBL info */);
    if (!newNbl) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_RESOURCES;
    }

    /* Complete the original NBL and create a copy to modify. */
    OvsCompleteNBLForwardingCtx(ovsFwdCtx, L"OVS-Dropped due to copy");

    status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext, newNbl,
                                  ovsFwdCtx->srcVportNo, 0,
                                  NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                  NULL, &ovsFwdCtx->layers, FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Dropped due to resouces");
        return NDIS_STATUS_RESOURCES;
    }

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    ASSERT(curNb->Next == NULL);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    mdlLen -= NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    /* Bail out if L2 + shiftLength is not contiguous in the first buffer. */
    if (MIN(packetLen, mdlLen) < sizeof(EthHdr) + shiftLength) {
        ASSERT(FALSE);
        return NDIS_STATUS_FAILURE;
    }
    bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    /* XXX At the momemnt !bufferData means it should be treated as VLAN. We
     * should split the function and refactor. */
    if (!bufferData) {
        EthHdr *ethHdr = (EthHdr *)bufferStart;
        if (ethHdr->Type != ETH_TYPE_802_1PQ_NBO) {
            OVS_LOG_ERROR("Invalid ethHdr type %u, nbl %p", ethHdr->Type, ovsFwdCtx->curNbl);
            return NDIS_STATUS_INVALID_PACKET;
        }
    }
    RtlMoveMemory(bufferStart + shiftLength, bufferStart, shiftOffset);
    NdisAdvanceNetBufferDataStart(curNb, shiftLength, FALSE, NULL);

    if (bufferData) {
        *bufferData = bufferStart + shiftLength;
    }

    return NDIS_STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 * OvsPopVlanInPktBuf --
 *     Function to pop a VLAN tag when the tag is in the packet buffer.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsPopVlanInPktBuf(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status;
    OVS_PACKET_HDR_INFO* layers = &ovsFwdCtx->layers;

    /*
     * Declare a dummy vlanTag structure since we need to compute the size
     * of shiftLength. The NDIS one is a unionized structure.
     */
    NDIS_PACKET_8021Q_INFO vlanTag = {0};
    UINT32 shiftLength = sizeof(vlanTag.TagHeader);
    UINT32 shiftOffset = sizeof(DL_EUI48) + sizeof(DL_EUI48);

    status = OvsPopFieldInPacketBuf(ovsFwdCtx, shiftOffset, shiftLength,
                                    NULL);

    if (status == NDIS_STATUS_SUCCESS) {
        layers->l3Offset -= (UINT16) shiftLength;
        layers->l4Offset -= (UINT16) shiftLength;
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsActionMplsPop --
 *     Function to pop the first MPLS label from the current packet.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsActionMplsPop(OvsForwardingContext *ovsFwdCtx,
                 ovs_be16 ethertype)
{
    NDIS_STATUS status;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    EthHdr *ethHdr = NULL;

    status = OvsPopFieldInPacketBuf(ovsFwdCtx, sizeof(*ethHdr),
                                    MPLS_HLEN, (PUINT8*)&ethHdr);
    if (status == NDIS_STATUS_SUCCESS) {
        if (ethHdr && OvsEthertypeIsMpls(ethHdr->Type)) {
            ethHdr->Type = ethertype;
        }

        layers->l3Offset -= MPLS_HLEN;
        layers->l4Offset -= MPLS_HLEN;
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsActionMplsPush --
 *     Function to push the MPLS label into the current packet.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsActionMplsPush(OvsForwardingContext *ovsFwdCtx,
                  const struct ovs_action_push_mpls *mpls)
{
    NDIS_STATUS status;
    PNET_BUFFER curNb = NULL;
    PMDL curMdl = NULL;
    PUINT8 bufferStart = NULL;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    EthHdr *ethHdr = NULL;
    MPLSHdr *mplsHdr = NULL;
    UINT32 mdlLen = 0, curMdlOffset = 0;
    PNET_BUFFER_LIST newNbl;

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               layers->l3Offset, MPLS_HLEN, TRUE);
    if (!newNbl) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_RESOURCES;
    }
    OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                L"Complete after partial copy.");

    status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                  newNbl, ovsFwdCtx->srcVportNo, 0,
                                  NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                  NULL, &ovsFwdCtx->layers, FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"OVS-Dropped due to resources");
        return NDIS_STATUS_RESOURCES;
    }

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    ASSERT(curNb->Next == NULL);

    status = NdisRetreatNetBufferDataStart(curNb, MPLS_HLEN, 0, NULL);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!curMdl) {
        ovsActionStats.noResource++;
        return NDIS_STATUS_RESOURCES;
    }

    curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    mdlLen -= curMdlOffset;
    ASSERT(mdlLen >= MPLS_HLEN);

    ethHdr = (EthHdr *)(bufferStart + curMdlOffset);
    ASSERT(ethHdr);
    RtlMoveMemory(ethHdr, (UINT8*)ethHdr + MPLS_HLEN, sizeof(*ethHdr));
    ethHdr->Type = mpls->mpls_ethertype;

    mplsHdr = (MPLSHdr *)(ethHdr + 1);
    mplsHdr->lse = mpls->mpls_lse;

    layers->l3Offset += MPLS_HLEN;
    layers->l4Offset += MPLS_HLEN;

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateEthHeader --
 *      Updates the ethernet header in ovsFwdCtx.curNbl inline based on the
 *      specified key.
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsUpdateEthHeader(OvsForwardingContext *ovsFwdCtx,
                   OvsFlowKey *key,
                   const struct ovs_key_ethernet *ethAttr)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    EthHdr *ethHdr;
    UINT32 packetLen, mdlLen;

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    ASSERT(curNb->Next == NULL);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!bufferStart) {
        ovsActionStats.noResource++;
        return NDIS_STATUS_RESOURCES;
    }
    mdlLen -= NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    ASSERT(mdlLen > 0);
    /* Bail out if the L2 header is not in a contiguous buffer. */
    if (MIN(packetLen, mdlLen) < sizeof *ethHdr) {
        ASSERT(FALSE);
        return NDIS_STATUS_FAILURE;
    }
    ethHdr = (EthHdr *)(bufferStart + NET_BUFFER_CURRENT_MDL_OFFSET(curNb));

    RtlCopyMemory(ethHdr->Destination, ethAttr->eth_dst, ETH_ADDR_LENGTH);
    RtlCopyMemory(ethHdr->Source, ethAttr->eth_src, ETH_ADDR_LENGTH);
    /* Update l2 flow key */
    RtlCopyMemory(key->l2.dlDst, ethAttr->eth_dst, ETH_ADDR_LENGTH);
    RtlCopyMemory(key->l2.dlSrc, ethAttr->eth_src, ETH_ADDR_LENGTH);

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsGetHeaderBySize --
 *      Tries to retrieve a continuous buffer from 'ovsFwdCtx->curnbl' of size
 *      'size'.
 *      If the original buffer is insufficient it will, try to clone the net
 *      buffer list and force the size.
 *      Returns 'NULL' on failure or a pointer to the first byte of the data
 *      in the first net buffer of the net buffer list 'nbl'.
 *----------------------------------------------------------------------------
 */
PUINT8 OvsGetHeaderBySize(OvsForwardingContext *ovsFwdCtx,
                          UINT32 size)
{
    PNET_BUFFER curNb;
    UINT32 mdlLen, packetLen;
    PMDL curMdl;
    ULONG curMdlOffset;
    PUINT8 start;

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    ASSERT(curNb->Next == NULL);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &start, &mdlLen, LowPagePriority);
    if (!start) {
        ovsActionStats.noResource++;
        return NULL;
    }

    curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    mdlLen -= curMdlOffset;
    ASSERT((INT)mdlLen >= 0);

    /* Count of number of bytes of valid data there are in the first MDL. */
    mdlLen = MIN(packetLen, mdlLen);
    if (mdlLen < size) {
        PNET_BUFFER_LIST newNbl;
        NDIS_STATUS status;
        newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                   size, 0, TRUE /*copy NBL info*/);
        if (!newNbl) {
            ovsActionStats.noCopiedNbl++;
            return NULL;
        }
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Complete after partial copy.");

        status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                      newNbl, ovsFwdCtx->srcVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      NULL, &ovsFwdCtx->layers, FALSE);

        if (status != NDIS_STATUS_SUCCESS) {
            OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                        L"OVS-Dropped due to resources");
            return NULL;
        }

        curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
        ASSERT(curNb->Next == NULL);
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        NdisQueryMdl(curMdl, &start, &mdlLen, LowPagePriority);
        if (!curMdl) {
            ovsActionStats.noResource++;
            return NULL;
        }
        curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
        mdlLen -= curMdlOffset;
        ASSERT(mdlLen >= size);
    }

    return start + curMdlOffset;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateUdpPorts --
 *      Updates the UDP source or destination port in ovsFwdCtx.curNbl inline
 *      based on the specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateUdpPorts(OvsForwardingContext *ovsFwdCtx,
                  OvsFlowKey *key,
                  const struct ovs_key_udp *udpAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    UDPHdr *udpHdr = NULL;

    ASSERT(layers->value != 0);

    if (!layers->isUdp) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, layers->l7Offset);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    if (udpHdr->check) {
        if (udpHdr->source != udpAttr->udp_src) {
            udpHdr->check = ChecksumUpdate16(udpHdr->check, udpHdr->source,
                                             udpAttr->udp_src);
            udpHdr->source = udpAttr->udp_src;
            key->ipKey.l4.tpSrc = udpAttr->udp_src;
        }
        if (udpHdr->dest != udpAttr->udp_dst) {
            udpHdr->check = ChecksumUpdate16(udpHdr->check, udpHdr->dest,
                                             udpAttr->udp_dst);
            udpHdr->dest = udpAttr->udp_dst;
            key->ipKey.l4.tpDst = udpAttr->udp_dst;
        }
    } else {
        udpHdr->source = udpAttr->udp_src;
        key->ipKey.l4.tpSrc = udpAttr->udp_src;
        udpHdr->dest = udpAttr->udp_dst;
        key->ipKey.l4.tpDst = udpAttr->udp_dst;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateTcpPorts --
 *      Updates the TCP source or destination port in ovsFwdCtx.curNbl inline
 *      based on the specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateTcpPorts(OvsForwardingContext *ovsFwdCtx,
                  OvsFlowKey *key,
                  const struct ovs_key_tcp *tcpAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    TCPHdr *tcpHdr = NULL;

    ASSERT(layers->value != 0);

    if (!layers->isTcp) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, layers->l7Offset);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);

    if (tcpHdr->source != tcpAttr->tcp_src) {
        tcpHdr->check = ChecksumUpdate16(tcpHdr->check, tcpHdr->source,
                                         tcpAttr->tcp_src);
        tcpHdr->source = tcpAttr->tcp_src;
        key->ipKey.l4.tpSrc = tcpAttr->tcp_src;
    }
    if (tcpHdr->dest != tcpAttr->tcp_dst) {
        tcpHdr->check = ChecksumUpdate16(tcpHdr->check, tcpHdr->dest,
                                         tcpAttr->tcp_dst);
        tcpHdr->dest = tcpAttr->tcp_dst;
        key->ipKey.l4.tpDst = tcpAttr->tcp_dst;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateAddressAndPort --
 *      Updates the source/destination IP and port fields in
 *      ovsFwdCtx.curNbl inline based on the specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateAddressAndPort(OvsForwardingContext *ovsFwdCtx,
                        UINT32 newAddr, UINT16 newPort,
                        BOOLEAN isSource, BOOLEAN isTx)
{
    PUINT8 bufferStart;
    UINT32 hdrSize;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPHdr *ipHdr;
    TCPHdr *tcpHdr = NULL;
    UDPHdr *udpHdr = NULL;
    UINT32 *addrField = NULL;
    UINT16 *portField = NULL;
    UINT16 *checkField = NULL;
    BOOLEAN l4Offload = FALSE;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    UINT16  preNatPseudoChecksum = 0;
    BOOLEAN preservePseudoChecksum = FALSE;

    ASSERT(layers->value != 0);

    if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  layers->isTcp ? sizeof (*tcpHdr) : sizeof (*udpHdr);
    } else {
        hdrSize = layers->l3Offset + sizeof (*ipHdr);
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, hdrSize);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    ipHdr = (IPHdr *)(bufferStart + layers->l3Offset);

    if (layers->isTcp) {
        tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);
    } else if (layers->isUdp) {
        udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    }

    csumInfo.Value = NET_BUFFER_LIST_INFO(ovsFwdCtx->curNbl,
                                          TcpIpChecksumNetBufferListInfo);

    /*
     * Adjust the IP header inline as dictated by the action, and also update
     * the IP and the TCP checksum for the data modified.
     *
     * In the future, this could be optimized to make one call to
     * ChecksumUpdate32(). Ignoring this for now, since for the most common
     * case, we only update the TTL.
     */
     /*Only tx direction the checksum value will be reset to be PseudoChecksum*/
    if (!isTx) {
        preNatPseudoChecksum = IPPseudoChecksum(&ipHdr->saddr, &ipHdr->daddr,
            tcpHdr ? IPPROTO_TCP : IPPROTO_UDP,
            ntohs(ipHdr->tot_len) - ipHdr->ihl * 4);
    }

    if (isSource) {
        addrField = &ipHdr->saddr;
        if (tcpHdr) {
            portField = &tcpHdr->source;
            checkField = &tcpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.TcpChecksum :
                        ((BOOLEAN)csumInfo.Receive.TcpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.TcpChecksumFailed);
        } else if (udpHdr) {
            portField = &udpHdr->source;
            checkField = &udpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.UdpChecksum :
                        ((BOOLEAN)csumInfo.Receive.UdpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.UdpChecksumFailed);
        }
        if (!isTx && l4Offload) {
            if (*checkField == preNatPseudoChecksum) {
                preservePseudoChecksum = TRUE;
            }
        }
        if (isTx && l4Offload || preservePseudoChecksum) {
            *checkField = IPPseudoChecksum(&newAddr, &ipHdr->daddr,
                tcpHdr ? IPPROTO_TCP : IPPROTO_UDP,
                ntohs(ipHdr->tot_len) - ipHdr->ihl * 4);
        }
    } else {
        addrField = &ipHdr->daddr;
        if (tcpHdr) {
            portField = &tcpHdr->dest;
            checkField = &tcpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.TcpChecksum :
                        ((BOOLEAN)csumInfo.Receive.TcpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.TcpChecksumFailed);
        } else if (udpHdr) {
            portField = &udpHdr->dest;
            checkField = &udpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.UdpChecksum :
                        ((BOOLEAN)csumInfo.Receive.UdpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.UdpChecksumFailed);
        }
        if (!isTx && l4Offload) {
            if (*checkField == preNatPseudoChecksum) {
                preservePseudoChecksum = TRUE;
            }
        }

        if (isTx && l4Offload || preservePseudoChecksum) {
            *checkField = IPPseudoChecksum(&ipHdr->saddr, &newAddr,
                tcpHdr ? IPPROTO_TCP : IPPROTO_UDP,
                ntohs(ipHdr->tot_len) - ipHdr->ihl * 4);
        }
    }

    if (*addrField != newAddr) {
        UINT32 oldAddr = *addrField;
        if ((checkField && *checkField != 0) &&
            (!l4Offload || (!isTx && !preservePseudoChecksum))) {
            /* Recompute total checksum. */
            *checkField = ChecksumUpdate32(*checkField, oldAddr,
                                            newAddr);
        }
        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate32(ipHdr->check, oldAddr,
                                            newAddr);
        }

        *addrField = newAddr;
    }

    if (portField && *portField != newPort) {
        if ((checkField) &&
            (!l4Offload || (!isTx && !preservePseudoChecksum))) {
            /* Recompute total checksum. */
            *checkField = ChecksumUpdate16(*checkField, *portField,
                                           newPort);
        }
        *portField = newPort;
    }
    return NDIS_STATUS_SUCCESS;
}

UINT16
OvsCalculateICMPv6Checksum(struct in6_addr srcAddr,
                        struct in6_addr dstAddr,
                        uint16_t totalLength,
                        uint16_t protocol,
                        uint16_t *icmpStart,
                        uint16_t length)
{
    uint32_t checkSum = 0;
    uint16_t *srcAddressPtr = (uint16_t *)&srcAddr;
    uint16_t *dstAddressPtr = (uint16_t *)&dstAddr;
    uint16_t *value = (uint16_t *)icmpStart;
    int index = 0;

    checkSum = totalLength + protocol;

    for (int i = 0; i < 8; i++) {
        checkSum += ntohs(srcAddressPtr[i]);
        checkSum += ntohs(dstAddressPtr[i]);
    }

    for (index = length; index > 1; index -= 2) {
        checkSum += ntohs(*value);
        value++;
    }

    if (index > 0) {
        checkSum += (uint16_t)(*((uint8_t *)value));
    }

    while ((checkSum >> 16) & 0xffff) {
        checkSum = (checkSum & 0xffff) + ((checkSum >> 16) & 0xffff);
    }

    return htons(~((uint16_t)checkSum));
}

/*
 *-----------------------------------------------------------------------------
 *
 * OvsUpdateAddressAndPortForIpv6--
 *
 *      Update ipv6 address in ovsFwdCtx.curNbl.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None
 *
 *-----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateAddressAndPortForIpv6(OvsForwardingContext *ovsFwdCtx,
                               struct in6_addr newAddr, UINT16 newPort,
                               BOOLEAN isSource, BOOLEAN isTx)
{
    PUINT8 bufferStart;
    UINT32 hdrSize;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPv6Hdr *ipHdr;
    TCPHdr *tcpHdr = NULL;
    UDPHdr *udpHdr = NULL;
    struct in6_addr *addrField = NULL;
    UINT16 *portField = NULL;
    UINT16 *checkField = NULL;
    BOOLEAN l4Offload = FALSE;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;

    ASSERT(layers->value != 0);

    if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  layers->isTcp ? sizeof (*tcpHdr) : sizeof (*udpHdr);
    } else if (layers->isIcmp) {
        /* The ICMPv6 checksum is recomputed over the L4 payload below, so the
         * whole packet must be contiguous, not just the IPv6 fixed header. */
        hdrSize = NET_BUFFER_DATA_LENGTH(
            NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));
    } else {
        hdrSize = layers->l3Offset + sizeof (*ipHdr);
    }

    csumInfo.Value = NET_BUFFER_LIST_INFO(ovsFwdCtx->curNbl,
                                          TcpIpChecksumNetBufferListInfo);

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, hdrSize);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    ipHdr = (IPv6Hdr *)(bufferStart + layers->l3Offset);

    if (layers->isTcp) {
        tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);
    } else if (layers->isUdp) {
        udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    }

    if (isSource) {
        addrField = &ipHdr->saddr;
        if (tcpHdr) {
            portField = &tcpHdr->source;
            checkField = &tcpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.TcpChecksum :
                        ((BOOLEAN)csumInfo.Receive.TcpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.TcpChecksumFailed);
        } else if (udpHdr) {
            portField = &udpHdr->source;
            checkField = &udpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.UdpChecksum :
                        ((BOOLEAN)csumInfo.Receive.UdpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.UdpChecksumFailed);
        }
        if (isTx && l4Offload) {
            *checkField = IPv6PseudoChecksum((UINT32 *)&newAddr, (UINT32 *)&ipHdr->daddr,
                                             tcpHdr ? IPPROTO_TCP : IPPROTO_UDP,
                                             ntohs(ipHdr->payload_len) -
                                                  (ovsFwdCtx->layers.l4Offset - ovsFwdCtx->layers.l3Offset));
        }
    } else {
        addrField = &ipHdr->daddr;
        if (tcpHdr) {
            portField = &tcpHdr->dest;
            checkField = &tcpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.TcpChecksum :
                        ((BOOLEAN)csumInfo.Receive.TcpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.TcpChecksumFailed);
        } else if (udpHdr) {
            portField = &udpHdr->dest;
            checkField = &udpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.UdpChecksum :
                        ((BOOLEAN)csumInfo.Receive.UdpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.UdpChecksumFailed);
        }

        if (isTx && l4Offload) {
            *checkField = IPv6PseudoChecksum((UINT32 *)&ipHdr->saddr, (UINT32 *)&newAddr,
                                             tcpHdr ? IPPROTO_TCP : IPPROTO_UDP,
                                             ntohs(ipHdr->payload_len) -
                                             (ovsFwdCtx->layers.l4Offset - ovsFwdCtx->layers.l3Offset));
        }
    }

    if (memcmp(addrField, &newAddr, sizeof(struct in6_addr))) {
        if ((checkField && *checkField != 0) && (!l4Offload || !isTx)) {
            uint32_t *oldField = (uint32_t *)addrField;
            uint32_t *newField = (uint32_t *)&newAddr;
            *checkField = ChecksumUpdate32(*checkField, oldField[0], newField[0]);
            *checkField = ChecksumUpdate32(*checkField, oldField[1], newField[1]);
            *checkField = ChecksumUpdate32(*checkField, oldField[2], newField[2]);
            *checkField = ChecksumUpdate32(*checkField, oldField[3], newField[3]);
        }

        *addrField = newAddr;

        if (layers->isIcmp) {
            ICMPHdr *icmp =(ICMPHdr *)(bufferStart + layers->l4Offset);
            /*
             * payload_len counts any IPv6 extension headers that l4Offset
             * already skips; clamp the ICMPv6 span to the captured L4 bytes so
             * the checksum walk cannot read past the contiguous buffer.
             */
            UINT32 captured = NET_BUFFER_DATA_LENGTH(
                NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl)) - layers->l4Offset;
            UINT32 ext = (UINT32)(layers->l4Offset - layers->l3Offset) -
                         (UINT32)sizeof(IPv6Hdr);
            UINT16 icmpLen = (UINT16)MIN((UINT32)ntohs(ipHdr->payload_len) - ext,
                                         captured);
            icmp->checksum = 0x00;
            icmp->checksum = OvsCalculateICMPv6Checksum(ipHdr->saddr,
                                                        ipHdr->daddr, icmpLen,
                                                        IPPROTO_ICMPV6,
                                                        (uint16_t *)icmp,
                                                        icmpLen);
        }
    }

    if (portField && *portField != newPort) {
        if ((checkField) && (!l4Offload || !isTx)) {
            /* Recompute total checksum. */
            *checkField = ChecksumUpdate16(*checkField, *portField,
                                           newPort);
        }
        *portField = newPort;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateIPv4Header --
 *      Updates the IPv4 header in ovsFwdCtx.curNbl inline based on the
 *      specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateIPv4Header(OvsForwardingContext *ovsFwdCtx,
                    OvsFlowKey *key,
                    const struct ovs_key_ipv4 *ipAttr)
{
    PUINT8 bufferStart;
    UINT32 hdrSize;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPHdr *ipHdr;
    TCPHdr *tcpHdr = NULL;
    UDPHdr *udpHdr = NULL;

    ASSERT(layers->value != 0);

    if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  layers->isTcp ? sizeof (*tcpHdr) : sizeof (*udpHdr);
    } else {
        hdrSize = layers->l3Offset + sizeof (*ipHdr);
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, hdrSize);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    ipHdr = (IPHdr *)(bufferStart + layers->l3Offset);

    if (layers->isTcp) {
        tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);
    } else if (layers->isUdp) {
        udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    }

    /*
     * Adjust the IP header inline as dictated by the action, and also update
     * the IP and the TCP checksum for the data modified.
     *
     * In the future, this could be optimized to make one call to
     * ChecksumUpdate32(). Ignoring this for now, since for the most common
     * case, we only update the TTL.
     */
    if (ipHdr->saddr != ipAttr->ipv4_src) {
        if (tcpHdr) {
            tcpHdr->check = ChecksumUpdate32(tcpHdr->check, ipHdr->saddr,
                                             ipAttr->ipv4_src);
        } else if (udpHdr && udpHdr->check) {
            udpHdr->check = ChecksumUpdate32(udpHdr->check, ipHdr->saddr,
                                             ipAttr->ipv4_src);
        }

        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate32(ipHdr->check, ipHdr->saddr,
                                            ipAttr->ipv4_src);
        }
        ipHdr->saddr = ipAttr->ipv4_src;
        key->ipKey.nwSrc = ipAttr->ipv4_src;
    }
    if (ipHdr->daddr != ipAttr->ipv4_dst) {
        if (tcpHdr) {
            tcpHdr->check = ChecksumUpdate32(tcpHdr->check, ipHdr->daddr,
                                             ipAttr->ipv4_dst);
        } else if (udpHdr && udpHdr->check) {
            udpHdr->check = ChecksumUpdate32(udpHdr->check, ipHdr->daddr,
                                             ipAttr->ipv4_dst);
        }

        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate32(ipHdr->check, ipHdr->daddr,
                                            ipAttr->ipv4_dst);
        }
        ipHdr->daddr = ipAttr->ipv4_dst;
        key->ipKey.nwDst = ipAttr->ipv4_dst;
    }
    if (ipHdr->protocol != ipAttr->ipv4_proto) {
        /*
         * ChecksumUpdate16() consumes the host-order read of the 16-bit word a
         * field lives in. The protocol byte is the low byte of the network-order
         * {TTL, protocol} word, i.e. the high byte once read into a host UINT16,
         * so it must be shifted left by 8. The previous '<< 16' masked to zero,
         * making this a no-op that left a stale checksum on any protocol change.
         */
        UINT16 oldProto = (ipHdr->protocol << 8) & 0xff00;
        UINT16 newProto = (ipAttr->ipv4_proto << 8) & 0xff00;
        if (tcpHdr) {
            tcpHdr->check = ChecksumUpdate16(tcpHdr->check, oldProto, newProto);
        } else if (udpHdr && udpHdr->check) {
            udpHdr->check = ChecksumUpdate16(udpHdr->check, oldProto, newProto);
        }

        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate16(ipHdr->check, oldProto, newProto);
        }
        ipHdr->protocol = ipAttr->ipv4_proto;
        key->ipKey.nwProto = ipAttr->ipv4_proto;
    }
    if (ipHdr->ttl != ipAttr->ipv4_ttl) {
        UINT16 oldTtl = (ipHdr->ttl) & 0xff;
        UINT16 newTtl = (ipAttr->ipv4_ttl) & 0xff;
        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate16(ipHdr->check, oldTtl, newTtl);
        }
        ipHdr->ttl = ipAttr->ipv4_ttl;
        key->ipKey.nwTtl = ipAttr->ipv4_ttl;
    }
    if (ipHdr->dscp != (ipAttr->ipv4_tos & 0xfc)) {
        /* ECN + DSCP */
        UINT8 newTos = (ipHdr->tos & 0x3) | (ipAttr->ipv4_tos & 0xfc);
        if (ipHdr->check != 0) {
            /*
             * ToS is the low byte of the network-order {version/IHL, ToS} word,
             * i.e. the high byte of the host-order read ChecksumUpdate16() wants,
             * so shift left by 8. Passing the bare byte updated the wrong word
             * position and produced a bad IP checksum on every DSCP/ECN change.
             */
            ipHdr->check = ChecksumUpdate16(ipHdr->check,
                                            (UINT16)(ipHdr->tos << 8),
                                            (UINT16)(newTos << 8));
        }
        ipHdr->tos = newTos;
        key->ipKey.nwTos = newTos;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateIPv6Header --
 *      Updates the IPv6 header in ovsFwdCtx.curNbl inline based on the
 *      specified key. The source/destination address rewrite (and the L4
 *      pseudo-checksum / ICMPv6 fixup it implies) is delegated to the shared
 *      OvsUpdateAddressAndPortForIpv6 helper; traffic class, flow label and
 *      hop limit are written here. IPv6 has no L3 checksum.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateIPv6Header(OvsForwardingContext *ovsFwdCtx,
                    OvsFlowKey *key,
                    const struct ovs_key_ipv6 *ipv6Attr)
{
    PUINT8 bufferStart;
    UINT32 hdrSize;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPv6Hdr *ipHdr;
    struct in6_addr newSrc, newDst;
    UINT16 curSrcPort = 0, curDstPort = 0;
    UINT32 label;
    UINT8 tc;
    NDIS_STATUS status;

    ASSERT(layers->value != 0);

    if (!layers->isIPv6) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    RtlCopyMemory(&newSrc, ipv6Attr->ipv6_src, sizeof newSrc);
    RtlCopyMemory(&newDst, ipv6Attr->ipv6_dst, sizeof newDst);

    if (layers->isIcmp) {
        /*
         * For ICMPv6 the shared address helper recomputes the checksum over the
         * L4 payload, so the whole packet must be contiguous, not just the L3
         * header.
         */
        hdrSize = NET_BUFFER_DATA_LENGTH(
            NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));
    } else if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  (layers->isTcp ? sizeof(TCPHdr) : sizeof(UDPHdr));
    } else {
        hdrSize = layers->l3Offset + sizeof *ipHdr;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, hdrSize);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    /*
     * The address rewrite leaves L4 ports untouched: read the current ports
     * and pass them back to the shared helper so its port-update branch is a
     * no-op. The address helper does its own contiguity-checked compare and
     * may clone curNbl, so capture everything needed by value here and do not
     * dereference 'bufferStart' across the helper calls.
     */
    if (layers->isTcp) {
        TCPHdr *tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);
        curSrcPort = tcpHdr->source;
        curDstPort = tcpHdr->dest;
    } else if (layers->isUdp) {
        UDPHdr *udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
        curSrcPort = udpHdr->source;
        curDstPort = udpHdr->dest;
    }

    /*
     * The helper no-ops when the address already matches, so the calls are
     * unconditional; this also avoids dereferencing a header pointer that an
     * intervening clone may have invalidated. isTx=FALSE selects the
     * incremental-checksum fixup, which is correct for an address change
     * regardless of TX offload (the address is part of the L4 pseudo-header),
     * matching the conservative set(ipv4) path rather than the NAT fast path.
     */
    status = OvsUpdateAddressAndPortForIpv6(ovsFwdCtx, newSrc, curSrcPort,
                                            TRUE, FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }
    status = OvsUpdateAddressAndPortForIpv6(ovsFwdCtx, newDst, curDstPort,
                                            FALSE, FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    /*
     * The helper may have cloned the NBL to satisfy the contiguity request,
     * so re-acquire the header before writing the remaining fields.
     */
    bufferStart = OvsGetHeaderBySize(ovsFwdCtx,
                                     layers->l3Offset + sizeof *ipHdr);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    ipHdr = (IPv6Hdr *)(bufferStart + layers->l3Offset);

    /*
     * Write traffic class and the 20-bit flow label byte-wise, the inverse of
     * how the extractor reads them (PacketParser.c): the TC high nibble lives
     * in 'priority', its low nibble plus the label's top nibble in flow_lbl[0],
     * and the rest of the label in flow_lbl[1..2]. This avoids any word-cast,
     * alignment or bitfield-layout assumption and leaves 'version' untouched.
     */
    tc = ipv6Attr->ipv6_tclass;
    label = ntohl(ipv6Attr->ipv6_label) & 0x000FFFFF;
    ipHdr->priority = (tc >> 4) & 0x0F;
    ipHdr->flow_lbl[0] = (UINT8)(((tc & 0x0F) << 4) | ((label >> 16) & 0x0F));
    ipHdr->flow_lbl[1] = (UINT8)((label >> 8) & 0xFF);
    ipHdr->flow_lbl[2] = (UINT8)(label & 0xFF);

    ipHdr->hop_limit = ipv6Attr->ipv6_hlimit;

    RtlCopyMemory(&key->ipv6Key.ipv6Src, &ipHdr->saddr, sizeof(struct in6_addr));
    RtlCopyMemory(&key->ipv6Key.ipv6Dst, &ipHdr->daddr, sizeof(struct in6_addr));
    /* The extractor stores the flow label as a host-order 20-bit value. */
    key->ipv6Key.ipv6Label = label;
    key->ipv6Key.nwTos = tc;
    key->ipv6Key.nwTtl = ipv6Attr->ipv6_hlimit;

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateSctpPorts --
 *      Updates the SCTP source/destination port in ovsFwdCtx.curNbl inline.
 *      SCTP carries a CRC32c over the whole transport payload, so the entire
 *      L4 payload is pulled contiguously and the checksum recomputed using the
 *      XOR-delta form that preserves a previously-incorrect checksum.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateSctpPorts(OvsForwardingContext *ovsFwdCtx,
                   OvsFlowKey *key,
                   const struct ovs_key_sctp *sctpAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    SCTPHdr *sctpHdr;
    UINT32 packetLen, payloadLen;

    ASSERT(layers->value != 0);

    if (!layers->isSctp) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    packetLen = NET_BUFFER_DATA_LENGTH(
        NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));
    if (packetLen < (UINT32)layers->l4Offset + sizeof(SCTPHdr)) {
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, packetLen);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    sctpHdr = (SCTPHdr *)(bufferStart + layers->l4Offset);

    /*
     * The CRC32c covers the SCTP segment only. Derive its length from the IP
     * header (like userspace dp_packet_l4_size) so L2 padding on a short frame
     * is not folded into the checksum, then clamp to the captured bytes so a
     * lying IP length cannot walk past the buffer.
     */
    {
        UINT32 captured = packetLen - layers->l4Offset;
        UINT32 ipHdrSpan = (UINT32)(layers->l4Offset - layers->l3Offset);
        UINT32 ipLen;

        if (key->l2.dlType == htons(ETH_TYPE_IPV6)) {
            IPv6Hdr *ip6 = (IPv6Hdr *)(bufferStart + layers->l3Offset);
            ipLen = (UINT32)ntohs(ip6->payload_len) -
                    (ipHdrSpan - (UINT32)sizeof(IPv6Hdr));
        } else {
            IPHdr *ip4 = (IPHdr *)(bufferStart + layers->l3Offset);
            ipLen = (UINT32)ntohs(ip4->tot_len) - ipHdrSpan;
        }
        payloadLen = MIN(ipLen, captured);
    }

    /* A malformed IP length could derive a span shorter than the SCTP header;
     * the CRC32c (and the port writes) need at least the full header. */
    if (payloadLen < sizeof(SCTPHdr)) {
        return NDIS_STATUS_FAILURE;
    }

    if (sctpHdr->source != sctpAttr->sctp_src ||
        sctpHdr->dest != sctpAttr->sctp_dst) {
        ovs_be32 oldCsum, oldCorrectCsum, newCsum;

        oldCsum = sctpHdr->check;
        sctpHdr->check = 0;
        oldCorrectCsum = OvsCrc32c((UINT8 *)sctpHdr, payloadLen);

        sctpHdr->source = sctpAttr->sctp_src;
        sctpHdr->dest = sctpAttr->sctp_dst;

        newCsum = OvsCrc32c((UINT8 *)sctpHdr, payloadLen);
        sctpHdr->check = oldCsum ^ oldCorrectCsum ^ newCsum;

        if (key->l2.dlType == htons(ETH_TYPE_IPV6)) {
            key->ipv6Key.l4.tpSrc = sctpAttr->sctp_src;
            key->ipv6Key.l4.tpDst = sctpAttr->sctp_dst;
        } else {
            key->ipKey.l4.tpSrc = sctpAttr->sctp_src;
            key->ipKey.l4.tpDst = sctpAttr->sctp_dst;
        }
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateArpHeader --
 *      Updates the ARP payload in ovsFwdCtx.curNbl inline based on the
 *      specified key. ARP carries no checksum.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateArpHeader(OvsForwardingContext *ovsFwdCtx,
                   OvsFlowKey *key,
                   const struct ovs_key_arp *arpAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    EtherArp *arpHdr;

    ASSERT(layers->value != 0);

    if (key->l2.dlType != htons(ETH_TYPE_ARP)) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx,
                                     layers->l3Offset + sizeof(EtherArp));
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    arpHdr = (EtherArp *)(bufferStart + layers->l3Offset);

    /* arp_op and ar_op are both network-order be16; the cast is a no-op. */
    arpHdr->ea_hdr.ar_op = (UINT16)arpAttr->arp_op;
    RtlCopyMemory(arpHdr->arp_spa, &arpAttr->arp_sip, sizeof arpHdr->arp_spa);
    RtlCopyMemory(arpHdr->arp_tpa, &arpAttr->arp_tip, sizeof arpHdr->arp_tpa);
    RtlCopyMemory(&arpHdr->arp_sha, arpAttr->arp_sha, sizeof arpHdr->arp_sha);
    RtlCopyMemory(&arpHdr->arp_tha, arpAttr->arp_tha, sizeof arpHdr->arp_tha);

    /*
     * Mirror the flow-key extractor (Flow.c): the opcode is keyed only when it
     * fits in 8 bits, and the addresses only for request/reply -- otherwise the
     * extractor leaves those key fields zero.
     */
    {
        UINT16 op = ntohs(arpAttr->arp_op);
        key->arpKey.nwProto = (op <= 0xff) ? (UINT8)op : 0;
        if (key->arpKey.nwProto == ARPOP_REQUEST ||
            key->arpKey.nwProto == ARPOP_REPLY) {
            key->arpKey.nwSrc = arpAttr->arp_sip;
            key->arpKey.nwDst = arpAttr->arp_tip;
            RtlCopyMemory(key->arpKey.arpSha, arpAttr->arp_sha,
                          sizeof key->arpKey.arpSha);
            RtlCopyMemory(key->arpKey.arpTha, arpAttr->arp_tha,
                          sizeof key->arpKey.arpTha);
        } else {
            key->arpKey.nwSrc = 0;
            key->arpKey.nwDst = 0;
            RtlZeroMemory(key->arpKey.arpSha, sizeof key->arpKey.arpSha);
            RtlZeroMemory(key->arpKey.arpTha, sizeof key->arpKey.arpTha);
        }
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateNdHeader --
 *      Updates the IPv6 neighbor-discovery target and the source/target
 *      link-layer address options in ovsFwdCtx.curNbl inline, then recomputes
 *      the ICMPv6 checksum over the IPv6 pseudo-header and the L4 payload.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateNdHeader(OvsForwardingContext *ovsFwdCtx,
                  OvsFlowKey *key,
                  const struct ovs_key_nd *ndAttr)
{
    PUINT8 bufferStart, l4Start;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPv6Hdr *ipHdr;
    ICMPHdr *icmpHdr;
    struct in6_addr *ndTarget;
    UINT32 packetLen, payloadLen, ofs;

    ASSERT(layers->value != 0);

    /*
     * layers->isIcmp is set for IPv4 ICMP too, so also require IPv6 before
     * reinterpreting the L3 header as IPv6Hdr and writing key->icmp6Key.
     */
    if (!layers->isIcmp || !layers->isIPv6) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    packetLen = NET_BUFFER_DATA_LENGTH(
        NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));
    if (packetLen < (UINT32)layers->l4Offset + sizeof(ICMPHdr) +
                    sizeof(struct in6_addr)) {
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, packetLen);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    ipHdr = (IPv6Hdr *)(bufferStart + layers->l3Offset);
    l4Start = bufferStart + layers->l4Offset;
    icmpHdr = (ICMPHdr *)l4Start;
    ndTarget = (struct in6_addr *)(l4Start + sizeof(ICMPHdr));

    /*
     * The ND target and link-layer options exist only for neighbor
     * solicitation / advertisement with code 0 (mirroring OvsParseIcmpV6); a
     * set(nd) on any other ICMPv6 message would corrupt the payload.
     */
    if (icmpHdr->code != 0 ||
        (icmpHdr->type != ND_NEIGHBOR_SOLICIT &&
         icmpHdr->type != ND_NEIGHBOR_ADVERT)) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    RtlCopyMemory(ndTarget, ndAttr->nd_target, sizeof *ndTarget);
    RtlCopyMemory(&key->icmp6Key.ndTarget, ndAttr->nd_target,
                  sizeof(struct in6_addr));

    /*
     * Walk the ND options updating the source/target link-layer address.
     * Bounds mirror the parser: each option is 'len' 8-byte units; a zero
     * length or one running past the L4 payload is malformed, so fail like
     * OvsParseIcmpV6 rather than forward a half-validated packet.
     */
    payloadLen = packetLen - layers->l4Offset;
    ofs = sizeof(ICMPHdr) + sizeof(struct in6_addr);
    while (ofs + sizeof(IPv6NdOptHdr) <= payloadLen) {
        IPv6NdOptHdr *ndOpt = (IPv6NdOptHdr *)(l4Start + ofs);
        UINT16 optLen = (UINT16)ndOpt->len * 8;

        if (optLen == 0 || ofs + optLen > payloadLen) {
            ovsActionStats.noCopiedNbl++;
            return NDIS_STATUS_FAILURE;
        }

        if (ndOpt->type == ND_OPT_SOURCE_LINKADDR && ndOpt->len == 1) {
            RtlCopyMemory(l4Start + ofs + sizeof(IPv6NdOptHdr),
                          ndAttr->nd_sll, ETH_ADDR_LENGTH);
            RtlCopyMemory(key->icmp6Key.arpSha, ndAttr->nd_sll,
                          ETH_ADDR_LENGTH);
        } else if (ndOpt->type == ND_OPT_TARGET_LINKADDR && ndOpt->len == 1) {
            RtlCopyMemory(l4Start + ofs + sizeof(IPv6NdOptHdr),
                          ndAttr->nd_tll, ETH_ADDR_LENGTH);
            RtlCopyMemory(key->icmp6Key.arpTha, ndAttr->nd_tll,
                          ETH_ADDR_LENGTH);
        }

        ofs += optLen;
    }

    /*
     * The ICMPv6 length is the IPv6 payload minus any extension headers that
     * l4Offset already skips; clamp to the captured L4 bytes so the checksum
     * walk cannot read past the contiguous buffer.
     */
    {
        UINT32 ext = (UINT32)(layers->l4Offset - layers->l3Offset) -
                     (UINT32)sizeof(IPv6Hdr);
        UINT16 csumLen = (UINT16)MIN((UINT32)ntohs(ipHdr->payload_len) - ext,
                                     payloadLen);
        icmpHdr->checksum = 0;
        icmpHdr->checksum = OvsCalculateICMPv6Checksum(ipHdr->saddr,
                                                       ipHdr->daddr, csumLen,
                                                       IPPROTO_ICMPV6,
                                                       (uint16_t *)icmpHdr,
                                                       csumLen);
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateMplsHeader --
 *      Rewrites the MPLS label stack entry adjacent to L3 in ovsFwdCtx.curNbl
 *      inline. The parser advances l3Offset past the whole label stack, so that
 *      LSE sits at l3Offset - MPLS_HLEN; for the single-label stacks in scope it
 *      is the only (hence topmost) label. Multi-label rewrite is out of scope --
 *      locating the outermost label of a deeper stack would need the L2 length,
 *      which is not carried in 'layers'. MPLS carries no checksum.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateMplsHeader(OvsForwardingContext *ovsFwdCtx,
                    OvsFlowKey *key,
                    const struct ovs_key_mpls *mplsAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    MPLSHdr *mplsHdr;

    ASSERT(layers->value != 0);

    /*
     * Guard against a set(mpls) misapplied to a non-MPLS packet (l3Offset would
     * point into L2/L3, not a label) and against l3Offset underflow.
     */
    if (!OvsEthertypeIsMpls(key->l2.dlType) || layers->l3Offset < MPLS_HLEN) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, layers->l3Offset);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    mplsHdr = (MPLSHdr *)(bufferStart + layers->l3Offset - MPLS_HLEN);

    mplsHdr->lse = mplsAttr->mpls_lse;
    key->mplsKey.lse = mplsAttr->mpls_lse;

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteSetAction --
 *      Executes a set() action, but storing the actions into 'ovsFwdCtx'
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteSetAction(OvsForwardingContext *ovsFwdCtx,
                    OvsFlowKey *key,
                    UINT64 *hash,
                    const PNL_ATTR a)
{
    enum ovs_key_attr type = NlAttrType(a);
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    switch (type) {
    case OVS_KEY_ATTR_ETHERNET:
        status = OvsUpdateEthHeader(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_ethernet)));
        break;

    case OVS_KEY_ATTR_IPV4:
        status = OvsUpdateIPv4Header(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_ipv4)));
        break;

    case OVS_KEY_ATTR_IPV6:
        status = OvsUpdateIPv6Header(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_ipv6)));
        break;

    case OVS_KEY_ATTR_TUNNEL:
    {
        OvsIPTunnelKey tunKey = { 0 };
        tunKey.flow_hash = (uint16)(hash ? *hash : OvsHashFlow(key));
        tunKey.dst_port = key->ipKey.l4.tpDst;
        NTSTATUS convertStatus = OvsTunnelAttrToIPTunnelKey((PNL_ATTR)a, &tunKey);
        status = SUCCEEDED(convertStatus) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_FAILURE;
        ASSERT(status == NDIS_STATUS_SUCCESS);
        RtlCopyMemory(&ovsFwdCtx->tunKey, &tunKey, sizeof ovsFwdCtx->tunKey);
        RtlCopyMemory(&key->tunKey, &tunKey, sizeof key->tunKey);
        break;
    }

    case OVS_KEY_ATTR_UDP:
        status = OvsUpdateUdpPorts(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_udp)));
        break;

    case OVS_KEY_ATTR_TCP:
        status = OvsUpdateTcpPorts(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_tcp)));
        break;

    case OVS_KEY_ATTR_SCTP:
        status = OvsUpdateSctpPorts(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_sctp)));
        break;

    case OVS_KEY_ATTR_ARP:
        status = OvsUpdateArpHeader(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_arp)));
        break;

    case OVS_KEY_ATTR_ND:
        status = OvsUpdateNdHeader(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_nd)));
        break;

    case OVS_KEY_ATTR_MPLS:
        /* OVS_KEY_ATTR_MPLS is a variable-length LSE array with no minimum
         * enforced by the install-time validator, so bound it here before the
         * topmost-LSE read. */
        if (NlAttrGetSize(a) < sizeof(struct ovs_key_mpls)) {
            status = NDIS_STATUS_FAILURE;
            break;
        }
        status = OvsUpdateMplsHeader(ovsFwdCtx, key,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_mpls)));
        break;

    default:
        OVS_LOG_INFO("Unhandled attribute %#x", type);
        break;
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteRecirc --
 *     The function adds a deferred action to allow the current packet, nbl,
 *     to re-enter datapath packet processing.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExecuteRecirc(OvsForwardingContext *ovsFwdCtx,
                 OvsFlowKey *key,
                 const PNL_ATTR actions,
                 int rem)
{
    POVS_DEFERRED_ACTION deferredAction = NULL;
    PNET_BUFFER_LIST newNbl = NULL;

    if (!NlAttrIsLast(actions, rem)) {
        /*
         * Recirc action is the not the last action of the action list, so we
         * need to clone the packet.
         */
        newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                   0, 0, TRUE /*copy NBL info*/);
        /*
         * Skip the recirc action when out of memory, but continue on with the
         * rest of the action list.
         */
        if (newNbl == NULL) {
            ovsActionStats.noCopiedNbl++;
            return NDIS_STATUS_SUCCESS;
        }
    }

    if (newNbl) {
        deferredAction = OvsAddDeferredActions(newNbl, key, &(ovsFwdCtx->layers),
                                               NULL);
    } else {
        deferredAction = OvsAddDeferredActions(ovsFwdCtx->curNbl, key,
                                              &(ovsFwdCtx->layers), NULL);
    }

    if (deferredAction) {
        deferredAction->key.recircId = NlAttrGetU32(actions);
    } else {
        if (newNbl) {
            ovsActionStats.deferredActionsQueueFull++;
            OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
        }
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteHash --
 *     The function updates datapath hash read from userspace.
 * --------------------------------------------------------------------------
 */
VOID
OvsExecuteHash(OvsFlowKey *key,
               const PNL_ATTR attr)
{
    struct ovs_action_hash *hash_act = NlAttrData(attr);
    UINT32 hash = 0;

    hash = (UINT32)OvsHashFlow(key);
    hash = OvsJhashWords(&hash, 1, hash_act->hash_basis);
    if (!hash)
        hash = 1;

    key->dpHash = hash;
}

/*
 * --------------------------------------------------------------------------
 * OvsOutputUserspaceAction --
 *      This function sends the packet to userspace according to nested
 *      %OVS_USERSPACE_ATTR_* attributes.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsOutputUserspaceAction(OvsForwardingContext *ovsFwdCtx,
                         OvsFlowKey *key,
                         const PNL_ATTR attr)
{
    NTSTATUS status = NDIS_STATUS_SUCCESS;
    PNL_ATTR userdataAttr;
    PNL_ATTR egrTunAttr = NULL;
    POVS_PACKET_QUEUE_ELEM elem;
    POVS_PACKET_HDR_INFO layers = &ovsFwdCtx->layers;
    BOOLEAN isRecv = FALSE;
    OVS_FWD_INFO fwdInfo;
    OvsIPTunnelKey tunKey;

    /* dispatchLock held by the NDIS ingress path; PREfast cannot track the
     * NDIS RW-lock across the call chain (genuine false positive). */
#pragma warning(suppress: 26110)
    POVS_VPORT_ENTRY vport = OvsFindVportByPortNo(ovsFwdCtx->switchContext,
                                                  ovsFwdCtx->srcVportNo);

    if (vport) {
        if (vport->isExternal ||
            OvsIsTunnelVportType(vport->ovsType)) {
            isRecv = TRUE;
        }
    }

    userdataAttr = NlAttrFindNested(attr, OVS_USERSPACE_ATTR_USERDATA);
    /* Indicate the packet is from egress-tunnel direction */
    egrTunAttr = NlAttrFindNested(attr, OVS_USERSPACE_ATTR_EGRESS_TUN_PORT);

    /* Fill tunnel key to export to usersspace to calculate the template id */
    if (egrTunAttr) {
        RtlZeroMemory(&tunKey,  sizeof tunKey);
        RtlCopyMemory(&tunKey, &ovsFwdCtx->tunKey, sizeof tunKey);
        if (!OvsIphIsZero(&(tunKey.src))) {
            status = OvsLookupIPhFwdInfo(tunKey.src, tunKey.dst, &fwdInfo);
            if (status == NDIS_STATUS_SUCCESS &&
                OvsIphAddrEquals(&(tunKey.dst), &(fwdInfo.dstIphAddr))) {
                OvsCopyIphAddress(&(tunKey.src), &fwdInfo.srcIphAddr);
            }
        }
        tunKey.flow_hash = tunKey.flow_hash ? tunKey.flow_hash : MAXINT16;
    }

    /* OVS_USERSPACE_ATTR_USERDATA is optional, so userdataAttr may be NULL;
     * OvsCreateQueueNlPacket accepts a NULL/zero-length userdata. Do not pass
     * it through NlAttrData/NlAttrGetSize, which would dereference NULL. */
    elem = OvsCreateQueueNlPacket(userdataAttr ? NlAttrData(userdataAttr) : NULL,
                                  userdataAttr ? NlAttrGetSize(userdataAttr) : 0,
                                  OVS_PACKET_CMD_ACTION,
                                  vport, key,
                                  egrTunAttr ? &(tunKey) : NULL,
                                  ovsFwdCtx->curNbl,
                                  NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl),
                                  isRecv,
                                  layers,
                                  ovsFwdCtx->switchContext->dpNo);
    if (elem) {
        LIST_ENTRY missedPackets;
        InitializeListHead(&missedPackets);
        InsertTailList(&missedPackets, &elem->link);
        OvsQueuePackets(&missedPackets, 1);
    } else {
        status = NDIS_STATUS_FAILURE;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteSampleAction --
 *      Executes actions based on probability, as specified in the nested
 *      %OVS_SAMPLE_ATTR_* attributes.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteSampleAction(OvsForwardingContext *ovsFwdCtx,
                       OvsFlowKey *key,
                       const PNL_ATTR attr)
{
    PNET_BUFFER_LIST newNbl = NULL;
    PNL_ATTR actionsList = NULL;
    PNL_ATTR a = NULL;
    INT rem = 0;

    SRand();
    NL_ATTR_FOR_EACH_UNSAFE(a, rem, NlAttrData(attr), NlAttrGetSize(attr)) {
        switch (NlAttrType(a)) {
        case OVS_SAMPLE_ATTR_PROBABILITY:
        {
            UINT32 probability = NlAttrGetU32(a);

            if (!probability || Rand() > probability) {
                return 0;
            }
            break;
        }
        case OVS_SAMPLE_ATTR_ACTIONS:
            actionsList = a;
            break;
        }
    }

    if (actionsList) {
        rem = NlAttrGetSize(actionsList);
        a = (PNL_ATTR)NlAttrData(actionsList);
    }

    if (!rem) {
        /* Actions list is empty, do nothing */
        return STATUS_SUCCESS;
    }

    /*
     * The only known usage of sample action is having a single user-space
     * action. Treat this usage as a special case.
     */
    if (NlAttrType(a) == OVS_ACTION_ATTR_USERSPACE &&
        NlAttrIsLast(a, rem)) {
        return OvsOutputUserspaceAction(ovsFwdCtx, key, a);
    }

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);
    if (newNbl == NULL) {
        /*
         * Skip the sample action when out of memory, but continue on with the
         * rest of the action list.
         */
        ovsActionStats.noCopiedNbl++;
        return STATUS_SUCCESS;
    }

    /*
     * Defer the whole actions-list container (not the first sub-action) so
     * OvsProcessDeferredActions runs every action in the list. The single
     * userspace action is already handled by the fast path above.
     */
    if (!OvsAddDeferredActions(newNbl, key, &(ovsFwdCtx->layers), actionsList)) {
        OVS_LOG_INFO(
            "Deferred actions limit reached, dropping sample action.");
        OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteClone --
 *     Runs the nested CLONE action list on an independent copy of the packet
 *     so the sub-actions cannot affect the packet the outer pipeline keeps.
 *     The copy is handed to the deferred-action queue, like sample/recirc, so
 *     the sub-list executes with bounded recursion depth.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteClone(OvsForwardingContext *ovsFwdCtx,
                OvsFlowKey *key,
                const PNL_ATTR attr)
{
    PNET_BUFFER_LIST newNbl;

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);
    if (newNbl == NULL) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_SUCCESS;
    }

    if (!OvsAddDeferredActions(newNbl, key, &(ovsFwdCtx->layers), attr)) {
        OVS_LOG_INFO("Deferred actions limit reached, dropping clone action.");
        OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteCheckPktLen --
 *     Selects one of two nested action lists by comparing the on-the-wire
 *     (L2) packet length against OVS_CHECK_PKT_LEN_ATTR_PKT_LEN and executes
 *     the selected list on a copy via the deferred-action queue.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteCheckPktLen(OvsForwardingContext *ovsFwdCtx,
                      OvsFlowKey *key,
                      const PNL_ATTR attr)
{
    PNL_ATTR a = NULL;
    INT rem = 0;
    UINT16 pktLen = 0;
    BOOLEAN havePktLen = FALSE;
    PNL_ATTR actionsIfGreater = NULL;
    PNL_ATTR actionsIfLessEqual = NULL;
    PNL_ATTR selected = NULL;
    UINT32 len;
    PNET_BUFFER_LIST newNbl;

    NL_ATTR_FOR_EACH_UNSAFE(a, rem, NlAttrData(attr), NlAttrGetSize(attr)) {
        switch (NlAttrType(a)) {
        case OVS_CHECK_PKT_LEN_ATTR_PKT_LEN:
            pktLen = NlAttrGetU16(a);
            havePktLen = TRUE;
            break;
        case OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER:
            actionsIfGreater = a;
            break;
        case OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL:
            actionsIfLessEqual = a;
            break;
        }
    }

    if (!havePktLen) {
        /*
         * PKT_LEN is mandatory. A missing attribute is a malformed action;
         * fail it rather than defaulting the threshold to 0 and silently
         * taking the 'greater' branch for every non-empty packet.
         */
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    len = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));
    selected = (len > pktLen) ? actionsIfGreater : actionsIfLessEqual;

    if (selected == NULL || NlAttrGetSize(selected) == 0) {
        /* The selected branch is empty: nothing to execute. */
        return NDIS_STATUS_SUCCESS;
    }

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);
    if (newNbl == NULL) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_SUCCESS;
    }

    if (!OvsAddDeferredActions(newNbl, key, &(ovsFwdCtx->layers), selected)) {
        OVS_LOG_INFO(
            "Deferred actions limit reached, dropping check_pkt_len action.");
        OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteDecTtl --
 *     Decrements the IPv4 TTL / IPv6 hop-limit by one with an incremental
 *     checksum fixup (IPv4 only; IPv6 has no L3 checksum). When the value is
 *     already <= 1 the packet must not be forwarded: '*exception' is set TRUE
 *     so the caller runs the embedded OVS_DEC_TTL_ATTR_ACTION list and drops
 *     the packet. A non-IP packet is left unchanged.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteDecTtl(OvsForwardingContext *ovsFwdCtx,
                 OvsFlowKey *key,
                 BOOLEAN *exception)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;

    *exception = FALSE;

    if (key->l2.dlType == htons(ETH_TYPE_IPV4)) {
        IPHdr *ipHdr;
        UINT16 oldTtl, newTtl;

        bufferStart = OvsGetHeaderBySize(ovsFwdCtx,
                                         layers->l3Offset + sizeof(IPHdr));
        if (bufferStart == NULL) {
            return NDIS_STATUS_RESOURCES;
        }
        ipHdr = (IPHdr *)(bufferStart + layers->l3Offset);
        if (ipHdr->ttl <= 1) {
            *exception = TRUE;
            return NDIS_STATUS_SUCCESS;
        }
        /*
         * ChecksumUpdate16() here takes the field value as read from the IP
         * header in place, not the network-order 16-bit word that Linux's
         * csum_replace2() expects -- so pass the raw TTL byte, matching the
         * IPv4 TTL update in OvsUpdateIPv4Header(). Verified against a full
         * header-checksum recompute that the bare byte (not 'ttl << 8') is the
         * correct delta for this routine.
         */
        oldTtl = ipHdr->ttl & 0xff;
        ipHdr->ttl--;
        newTtl = ipHdr->ttl & 0xff;
        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate16(ipHdr->check, oldTtl, newTtl);
        }
        key->ipKey.nwTtl = ipHdr->ttl;
    } else if (key->l2.dlType == htons(ETH_TYPE_IPV6)) {
        IPv6Hdr *ipv6Hdr;

        bufferStart = OvsGetHeaderBySize(ovsFwdCtx,
                                         layers->l3Offset + sizeof(IPv6Hdr));
        if (bufferStart == NULL) {
            return NDIS_STATUS_RESOURCES;
        }
        ipv6Hdr = (IPv6Hdr *)(bufferStart + layers->l3Offset);
        if (ipv6Hdr->hop_limit <= 1) {
            *exception = TRUE;
            return NDIS_STATUS_SUCCESS;
        }
        ipv6Hdr->hop_limit--;
        key->ipv6Key.nwTtl = ipv6Hdr->hop_limit;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoExecuteActions --
 *     Interpret and execute the specified 'actions' on the specified packet
 *     'curNbl'. The expectation is that if the packet needs to be dropped
 *     (completed) for some reason, it is added to 'completionList' so that the
 *     caller can complete the packet. If 'completionList' is NULL, the NBL is
 *     assumed to be generated by OVS and freed up. Otherwise, the function
 *     consumes the NBL by generating a NDIS send indication for the packet.
 *
 *     There are one or more of "clone" NBLs that may get generated while
 *     executing the actions. Upon any failures, the "cloned" NBLs are freed up,
 *     and the caller does not have to worry about them.
 *
 *     Success or failure is returned based on whether the specified actions
 *     were executed successfully on the packet or not.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDoExecuteActions(POVS_SWITCH_CONTEXT switchContext,
                    OvsCompletionList *completionList,
                    PNET_BUFFER_LIST curNbl,
                    UINT32 portNo,
                    ULONG sendFlags,
                    OvsFlowKey *key,
                    UINT64 *hash,
                    OVS_PACKET_HDR_INFO *layers,
                    const PNL_ATTR actions,
                    INT actionsLen)
{
    PNL_ATTR a;
    INT rem;
    UINT32 dstPortID;
    OvsForwardingContext ovsFwdCtx;
    PCWSTR dropReason = L"";
    NDIS_STATUS status;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail =
        NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);

    /* XXX: ASSERT that the flow table lock is held. */
    status = OvsInitForwardingCtx(&ovsFwdCtx, switchContext, curNbl, portNo,
                                  sendFlags, fwdDetail, completionList,
                                  layers, TRUE);
    if (status != NDIS_STATUS_SUCCESS) {
        dropReason = L"OVS-initing destination port list failed";
        goto dropit;
    }

    if (actionsLen == 0) {
        dropReason = L"OVS-Dropped due to Flow action";
        ovsActionStats.zeroActionLen++;
        goto dropit;
    }

    NL_ATTR_FOR_EACH_UNSAFE (a, rem, actions, actionsLen) {
        switch(NlAttrType(a)) {
        case OVS_ACTION_ATTR_OUTPUT:
            dstPortID = NlAttrGetU32(a);
            status = OvsAddPorts(&ovsFwdCtx, key, dstPortID,
                                              TRUE, TRUE);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-adding destination port failed";
                goto dropit;
            }
            break;

        case OVS_ACTION_ATTR_PUSH_VLAN:
        {
            struct ovs_action_push_vlan *vlan;
            PVOID vlanTagValue;
            PNDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag;

            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            vlanTagValue = NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                                Ieee8021QNetBufferListInfo);
            if (vlanTagValue != NULL) {
                /*
                 * XXX: We don't support double VLAN tag offload. In such cases,
                 * we need to insert the existing one into the packet buffer,
                 * and add the new one as offload. This will take care of
                 * guest tag-in-tag case as well as OVS rules that specify
                 * tag-in-tag.
                 */
            } else {
                 vlanTagValue = 0;
                 vlanTag = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(PVOID *)&vlanTagValue;
                 vlan = (struct ovs_action_push_vlan *)NlAttrGet((const PNL_ATTR)a);
                 vlanTag->TagHeader.VlanId = ntohs(vlan->vlan_tci) & 0xfff;
                 vlanTag->TagHeader.UserPriority = ntohs(vlan->vlan_tci) >> 13;
                 vlanTag->TagHeader.CanonicalFormatId = (ntohs(vlan->vlan_tci) >> 12) & 0x1;

                 NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                      Ieee8021QNetBufferListInfo) = vlanTagValue;
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            if (NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                     Ieee8021QNetBufferListInfo) != 0) {
                NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                     Ieee8021QNetBufferListInfo) = 0;
            } else {
                /*
                 * The VLAN tag is inserted into the packet buffer. Pop the tag
                 * by packet buffer modification.
                 */
                status = OvsPopVlanInPktBuf(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    OVS_LOG_ERROR("OVS-pop vlan action failed status = %lu", status);
                    dropReason = L"OVS-pop vlan action failed";
                    goto dropit;
                }
            }
            /* Reset vlan header info in flowkey. */
            key->l2.vlanKey.vlanTci = 0;
            key->l2.vlanKey.vlanTpid = 0;
            break;
        }

        case OVS_ACTION_ATTR_PUSH_MPLS:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsActionMplsPush(&ovsFwdCtx,
                                       (struct ovs_action_push_mpls *)NlAttrGet
                                       ((const PNL_ATTR)a));
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-push MPLS action failed";
                goto dropit;
            }
            layers->l3Offset += MPLS_HLEN;
            layers->l4Offset += MPLS_HLEN;
            break;
        }

        case OVS_ACTION_ATTR_POP_MPLS:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsActionMplsPop(&ovsFwdCtx, NlAttrGetBe16(a));
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-pop MPLS action failed";
                goto dropit;
            }
            layers->l3Offset -= MPLS_HLEN;
            layers->l4Offset -= MPLS_HLEN;
            break;
        }

        case OVS_ACTION_ATTR_HASH:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            OvsExecuteHash(key, (const PNL_ATTR)a);
            break;
        }

        case OVS_ACTION_ATTR_CT:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0
                || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            PNET_BUFFER_LIST oldNbl = ovsFwdCtx.curNbl;
            status = OvsExecuteConntrackAction(&ovsFwdCtx, key,
                                               (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                /* Pending NBLs are consumed by Defragmentation. */
                if (status != NDIS_STATUS_PENDING) {
                    OVS_LOG_ERROR("CT Action failed status = %lu", status);
                    dropReason = L"OVS-conntrack action failed";
                } else {
                    /* We added a new pending NBL to be consumed later.
                     * Report to the userspace that the action applied
                     * successfully */
                    status = NDIS_STATUS_SUCCESS;
                }
                goto dropit;
            } else if (oldNbl != ovsFwdCtx.curNbl) {
                /*
                 * OvsIpv4Reassemble/OvsIpv6Reassemble consumes the
                 * original NBL and creates a new one and assigns
                 * it to the curNbl of ovsFwdCtx.
                 */
                OvsInitForwardingCtx(&ovsFwdCtx,
                                     ovsFwdCtx.switchContext,
                                     ovsFwdCtx.curNbl,
                                     ovsFwdCtx.srcVportNo,
                                     ovsFwdCtx.sendFlags,
                                     NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(ovsFwdCtx.curNbl),
                                     ovsFwdCtx.completionList,
                                     &ovsFwdCtx.layers, FALSE);
                key->ipKey.nwFrag = OVS_FRAG_TYPE_NONE;
                key->ipv6Key.nwFrag = OVS_FRAG_TYPE_NONE;
            }
            break;
        }

        case OVS_ACTION_ATTR_CT_CLEAR:
            /*
             * Clears conntrack metadata (incl. OVS_CS_F_TRACKED) from the flow
             * key only. It mutates no packet bytes and no forwarding context,
             * so it needs no OvsOutputBeforeSetAction flush and is correct in
             * any position relative to output actions.
             */
            OvsCtClearFlowKey(key);
            break;

        case OVS_ACTION_ATTR_RECIRC:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsExecuteRecirc(&ovsFwdCtx, key, (const PNL_ATTR)a, rem);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-recirculation action failed";
                goto dropit;
            }

            if (NlAttrIsLast(a, rem)) {
                goto exit;
            }
            break;
        }

        case OVS_ACTION_ATTR_USERSPACE:
        {
            status = OvsOutputUserspaceAction(&ovsFwdCtx, key,
                                              (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-Dropped due to failure to queue to "
                             L"userspace";
                goto dropit;
            }
            dropReason = L"OVS-Completed since packet was copied to "
                         L"userspace";
            break;
        }
        case OVS_ACTION_ATTR_SET:
        {
            OvsIPTunnelKey pre_tunKey = { 0 };
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }
            RtlCopyMemory(&pre_tunKey, &key->tunKey, sizeof key->tunKey);
            status = OvsExecuteSetAction(&ovsFwdCtx, key, hash,
                                         (const PNL_ATTR)NlAttrGet
                                         ((const PNL_ATTR)a));
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-set action failed";
                goto dropit;
            }

            if (!OvsIphIsZero(&(key->tunKey.dst)) &&
                 key->l2.offset != OvsGetFlowIPL2Offset(&key->tunKey)) {
                 key->l2.offset = OvsGetFlowIPL2Offset(&ovsFwdCtx.tunKey);
            }
            if (!OvsIphIsZero(&(pre_tunKey.dst))) {
                 /*if pre_tunkey dst is not null in multiple IPV6 Geneve tunnels case,
                  * for broadcast and multicast packet the flow pipeline will set different
                  * tunnel setting on one flow. In such case, it needs to do layers update.
                  * Elsewise it will meet BSOD issue but in IPV4 tunnel the BSOD will not
                  * have construct case to make it happen.
                  */
                 status = OvsExtractLayers(ovsFwdCtx.curNbl, &ovsFwdCtx.layers);
                 if (status != NDIS_STATUS_SUCCESS) {
                     dropReason = L"OVS-set action ExtractLayers failed";
                     goto dropit;
                 }
            }
            break;
        }
        case OVS_ACTION_ATTR_METER: {
            if (OvsMeterExecute(&ovsFwdCtx, NlAttrGetU32(a))) {
                OVS_LOG_INFO("Drop packet");
                dropReason = L"Ovs-meter exceed max rate";
                goto dropit;
            }

            break;
        }
        case OVS_ACTION_ATTR_SAMPLE:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsExecuteSampleAction(&ovsFwdCtx, key,
                                            (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-sample action failed";
                goto dropit;
            }
            break;
        }
        case OVS_ACTION_ATTR_ADD_MPLS:
        {
            const struct ovs_action_add_mpls *addMpls =
                (const struct ovs_action_add_mpls *)NlAttrGet((const PNL_ATTR)a);
            struct ovs_action_push_mpls pushMpls;

            if (!(addMpls->tun_flags & OVS_MPLS_L3_TUNNEL_FLAG_MASK)) {
                /*
                 * Flag clear inserts the LSE at the very start of the packet --
                 * an L3-only packet with no Ethernet header (mac_len == 0) --
                 * which needs L3-port / packet_type support not present here.
                 * The set flag (handled below) is the common over-Ethernet case
                 * OVN actually emits. Fail closed rather than forward the packet
                 * with the action silently skipped.
                 */
                status = NDIS_STATUS_NOT_SUPPORTED;
                dropReason = L"OVS-add_mpls L3 facet not supported";
                goto dropit;
            }

            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            /*
             * OVS_MPLS_L3_TUNNEL_FLAG_MASK set: insert one LSE at the start of
             * the L3 header, after the existing Ethernet header -- identical to
             * push_mpls. ovs_action_add_mpls carries the same mpls_lse/
             * mpls_ethertype.
             */
            pushMpls.mpls_lse = addMpls->mpls_lse;
            pushMpls.mpls_ethertype = addMpls->mpls_ethertype;
            status = OvsActionMplsPush(&ovsFwdCtx, &pushMpls);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-add MPLS action failed";
                goto dropit;
            }
            layers->l3Offset += MPLS_HLEN;
            layers->l4Offset += MPLS_HLEN;
            break;
        }

        case OVS_ACTION_ATTR_CHECK_PKT_LEN:
            status = OvsExecuteCheckPktLen(&ovsFwdCtx, key, (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-check_pkt_len action failed";
                goto dropit;
            }
            break;

        case OVS_ACTION_ATTR_CLONE:
            status = OvsExecuteClone(&ovsFwdCtx, key, (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-clone action failed";
                goto dropit;
            }
            break;

        case OVS_ACTION_ATTR_DEC_TTL:
        {
            BOOLEAN exception = FALSE;

            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsExecuteDecTtl(&ovsFwdCtx, key, &exception);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-dec_ttl action failed";
                goto dropit;
            }
            if (exception) {
                /*
                 * TTL/hop-limit expired (<= 1): the packet is not forwarded.
                 * Run the whole embedded OVS_DEC_TTL_ATTR_ACTION list (for OVN
                 * a controller/userspace notification) on a copy via the
                 * deferred-action queue -- like clone -- then drop the original
                 * via dropit. This runs the full list (not just a single
                 * userspace action) and balances the copy on every path.
                 */
                PNL_ATTR exList = NlAttrFindNested((const PNL_ATTR)a,
                                                   OVS_DEC_TTL_ATTR_ACTION);
                if (exList && NlAttrGetSize(exList)) {
                    PNET_BUFFER_LIST exNbl =
                        OvsPartialCopyNBL(ovsFwdCtx.switchContext,
                                          ovsFwdCtx.curNbl, 0, 0, TRUE);
                    if (exNbl == NULL) {
                        ovsActionStats.noCopiedNbl++;
                    } else if (!OvsAddDeferredActions(exNbl, key,
                                                      &ovsFwdCtx.layers,
                                                      exList)) {
                        OvsCompleteNBL(ovsFwdCtx.switchContext, exNbl, TRUE);
                    }
                }
                dropReason = L"OVS-dec_ttl ttl expired";
                goto dropit;
            }
            break;
        }

        case OVS_ACTION_ATTR_DROP:
            /*
             * Explicit, reason-carrying drop (the u32 xlate_error is not yet
             * surfaced to userspace). Linux emits outputs eagerly, so any
             * OUTPUT earlier in the same list has already been sent; flush the
             * accumulated destinations here before dropping so a list of
             * output(s) followed by drop behaves the same way.
             */
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }
            ovsActionStats.explicitDrop++;
            dropReason = L"OVS-explicit drop action";
            goto dropit;

        default:
            status = NDIS_STATUS_NOT_SUPPORTED;
            break;
        }
    }

    if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
        || ovsFwdCtx.tunnelRxNic != NULL) {
        status = OvsOutputForwardingCtx(&ovsFwdCtx);
        ASSERT(ovsFwdCtx.curNbl == NULL);
    }

    ASSERT(ovsFwdCtx.destPortsSizeOut == 0);
    ASSERT(ovsFwdCtx.tunnelRxNic == NULL);
    ASSERT(ovsFwdCtx.tunnelTxNic == NULL);

dropit:
    /*
     * If curNbl != NULL, it implies the NBL has not been not freed up so far.
     */
    if (ovsFwdCtx.curNbl) {
        OvsCompleteNBLForwardingCtx(&ovsFwdCtx, dropReason);
    }

exit:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsActionsExecute --
 *     The function interprets and executes the specified 'actions' on the
 *     specified packet 'curNbl'. See 'OvsDoExecuteActions' description for
 *     more details.
 *
 *     Also executes deferred actions added by recirculation or sample
 *     actions.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsActionsExecute(POVS_SWITCH_CONTEXT switchContext,
                  OvsCompletionList *completionList,
                  PNET_BUFFER_LIST curNbl,
                  UINT32 portNo,
                  ULONG sendFlags,
                  OvsFlowKey *key,
                  UINT64 *hash,
                  OVS_PACKET_HDR_INFO *layers,
                  const PNL_ATTR actions,
                  INT actionsLen)
{
    NDIS_STATUS status;

    status = OvsDoExecuteActions(switchContext, completionList, curNbl,
                                 portNo, sendFlags, key, hash, layers,
                                 actions, actionsLen);

    if (status == STATUS_SUCCESS) {
        status = OvsProcessDeferredActions(switchContext, completionList,
                                           portNo, sendFlags);
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoRecirc --
 *     The function processes the packet 'curNbl' that re-entered datapath
 *     packet processing after a recirculation action.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDoRecirc(POVS_SWITCH_CONTEXT switchContext,
            OvsCompletionList *completionList,
            PNET_BUFFER_LIST curNbl,
            OvsFlowKey *key,
            UINT32 srcPortNo,
            OVS_PACKET_HDR_INFO *layers)
{
    NDIS_STATUS status;
    OvsFlow *flow;
    OvsForwardingContext ovsFwdCtx = { 0 };
    UINT64 hash = 0;
    ASSERT(layers);

    OvsInitForwardingCtx(&ovsFwdCtx, switchContext, curNbl,
                         srcPortNo, 0,
                         NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl),
                         completionList, layers, TRUE);
    ASSERT(ovsFwdCtx.switchContext);

    flow = OvsLookupFlow(&ovsFwdCtx.switchContext->datapath, key, &hash, FALSE);
    if (flow) {
        UINT32 level = OvsDeferredActionsLevelGet();

        if (level > DEFERRED_ACTION_EXEC_LEVEL) {
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped due to deferred actions execution level limit \
                  reached");
            ovsActionStats.deferredActionsExecLimit++;
            ovsFwdCtx.curNbl = NULL;
            return NDIS_STATUS_FAILURE;
        }

        OvsFlowUsed(flow, ovsFwdCtx.curNbl, &ovsFwdCtx.layers);
        ovsFwdCtx.switchContext->datapath.hits++;

        OvsDeferredActionsLevelInc();

        status = OvsDoExecuteActions(ovsFwdCtx.switchContext,
                                     ovsFwdCtx.completionList,
                                     ovsFwdCtx.curNbl,
                                     ovsFwdCtx.srcVportNo,
                                     ovsFwdCtx.sendFlags,
                                     key, &hash, &ovsFwdCtx.layers,
                                     flow->actions, flow->actionsLen);
        ovsFwdCtx.curNbl = NULL;

        OvsDeferredActionsLevelDec();
    } else {
        POVS_VPORT_ENTRY vport = NULL;
        LIST_ENTRY missedPackets;
        UINT32 num = 0;

        ovsFwdCtx.switchContext->datapath.misses++;
        InitializeListHead(&missedPackets);
        /* dispatchLock held by the NDIS ingress path; PREfast cannot track the
         * NDIS RW-lock across the call chain (genuine false positive). */
#pragma warning(suppress: 26110)
        vport = OvsFindVportByPortNo(switchContext, srcPortNo);
        if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped due to port removal");
            ovsActionStats.noVport++;
            return NDIS_STATUS_SUCCESS;
        }
        status = OvsCreateAndAddPackets(NULL, 0, OVS_PACKET_CMD_MISS,
                                        vport, key, ovsFwdCtx.curNbl,
                                        OvsIsExternalVportByPortId(switchContext,
                                            vport->portId),
                                        &ovsFwdCtx.layers,
                                        ovsFwdCtx.switchContext,
                                        &missedPackets, &num);
        if (num) {
            OvsQueuePackets(&missedPackets, num);
        }
        if (status == NDIS_STATUS_SUCCESS) {
            /* Complete the packet since it was copied to user buffer. */
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped since packet was copied to userspace");
            ovsActionStats.flowMiss++;
        } else {
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped due to failure to queue to userspace");
            ovsActionStats.failedFlowMiss++;
            status = NDIS_STATUS_FAILURE;
        }
    }

    return status;
}
