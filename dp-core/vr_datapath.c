/*
 * vr_datapath.c -- data path inside the router
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_bridge.h>
#include <vr_datapath.h>

extern struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int,
                struct vr_route_req *, struct vr_packet *);


static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    if (sarp->arp_spa == sarp->arp_dpa)
        return true;
    return false;
}


static int
vr_arp_request_treatment(struct vr_interface *vif, struct vr_arp *arp,
                                                   struct vr_nexthop **ret_nh)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;

    /*
     * Packet from VM :
     *       - If no source address DROP
     *       - If L3 route exists PROXY
     *       - If no L3 route FLOOD
     *       - If no route DROP
     *       - If GRAT ARP, ideally should be flooded to hosts behind TOR
     *             but dropped as of now
     *
     * Packet from Vhost
     *       - If to Link Local IP PROXY
     *       - else Xconnect including GRAT
     *
     * Packet from Fabric
     *       - If to Vhost IP Proxy
     *       - If grat ARP Trap to Agent and Xconnect
     *       - else DROP
     *
     * Packet from Xen or VGW, PROXY
     */

    /* 
     * still @ l2 level, and hence we can use the mode of the interface
     * to figure out whether we need to xconnect or not. in the xconnect
     * mode, just pass it to the peer so that he can handle the arp requests
     */
    if (vif_mode_xconnect(vif))
        return PKT_ARP_XCONNECT;


    if (vif->vif_type == VIF_TYPE_VIRTUAL && !arp->arp_spa)
        /*
         * some OSes send arp queries with zero SIP before taking ownership
         * of the DIP
         */
        return PKT_ARP_DROP;

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST ||
            vif->vif_type == VIF_TYPE_GATEWAY)
        return PKT_ARP_PROXY;

    if (vif->vif_type == VIF_TYPE_HOST) {
        if (IS_LINK_LOCAL_IP(arp->arp_dpa))
            return PKT_ARP_PROXY;
    }

    if (vr_grat_arp(arp)) {
        if (vif->vif_type == VIF_TYPE_PHYSICAL)
            return PKT_ARP_TRAP_XCONNECT;
        return PKT_ARP_DROP;
    }

    /*
     * following cases are handled below
     * - requests from fabric to vhost IP
     * - requests from fabric to a VM that has an IP in the fabric and
     *   is hosted in this system
     * - requests from vhost to a VM that has an IP in the fabric and
     *   in the same system
     */
    rt.rtr_req.rtr_vrf_id = vif->vif_vrf;
    rt.rtr_req.rtr_prefix = ntohl(arp->arp_dpa);
    rt.rtr_req.rtr_prefix_len = 32;
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_label_flags = 0;

    nh = vr_inet_route_lookup(vif->vif_vrf, &rt, NULL);
    if (!nh || nh->nh_type == NH_DISCARD)
        return PKT_ARP_DROP;

    if (rt.rtr_req.rtr_label_flags & VR_RT_HOSTED_FLAG)
        return PKT_ARP_PROXY;

    if (nh->nh_type == NH_TUNNEL)
        return PKT_ARP_PROXY;

    if ((nh->nh_type == NH_COMPOSITE) &&
            (nh->nh_flags & NH_FLAG_COMPOSITE_EVPN)) {
        if (ret_nh)
            *ret_nh = nh;
        return PKT_ARP_FLOOD;
    }

    if (vif->vif_type == VIF_TYPE_HOST)
        return PKT_ARP_XCONNECT;

    return PKT_ARP_DROP;
}

static int
vr_handle_arp_request(struct vrouter *router, unsigned short vrf,
        struct vr_arp *sarp, struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_packet *cloned_pkt;
    struct vr_interface *vif = pkt->vp_if;
    unsigned short proto = htons(VR_ETH_PROTO_ARP);
    struct vr_eth *eth;
    struct vr_arp *arp;
    unsigned int dpa;
    int arp_result;
    struct vr_nexthop *nh;

    arp_result = vr_arp_request_treatment(vif, sarp, &nh);

    switch (arp_result) {
    case PKT_ARP_PROXY:
        pkt_reset(pkt);

        eth = (struct vr_eth *)pkt_data(pkt);
        memcpy(eth->eth_dmac, sarp->arp_sha, VR_ETHER_ALEN);
        memcpy(eth->eth_smac, vif->vif_mac, VR_ETHER_ALEN);
        memcpy(&eth->eth_proto, &proto, sizeof(proto));

        arp = (struct vr_arp *)pkt_pull_tail(pkt, VR_ETHER_HLEN);

        sarp->arp_op = htons(VR_ARP_OP_REPLY);
        memcpy(sarp->arp_sha, vif->vif_mac, VR_ETHER_ALEN);
        memcpy(sarp->arp_dha, eth->eth_dmac, VR_ETHER_ALEN);
        dpa = sarp->arp_dpa;
        memcpy(&sarp->arp_dpa, &sarp->arp_spa, sizeof(sarp->arp_dpa));
        memcpy(&sarp->arp_spa, &dpa, sizeof(sarp->arp_spa));

        memcpy(arp, sarp, sizeof(*sarp));
        pkt_pull_tail(pkt, sizeof(*arp));

        vif->vif_tx(vif, pkt);
        break;
    case PKT_ARP_XCONNECT:
        vif_xconnect(vif, pkt);
        break;
    case PKT_ARP_TRAP_XCONNECT:
        cloned_pkt = vr_pclone(pkt);
        if (cloned_pkt) {
            vr_preset(cloned_pkt);
            vif_xconnect(vif, cloned_pkt);
        }
        vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
        break;
    case PKT_ARP_FLOOD:
        if (nh) {
            nh_output(vrf, pkt, nh, fmd);
            break;
        }
        /* Fall through */
    case PKT_ARP_DROP:
    default:
        vr_pfree(pkt, VP_DROP_ARP_NOT_ME);
    }

    return 0;
}

/*
 * arp responses from vhostX need to be cross connected. nothing
 * needs to be done for arp responses from VMs, while responses
 * from fabric needs to be Xconnected and sent to agent
 */
static int
vr_handle_arp_reply(struct vrouter *router, unsigned short vrf,
        struct vr_arp *sarp, struct vr_packet *pkt)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vr_packet *cloned_pkt;

    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST)
        return vif_xconnect(vif, pkt);

    if (vif->vif_type != VIF_TYPE_PHYSICAL) {
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return 0;
    }

    cloned_pkt = vr_pclone(pkt);
    if (cloned_pkt) {
        vr_preset(cloned_pkt);
        vif_xconnect(vif, cloned_pkt);
    }

    return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
}

int
vr_get_eth_proto(struct vr_packet *pkt, unsigned short *eproto)
{
    unsigned char *data = pkt_data(pkt);
    unsigned char *eth = data;
    unsigned short eth_proto;
    struct vr_vlan_hdr *vlan;
    unsigned short pull_len;

    pull_len = VR_ETHER_HLEN;
    if (pkt_head_len(pkt) < pull_len)
        return -1;

    eth_proto = ntohs(*(unsigned short *)(eth + VR_ETHER_PROTO_OFF));
    while (eth_proto == VR_ETH_PROTO_VLAN) {
        if (pkt_head_len(pkt) < (pull_len + sizeof(*vlan)))
            return -1;
        vlan = (struct vr_vlan_hdr *)(pkt_data(pkt) + pull_len);
        eth_proto = ntohs(vlan->vlan_proto);
        pull_len += sizeof(*vlan);
    }

    if (eproto)
        *eproto = eth_proto;

    return pull_len;
}

unsigned int
vr_arp_input(struct vrouter *router, unsigned short vrf,
             struct vr_packet *pkt, struct vr_arp *arp_hdr,
             unsigned short vlan_id, struct vr_forwarding_md *fmd)
{
    struct vr_arp sarp;

    /* If we are "L2 Only", lets bridge even ARP packets */
    if (!(pkt->vp_if->vif_flags & VIF_FLAG_L3_ENABLED))
        return vr_l2_input(vrf, pkt, fmd, vlan_id,
                              VR_ETH_PROTO_ARP, (unsigned char *)arp_hdr);

    /* If vlan tagged packet from VM, we bridge it */
    if (pkt->vp_if->vif_type == VIF_TYPE_VIRTUAL &&
                                vlan_id != VLAN_ID_INVALID)
        return vr_l2_input(vrf, pkt, fmd, vlan_id,
                              VR_ETH_PROTO_ARP, (unsigned char *)arp_hdr);

    memcpy(&sarp, arp_hdr, sizeof(struct vr_arp));
    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        vr_handle_arp_request(router, vrf, &sarp, pkt, fmd);
        break;

    case VR_ARP_OP_REPLY:
        vr_handle_arp_reply(router, vrf, &sarp, pkt);
        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
    }

    return 0;
}

int
vr_trap(struct vr_packet *pkt, unsigned short trap_vrf,
        unsigned short trap_reason, void *trap_param)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vrouter *router = vif->vif_router;
    struct agent_send_params params;

    if (router->vr_agent_if && router->vr_agent_if->vif_send) {
        params.trap_vrf = trap_vrf;
        params.trap_reason = trap_reason;
        params.trap_param = trap_param;
        return router->vr_agent_if->vif_send(router->vr_agent_if, pkt,
                        &params);
    } else {
        vr_pfree(pkt, VP_DROP_TRAP_NO_IF);
    }

    return 0;
}


unsigned int
vr_l3_input(unsigned short vrf, struct vr_packet *pkt,
                              struct vr_forwarding_md *fmd)
{
    int reason;
    struct vr_interface *vif = pkt->vp_if;

    pkt_set_network_header(pkt, pkt->vp_data);
    pkt_set_inner_network_header(pkt, pkt->vp_data);
    if (vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj &&
                            (vif->vif_type == VIF_TYPE_VIRTUAL)) {
        if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, VROUTER_OVERLAY_LEN))) {
            vr_pfree(pkt, reason);
            return 0;
        }
    }
    return vr_flow_inet_input(vif->vif_router, vrf, pkt, VR_ETH_PROTO_IP, fmd);
}

int
vr_trap_well_known_packets(unsigned short vrf, struct vr_packet *pkt,
                            unsigned short eth_proto, unsigned char *l3_hdr)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_interface *vif = pkt->vp_if;
    struct vr_ip *iph;
    struct vr_udp *udph;

    if (!(vif->vif_flags & VIF_FLAG_L3_ENABLED)) {
        return -1;
    }

    if (well_known_mac(data)) {
        vr_trap(pkt, vrf,  AGENT_TRAP_L2_PROTOCOLS, NULL);
        return 0;
    }

    if (eth_proto == VR_ETH_PROTO_IP && IS_MAC_BMCAST(data) &&
                          pkt->vp_if->vif_type == VIF_TYPE_VIRTUAL) {
        iph = (struct vr_ip *)(l3_hdr);
        if ((iph->ip_proto == VR_IP_PROTO_UDP) &&
                              vr_ip_transport_header_valid(iph)) {
            udph = (struct vr_udp *)(l3_hdr + iph->ip_hl * 4);
            if (udph->udp_sport == htons(68)) {
                vr_trap(pkt, vrf,  AGENT_TRAP_L3_PROTOCOLS, NULL);
                return 0;
            }

        }
    }

    return -1;
}
