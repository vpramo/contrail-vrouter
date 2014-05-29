/*
 * vr_datapath.h
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_DATAPATH_H__
#define __VR_DATAPATH_H__


static inline bool
well_known_mac(unsigned char *dmac)
{
    unsigned char vr_well_known_mac_infix[] = { 0x80, 0xc2 };
    if (!memcmp(&dmac[VR_ETHER_PROTO_MAC_OFF], vr_well_known_mac_infix,
                            VR_ETHER_PROTO_MAC_LEN)) 
        if (!*dmac || (*dmac == 0x1))
            return true;

    return false;
}

unsigned int vr_arp_input(struct vrouter *, unsigned short ,
             struct vr_packet *, struct vr_arp *,
             unsigned short , struct vr_forwarding_md *);
int vr_trap(struct vr_packet *, unsigned short ,
        unsigned short , void *);
unsigned int vr_l3_input(unsigned short , struct vr_packet *,
                              struct vr_forwarding_md *);
int vr_get_eth_proto(struct vr_packet *, unsigned short *);
int vr_trap_well_known_packets(unsigned short , struct vr_packet *,
                            unsigned short , unsigned char *);


#endif //__VR_DATAPATH_H__
