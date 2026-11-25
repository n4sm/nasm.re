---
title: "Unisoc T7250 - Multiple RCE baseband bugs"
published: 2026-11-10
tags: ["linux", "nasm", "pwn", "0day", "poc", "research", "baseband", "unisoc"]
category: "research"
draft: true
description: Multiple 0-days in the Unisoc T7250 chipset
---

# Introduction

I am using `arctic_global_images_OS3.0.13.0.WBVMIXM_16.0`, the firmware image of the [Xiaomi Redmi A7 Pro](https://www.gsmarena.com/xiaomi_redmi_a7_pro-14463.php) which is running a `Unisoc T7250`. The bugs are still present in the latest firmware but the one I reverse is the release from September 2026.

# Reversing

The baseband will read the IP/dns packets from a receive queue and parse them in this function:
```c
int pktdemux_loop()
{
  pkt_iface_t **iface_table; // r5
  int iface_idx; // r4
  pkt_iface_t *iface; // r0
  int (__fastcall *rcv_cb)(int); // r1
  pkt_queue_t *rx_queue; // r7
  int packet_cnt; // r0
  _DWORD *pkt; // r4
  pkt_iface_t *pkt_iface; // r5
  pkt_iface_stats_t *iface_stats; // r6
  iface_type_t iface_type; // r1
  int l2_hdr_ptr; // r1
  __int16 ethertype; // r0
  pkt_type_t pkt_type; // r0 byte-swapped EtherType: 0x0008=IPv4, 0x0608=ARP, 0xDD86=IPv6
  int pkt_plen; // r1
  int trace_type; // r2
  int pkt_prot; // r0


  rx_queue = pktdemux_rx_queue;
  while ( 1 )
  {
    packet_cnt = rx_queue->count;
    if ( packet_cnt == 0 )
      return packet_cnt;
    tcpip_lock(a1: 1u);
    pkt = pkt_queue_pop(q: pktdemux_rx_queue);
    tcpip_unlock(a1: 1u);
    if ( pkt == nullptr )
      return println(a1: aTcpipPktdemuxG);
    pkt_iface = (pkt_iface_t *)pkt[7];
    iface_stats = pkt_iface->stats;
    if ( pkt_is_broadcast_mac(iface: pkt_iface, addr: (unsigned __int16 *)(pkt[1] + 2)) )
      ++iface_stats->rx_broadcast;
    else
      ++iface_stats->rx_unicast;
    if ( iface_stats->state == 2 )
    {
      pkt_free(a1: (unsigned int)pkt);
      ++iface_stats->rx_dropped;
    }
    else
    {
      if ( (pkt_iface->flags & 8) == 0 )
      {
        iface_type = pkt_iface->stats->if_type;
        if ( iface_type != IFACE_TYPE_ETHERNET )
        {
          println(a1: "pktdemux: bad iface type %ld\n", iface_type);
          goto LABEL_25;
        }
        l2_hdr_ptr = pkt[1];
        ethertype = *(unsigned __int8 *)(l2_hdr_ptr + 15) + (*(unsigned __int8 *)(l2_hdr_ptr + 14) << 8);
        *((_WORD *)pkt + 18) = HIBYTE(ethertype) | (unsigned __int16)(ethertype << 8);
        pkt[3] = *(_DWORD *)(pkt[7] + 48) + l2_hdr_ptr + 2;
      }
      pkt_type = *((unsigned __int16 *)pkt + 18);
      switch ( pkt_type )
      {
        case PKT_TYPE_IPV4:
          ip_rcv(a1: pkt);
          goto LABEL_35;
        case PKT_TYPE_ARP:
          arp_rcv(a1: (int)pkt);
          goto LABEL_35;
        case PKT_TYPE_IPV6:
          ip6_rcv(a1: pkt);
LABEL_35:
          tcpip_unlock(a1: 0);
          break;
        default:
          println(a1: "tcpip: pktdemux: bad pkt type 0x%04x\n", __rev16(pkt_type));
          if ( (*((_WORD *)off_8B05906C + 2) & 0x400) != 0 )
            println(a1: "pktdemux: bad pkt type 0x%04x\n", __rev16(*((unsigned __int16 *)pkt + 18)));
          ++pkt_iface->stats->bad_type;
LABEL_25:
          pkt_free(a1: (unsigned int)pkt);
          break;
      }
    }
  }
}
```

We're interested in ipv4 packets, they get passed to `ip_rcv`:
```c
void __fastcall ip_rcv(pkt_buf_t *pkt)
{
  _DWORD *v1; // r6
  int v2; // r0
  _DWORD *v3; // r5
  pkt_buf_t *packet; // r0
  ipv4_hdr_t *ip_hdr; // r4
  unsigned int total_len; // r1
  unsigned int nb_tlen; // r2
  unsigned int v8; // r1
  unsigned int version_ihl; // r0
  int checksum; // r7
  int v11; // r0
  int i; // r4
  pkt_buf_t *pkt_1; // [sp+0h] [bp-4h]

  v1 = off_8B05CAC0;
  ip_hdr = (ipv4_hdr_t *)packet->nb_prot;
  total_len = ip_hdr->total_len;
  if ( ip_hdr->total_len == 0 || ip_hdr->src_addr == -1 )
  {
    ++v3[4];
LABEL_17:
    pkt_free(a1: (unsigned int)packet);
    return;
  }
  nb_tlen = packet->nb_tlen;
  if ( nb_tlen < __rev16(total_len) || packet->nb_plen < 0x14 )
  {
    if ( (*v1 & 0x400) != 0 && (*v1 & 0x200) != 0 )
    {
      println(a1: aIpRcvBadPktLen, *v1 << 21);
      if ( (*(_BYTE *)v1 & 2) != 0 )
        sub_8B07593C(a1: pkt_1);
    }
    ++v3[3];
    pkt_free(a1: (unsigned int)pkt_1);
    println(a1: "tcpip: ip_rcv() - BAD_IP_HEAD(%d): bad pkt len, pkt = %08x\n", v3[3], pkt_1);
    return;
  }
  v8 = __rev16(total_len);
  if ( nb_tlen > v8 && sub_8B095792(pkt: packet, n: nb_tlen - v8) != 0 )
  {
LABEL_31:
    ++v3[3];
    packet = pkt_1;
    goto LABEL_17;
  }
  version_ihl = ip_hdr->version_ihl;
  if ( version_ihl >> 4 == 4 )
  {
    checksum = ip_hdr->checksum;
    ip_hdr->checksum = 0;
    v11 = (unsigned __int16)~sub_8B092CA2(a1: (int)ip_hdr, a2: (2 * version_ihl) & 0x1F);
    if ( checksum == v11 || v11 == 0 && checksum == 0xFFFF )
    {
      ip_hdr->checksum = checksum;
      for ( i = 0; i == 0; i = (unsigned __int8)(i + 1) )
        ip_rcv_phase2(pkt: *(&pkt_1 + i));
      return;
    }
    println(a1: "tcpip: ip_rcv() - BAD_IP_HEAD(%d): bad chksum, pkt %x", v3[3], pkt_1);
    ip_hdr->checksum = checksum;
    if ( (*v1 & 0x400) != 0 && (*v1 & 0x200) != 0 )
    {
      println(a1: aIpRcvBadXsum, *v1 << 21);
      if ( (*(_BYTE *)v1 & 2) != 0 )
        sub_8B07593C(a1: pkt_1);
    }
    goto LABEL_31;
  }
  if ( (*v1 & 0x400) != 0 && (*v1 & 0x200) != 0 )
  {
    println(a1: aIpRcvBadVersio, *v1 << 21);
    if ( (*(_BYTE *)v1 & 2) != 0 )
      sub_8B07593C(a1: pkt_1);
  }
  ++v3[3];
  pkt_free(a1: (unsigned int)pkt_1);
  println(a1: "tcpip: ip_rcv() - BAD_IP_HEAD(%d): bad version num, pkt = %08x\n", v3[3], pkt_1);
}
```

After checking the length of the ip packet and its checksum we end up in `ip_rcv_phase2`:
```c
void __fastcall ip_rcv_phase2(pkt_buf_t *pkt)
{
  _DWORD *v1; // r5
  _DWORD *v2; // r6
  ipv4_hdr_t *ip_hdr; // r4
  pkt_iface_t *iface; // r1
  unsigned int dst_addr; // r0
  unsigned int ipv4_addr0; // r2
  bool v7; // zf
  unsigned int ipv4_addr1; // r7
  unsigned int ipv4_addr2; // r7
  unsigned int ipv4_addr3; // r7
  pkt_buf_t *v11; // r1
  unsigned int v12; // r0
  pkt_iface_t *new_iface; // r7
  unsigned int v14; // r0
  unsigned int v15; // r3
  pkt_buf_t *v16; // r0
  unsigned int mtu; // r3
  int v18; // r1
  int hop; // [sp+8h] [bp-8h] BYREF
  pkt_buf_t *pkta; // [sp+Ch] [bp-4h] BYREF

  pkta = pkt;
  println(a1: "tcpip: ip_rcv_phase2: p->nb_buff=0x%x, p->nb_prot=0x%x", pkt->nb_buff, pkt->nb_prot);
  v1 = off_8B05C7EC;
  v2 = off_8B05C814;
  ip_hdr = (ipv4_hdr_t *)pkta->nb_prot;
  iface = pkta->iface;
  dst_addr = ip_hdr->dst_addr;
  if ( __builtin_bswap32(dst_addr) >> 28 == 14 )
  {
    if ( sub_8B0B6168(a1: dst_addr) == 0 )
    {
      ++v1[4];
      pkt_free(a1: (unsigned int)pkta);
      return;
    }
    goto LABEL_39;
  }
  ipv4_addr0 = iface->ipv4_addr0;
  v7 = dst_addr == ipv4_addr0;
  while ( 1 )
  {
    if ( v7 )
      goto LABEL_39;
    v7 = dst_addr == -1;
    if ( dst_addr != -1 )
    {
      v7 = HIBYTE(dst_addr) == 255;
      if ( HIBYTE(dst_addr) != 255 )
      {
        ipv4_addr1 = iface->ipv4_addr1;
        v7 = dst_addr == ipv4_addr1;
        if ( dst_addr != ipv4_addr1 )
        {
          ipv4_addr2 = iface->ipv4_addr2;
          v7 = dst_addr == ipv4_addr2;
          if ( dst_addr != ipv4_addr2 )
          {
            ipv4_addr3 = iface->ipv4_addr3;
            v7 = dst_addr == ipv4_addr3;
            if ( dst_addr != ipv4_addr3 )
            {
              iface = (pkt_iface_t *)iface->netmask;
              ipv4_addr0 &= ~(unsigned int)iface;
              v7 = ipv4_addr0 == 0;
              if ( ipv4_addr0 != 0 )
                break;
            }
          }
        }
      }
    }
  }
  if ( (*(_DWORD *)off_8B05C814 & 0x400) != 0 && (*(_DWORD *)off_8B05C814 & 0x200) != 0 )
    println(
      a1: "ip_rcv: got pkt not for me; for %u.%u.%u.%u\n",
      (unsigned __int8)dst_addr,
      BYTE1(dst_addr),
      BYTE2(dst_addr),
      HIBYTE(dst_addr));
  if ( *v1 == 2 )
  {
    ++v1[10];
    goto LABEL_36;
  }
  ++v1[5];
  if ( ip_hdr->ttl <= 1u )
  {
    ++v1[10];
    icmp_send_time_exceeded(a1: (int)pkta, a2: 0);
LABEL_36:
    pkt_free(a1: (unsigned int)pkta);
    return;
  }
  v11 = pkta;
  v12 = ip_hdr->dst_addr;
  pkta->addr_cache = v12;
  new_iface = ip_route_lookup(dst: v12, &hop, iface: v11->iface);
  if ( new_iface == nullptr )
  {
LABEL_35:
    ++v1[11];
    goto LABEL_36;
  }
  v14 = ip_hdr->dst_addr;
  if ( v14 != new_iface->ipv4_addr0 && v14 != new_iface->ipv4_addr1 && v14 != pkta->iface->ipv4_addr1 )
  {
    pkta->iface = new_iface;
    daps_ipsec_policy(a1: (int)&pkta);
    if ( pkta == nullptr )
      return;
    if ( pkta->addr_cache != 0
      || (ip_hdr = (ipv4_hdr_t *)pkta->nb_prot,
          v15 = ip_hdr->dst_addr,
          pkta->addr_cache = v15,
          (new_iface = ip_route_lookup(dst: v15, &hop, iface: nullptr)) != nullptr) )
    {
      v16 = pkta;
      mtu = new_iface->mtu;
      if ( new_iface->n_mib->if_type == IFACE_TYPE_ETHERNET )
        v18 = 2;
      else
        v18 = 0;
      if ( new_iface->prot_offset + pkta->nb_tlen > v18 + mtu )
      {
        if ( ((ip_hdr->frag_off << 8) & 0x4000) != 0 )
        {
          println(a1: "tcpip: pkt %x should be fragmentated, pktlen(%d) > mtu(%d)", pkta, pkta->nb_plen, mtu);
          icmp_send_unreachable(
            a1: 4,
            a2: ip_hdr->src_addr,
            a3: pkta->iface->ipv4_addr0,
            a4: (int)pkta,
            a5: 1,
            a6: (int)pkta->iface);
          ++v1[17];
          pkt_free(a1: (unsigned int)pkta);
        }
        else
        {
          --ip_hdr->ttl;
          ip_fragment(a1: v16, a2: hop);
        }
      }
      else
      {
        --ip_hdr->ttl;
        ip_hdr->checksum = 0;
        ip_hdr->checksum = ~(unsigned __int16)sub_8B092CA2(a1: (int)ip_hdr, a2: 10);
        ip2mac(a1: (int *)pkta, a2: hop);
      }
      return;
    }
    goto LABEL_35;
  }
LABEL_39:
  if ( (__rev16(ip_hdr->frag_off) & 0xFFFF3FFF) != 0 )
  {
    if ( (*v2 & 0x400) != 0 && (*v2 & 0x200) != 0 )
    {
      println(
        a1: "ip_rcv: fragment from %u.%u.%u.%u\n",
        (unsigned __int8)ip_hdr->src_addr,
        BYTE1(ip_hdr->src_addr),
        (unsigned __int8)BYTE2(ip_hdr->src_addr),
        HIBYTE(ip_hdr->src_addr));
      sub_8B07593C(a1: pkta);
    }
    ++v1[13];
    ip_reass_input(pkt: pkta);
  }
  else
  {
    ip_demux(pkt: pkta);
  }
}
```

This function is mainly routing the ip packet, eventually re-encapsulating it with ipsec before forwarding it through `ip_fragment`. Then the receive path goes through `ip_demux`:
```c
int __fastcall ip_demux(pkt_buf_t *pkt)
{
  ipv4_hdr_t *ip_hdr; // r4
  pkt_iface_t *pkt_iface; // r1
  ike_port_t natt_delta; // r1
  int v6; // r2
  int v7; // r3
  ip_proto_t ip_proto; // r0
  int err; // r5
  unsigned __int8 *ip_bytes; // r1
  int ihl_bytes; // r0
  ike_port_t src_port; // r0
  pkt_buf_t *new_pkt; // r0
  unsigned int new_ver; // r0
  int ip_ver_ihl; // r1
  ip_mib_t *mib; // r6
  _DWORD *dbg_flags; // r7
  int dbg_mask; // r1
  ip_proto_t proto_sw; // r0
  int handler_ret; // r0
  unsigned int dst_addr; // r0
  pkt_iface_t *rx_iface; // r1
  unsigned int iface_addr3; // r2
  pkt_buf_t *pkta; // [sp+8h] [bp-4h] BYREF

  pkta = pkt;
  ip_hdr = (ipv4_hdr_t *)pkt->nb_prot;
  println(a1: "tcpip: ip_demux: p->nb_prot=0x%x, pip->ip_prot=0x%x", ip_hdr, ip_hdr->proto);
  pkt_iface = pkta->iface;
  if ( pkt_iface != nullptr && pkt_iface->fwd_enable != 0 )
    return TCPIP_RawTx(a1: pkta, a2: (int)&pkt_iface->fwd_ctx, a3: 1, a4: pkt_iface->fwd_arg);
  if ( sub_8B094E26(a1: pkta) == 1 )
  {
    pkt_free(a1: (unsigned int)pkta);
    return 0;
  }
  ip_proto = ip_hdr->proto;
  err = -11;
  if ( ip_proto == IPPROTO_UDP )
  {
    if ( sub_8B094DFE(a1: pkta->nb_prot, a2: pkta->nb_plen) != 0 )
    {
      println(a1: aTcpipIpDemuxCa);
      goto LABEL_24;
    }
    ip_bytes = pkta->nb_prot;
    ihl_bytes = (4 * *ip_bytes) & 0x3F;
    v6 = ip_bytes[ihl_bytes + 1];
    src_port = v6 + (ip_bytes[ihl_bytes] << 8);
    natt_delta = src_port - 4500;
    if ( src_port != IKE_NAT_T_PORT )
      goto LABEL_24;
    if ( ip_hdr->proto == 17 )
      goto LABEL_19;
  }
  else if ( ip_proto != IPPROTO_ESP && ip_proto != IPPROTO_AH )
  {
    goto LABEL_24;
  }
  if ( *(_BYTE *)ipsec_inbound_enable != 0 )
  {
    new_pkt = pkta;
    if ( pkta != nullptr )
      goto LABEL_16;
    return err;
  }
LABEL_19:
  ipsec_inbound(ppkt: &pkta, a2: natt_delta, a3: v6, a4: v7);
  new_pkt = pkta;
  if ( pkta == nullptr )
    return err;
  ip_hdr = (ipv4_hdr_t *)pkta->nb_prot;
LABEL_16:
  v6 = (int)new_pkt;
  if ( new_pkt != pkt )
  {
    new_ver = *new_pkt->nb_prot;
    if ( new_ver >> 4 == 4 )
    {
      *(_WORD *)(v6 + 36) = 8;
      println(a1: "tcpip debug: ipsec decoded ip4/4, %p -> %p", pkt, (const void *)v6);
      return ip_demux(pkt: pkta);
    }
    else if ( new_ver >> 4 == 6 )
    {
      *(_WORD *)(v6 + 36) = -8826;
      println(a1: "tcpip debug: ipsec decoded ip4/6, %p -> %p", pkt, (const void *)v6);
      return ip6_rcv(pkt: pkta);
    }
    else
    {
      println(a1: "tcpip error: ipsec decoded ip4/drop, %p -> %p", pkt, (const void *)v6);
      pkt_free(a1: (unsigned int)pkta);
      return -32;
    }
  }
LABEL_24:
  ip_ver_ihl = ip_hdr->version_ihl;
  mib = ip_mib;
  if ( ip_ver_ihl != 69 && (unsigned int)(ip_ver_ihl - 69) >= 0xB )
  {
    println(a1: "tcpip: ip_demux - bad IP type 0x%x\n", ip_ver_ihl);
    ++mib->ipInHdrErrors;
    pkt_free(a1: (unsigned int)pkta);
    return err;
  }
  dbg_flags = ip_debug_flags;
  pkta->addr_cache = ip_hdr->src_addr;
  dbg_mask = *dbg_flags << 21;
  if ( (*dbg_flags & 0x400) != 0 && (*dbg_flags & 0x200) != 0 )
  {
    println(
      a1: "ip_demux: pkt prot %u from %u.%u.%u.%u\n",
      ip_hdr->proto,
      (unsigned __int8)ip_hdr->src_addr,
      BYTE1(ip_hdr->src_addr),
      (unsigned __int8)BYTE2(ip_hdr->src_addr),
      HIBYTE(ip_hdr->src_addr));
    if ( (*(_BYTE *)dbg_flags & 2) != 0 )
      sub_8B07593C(a1: pkta);
  }
  proto_sw = ip_hdr->proto;
  switch ( proto_sw )
  {
    case IPPROTO_ICMP:
      ++mib->ipInDelivers;
      handler_ret = parse_icmp(a1: pkta, a2: dbg_mask);
      break;
    case IPPROTO_TCP:
      ++mib->ipInDelivers;
      sub_8B07601E(a1: pkta, a2: pkta->iface);
      handler_ret = parse_tcp(a1: (unsigned int)pkta);
      break;
    case IPPROTO_UDP:
      ++mib->ipInDelivers;
      handler_ret = parse_udp(pkt: pkta, a2: dbg_mask, a3: v6, a4: v7);
      break;
    default:
      err = -10;
      ++mib->ipInUnknownProtos;
      println(a1: "tcpip: ip_demux - unknown IP prot %x\n", ip_hdr->proto);
      goto LABEL_35;
  }
  err = handler_ret;
LABEL_35:
  if ( err != -10 )
    return err;
  dst_addr = ip_hdr->dst_addr;
  if ( dst_addr != -1 && __builtin_bswap32(dst_addr) >> 28 != 14 )
  {
    rx_iface = pkta->iface;
    if ( dst_addr != rx_iface->ipv4_addr1 && dst_addr != rx_iface->ipv4_addr2 )
    {
      iface_addr3 = rx_iface->ipv4_addr3;
      if ( dst_addr != iface_addr3 && rx_iface->ipv4_addr0 != iface_addr3 )
      {
        if ( (*dbg_flags & 0x400) != 0 && (*dbg_flags & 0x200) != 0 )
        {
          println(a1: "ip_demux: unhandled prot %u\n", ip_hdr->proto);
          if ( (*(_BYTE *)dbg_flags & 2) != 0 )
            sub_8B07593C(a1: pkta);
        }
        icmp_send_unreachable(
          a1: 2,
          a2: ip_hdr->src_addr,
          a3: ip_hdr->dst_addr,
          a4: (int)pkta,
          a5: 1,
          a6: (int)pkta->iface);
      }
    }
  }
  ++mib->ipInUnknownProtos;
  pkt_free(a1: (unsigned int)pkta);
  return 2;
}
```

This functions is decapsulating the ipsec packets and receives the incoming packets in three different functions: `parse_icmp`, `parse_tcp` and `parse_udp`. Let's dig into `parse_udp`:
```c
// UDP receive/parse. DNS responses are intercepted before PCB dispatch: when
// the UDP source port == 53, dns_response_parse_unchecked is called with the
// destination (client) port and DNS XID; return != 2 means the DNS cache
// consumed the packet, return 2 falls through to normal UDP PCB/socket delivery.
int __fastcall parse_udp(pkt_buf_t *pkt, int a2, int a3, int a4)
{
  udp_mib_t *mib; // r6
  int *ip_hdr_words; // r7
  int ihl_bytes; // r9
  int pullup_ret; // r0
  udp_hdr_t *udp_hdr; // r5
  unsigned int udp_len; // r4
  _BYTE *dbg_flags; // r10
  int udp_csum; // r8
  pkt_buf_t *pkt_pulled; // r0
  unsigned int nb_tlen; // r1
  __int16 v15; // r0
  int csum_calc; // r1
  pkt_buf_t *pkt_pulled2; // r0
  unsigned __int16 *udp_ports; // r5
  int ret; // r4
  BOOL is_multicast; // r8
  udp_pcb_t *pcb; // r4
  unsigned int pcb_remote_addr; // r0
  unsigned int pcb_local_addr; // r1
  int (__fastcall *recv_cb)(pkt_buf_t *, int, void *); // r3
  pkt_iface_t *rx_iface; // r1
  int hdr_copy[4]; // [sp+10h] [bp-6Ch] BYREF
  unsigned int ip_dst; // [sp+20h] [bp-5Ch]
  udp_upcall_t upcall_info; // [sp+54h] [bp-28h] BYREF
  unsigned int ip_src; // [sp+58h] [bp-24h]
  _DWORD pseudo_src_dst[2]; // [sp+64h] [bp-18h] BYREF
  char pseudo_zero; // [sp+6Ch] [bp-10h]
  char pseudo_proto; // [sp+6Dh] [bp-Fh]
  unsigned __int16 pseudo_len; // [sp+6Eh] [bp-Eh]
  _BYTE mcast_ctx[8]; // [sp+70h] [bp-Ch] BYREF
  pkt_buf_t *pkta; // [sp+78h] [bp-4h] BYREF

  pkta = pkt;
  mib = udp_mib;
  mcast_ctx[0] = 0;
  ip_hdr_words = pkt->nb_prot;
  ihl_bytes = (4 * *ip_hdr_words) & 0x3F;
  if ( pkt->nb_plen < ihl_bytes + 8 )
  {
    pkt_pullup(a1: &pkta, a2: ihl_bytes + 8, a3: 15);
    if ( pullup_ret != 0 )
    {
LABEL_3:
      ++mib->udpInErrors;
      pkt_free(a1: pkta);
      return -32;
    }
    ip_hdr_words = pkta->nb_prot;
  }
  udp_hdr = &ip_hdr_words[*ip_hdr_words & 0xF];
  udp_len = __rev16(udp_hdr->length);
  memcpy_aligned(result: hdr_copy, a2: ip_hdr_words, a3: ihl_bytes + 8, a4);
  dbg_flags = udp_debug_flags;
  if ( pkta->nb_tlen - ihl_bytes < udp_len || udp_len < 8 )
  {
    if ( (*udp_debug_flags & 0x400) != 0 && (*udp_debug_flags & 0x100) != 0 )
      println(a1: "UDP: bad len pkt: rcvd: %u, hdr: %u.\n", pkta->nb_plen, __rev16(udp_hdr->length) + 8);
    goto LABEL_3;
  }
  udp_csum = udp_hdr->checksum;
  if ( udp_hdr->checksum != 0 )
  {
    pseudo_src_dst[0] = pkta->addr_cache;
    pseudo_src_dst[1] = ip_hdr_words[4];
    pseudo_zero = 0;
    pseudo_proto = 17;
    pseudo_len = udp_hdr->length;
    udp_hdr->checksum = inet_checksum(a1: pseudo_src_dst, a2: 6);
  }
  pkt_strip(pkt: pkta, n: ihl_bytes);
  pkta = pkt_pulled;
  if ( pkt_pulled != nullptr )
  {
    nb_tlen = pkt_pulled->nb_tlen;
    if ( nb_tlen > udp_len && pkt_trim(pkt: pkt_pulled, n: nb_tlen - udp_len) != 0 )
      goto LABEL_3;
    println(a1: "tcpip: need check is %d", pkta->cksum_verify);
    if ( pkta->cksum_verify == 1 && udp_csum != 0 )
    {
      pkt_checksum(a1: pkta, a2: 0, a3: 0);
      csum_calc = ~v15;
      if ( v15 == -1 )
        csum_calc = 0xFFFF;
      udp_hdr->checksum = udp_csum;
      if ( csum_calc != udp_csum )
      {
        if ( (*dbg_flags & 0x400) != 0 && (*dbg_flags & 0x100) != 0 )
        {
          println(
            a1: "tcpip: udpdemux - bad xsum %04x right %04x from %u.%u.%u.%u\n",
            udp_csum,
            csum_calc,
            pkta->addr_cache,
            BYTE1(pkta->addr_cache),
            BYTE2(pkta->addr_cache),
            HIBYTE(pkta->addr_cache));
          if ( (*dbg_flags & 2) != 0 )
            ip_dump_packet(result: hdr_copy);
        }
        goto LABEL_3;
      }
      println(a1: "tcpip: checksum is %04x", csum_calc);
    }
    upcall_info.type = 2;
    ip_src = pkta->addr_cache;
    upcall_info.src_port = udp_hdr->src_port;
    pkt_strip(pkt: pkta, n: 8);
    pkta = pkt_pulled2;
    if ( pkt_pulled2 != nullptr )
    {
      udp_ports = (hdr_copy + ihl_bytes);
      udp_ntohs(result: (hdr_copy + ihl_bytes));
      if ( (*dbg_flags & 0x400) != 0 && (*dbg_flags & 0x100) != 0 )
        println(
          a1: "UDP: pkt[%u] from %u.%u.%u.%u:%d to %d\n",
          udp_len,
          pkta->addr_cache,
          BYTE1(pkta->addr_cache),
          BYTE2(pkta->addr_cache),
          HIBYTE(pkta->addr_cache),
          *udp_ports,
          udp_ports[1]);
      // [DNS] response: UDP source port 53 -> parse_dns with &dst_port
      if ( *udp_ports == 53 )
      {
        tcpip_unlock(a1: 0);
        // [DNS] match cache XID + client port; ret==2 falls through to PCB dispatch
        ret = parse_dns(pkt: pkta, client_port_ptr: udp_ports + 1);
        tcpip_lock(a1: 0);
        ++mib->udpInDatagrams;
        if ( ret != 2 )
          goto LABEL_35;
      }
      is_multicast = __builtin_bswap32(ip_dst) >> 28 == 14;
      for ( pcb = *udp_pcb_list; ; pcb = pcb->next )
      {
        if ( pcb == nullptr )
        {
          if ( is_multicast && mcast_ctx[0] != 0 )
            return udp_mcast_deliver(a1: pkta, a2: mcast_ctx[0], a3: &upcall_info);
          if ( ip_dst == -1
            || (rx_iface = pkta->iface, ip_dst == rx_iface->ipv4_addr1)
            || HIBYTE(ip_dst) == 255
            || ip_dst == rx_iface->ipv4_addr2
            || ip_dst == rx_iface->ipv4_addr3
            || __builtin_bswap32(ip_dst) >> 28 == 14 )
          {
            if ( (*dbg_flags & 0x400) != 0 && (*dbg_flags & 0x100) != 0 )
              println(a1: aUdpIgnoringIpB, *dbg_flags << 21);
            ++mib->udpInErrors;
          }
          else
          {
            if ( (*dbg_flags & 0x400) != 0 && (*dbg_flags & 0x100) != 0 )
            {
              println(a1: "UDP: unexpected port %04x\n", udp_ports[1]);
              if ( (*dbg_flags & 2) != 0 )
                ip_dump_packet(result: hdr_copy);
            }
            udp_ntohs(result: udp_ports);
            icmp_send_unreachable(a1: 3, a2: pkta->addr_cache, a3: ip_dst, a4: hdr_copy, a5: 0, a6: pkta->iface);
            ++mib->udpNoPorts;
          }
          pkt_free(a1: pkta);
          return 2;
        }
        if ( pcb->flags << 31 != 0
          && (pcb->local_port == 0 || pcb->local_port == udp_ports[1])
          && (pcb->remote_port == 0 || pcb->remote_port == *udp_ports) )
        {
          pcb_remote_addr = pcb->remote_addr;
          if ( pcb_remote_addr == 0 || pcb_remote_addr == pkta->addr_cache )
          {
            pcb_local_addr = pcb->local_addr;
            if ( pcb_local_addr == 0
              || pcb_local_addr == ip_dst
              || ip_dst == -1
              || ip_dst == pkta->iface->ipv4_addr1
              || __builtin_bswap32(ip_dst) >> 28 == 14 )
            {
              break;
            }
          }
        }
LABEL_51:
        ;
      }
      if ( is_multicast )
      {
        udp_mcast_mark_recipient(a1: pkta, a2: pseudo_src_dst, a3: pcb, a4: mcast_ctx);
        goto LABEL_51;
      }
      ++mib->udpInDatagrams;
      recv_cb = pcb->recv_cb;
      if ( recv_cb != nullptr )
      {
        ret = recv_cb(a1: pkta, a2: pcb->cb_arg, a3: &upcall_info);
        if ( ret == 0 )
          return ret;
      }
      else
      {
        ret = -11;
      }
      ++mib->udpInErrors;
LABEL_35:
      pkt_free(a1: pkta);
      return ret;
    }
  }
  ++mib->udpInErrors;
  return -32;
}
```

This function iterates through `udp_pcb_list` which is referencing the opened sockets and if there is a match `recv_cb` is called to process the packet and send it to the corresponding socket/service. If the source port if 53, meaning that the packet is coming from a DNS server, `parse_dns` is parsing the packet (a dns response), if no matching DNS cache entry is found the packet goes through the normal `udp_pcb_list` loop.

```c
int __fastcall parse_dns(pkt_buf_t *pkt, unsigned __int16 *client_port_ptr)
{
  dns_cache_entry_t *dns_cache; // r4


  dns_cache = (dns_cache_entry_t *)off_8B05A520;
  first_name_offset = 0;
  err_code = DNS_PARSE_OK;
  ns_name_offset = 0;
  ++*((_DWORD *)off_8B05A520 + 4);
  dns_hdr = (dns_hdr_t *)pkt->nb_prot;
  tcpip_lock(a1: 7u);
  println(a1: aTcpipDnsTraceD_14);

  do
  {
    dns_cache = dns_cache->next;
    if ( dns_cache == nullptr )
    {
      tcpip_unlock(a1: 7u);
      return 2;
    }
    println(a1: off_8B05A550[0], dns_cache, dns_cache->name, dns_cache->xid, dns_hdr->id);
  } while ( dns_cache->xid == 0 || dns_cache->xid != dns_hdr->id || dns_cache->client_port != *client_port_ptr );

  println(a1: off_8B05A554, dns_cache);
  ++dns_cache->hit_count;
  if ( dns_cache->rcode != 0 )
  {
    dns_cache->txt_list_ptr = 0;
    dns_cache->txt_count = 0;
    flags_raw = __rev16(dns_hdr->flags);
    rcode = flags_raw & 0xF;
    qdcount = __rev16(dns_hdr->qdcount);
    nscount = __rev16(dns_hdr->nscount);
    ancount = __rev16(dns_hdr->ancount);
    arcount = __rev16(dns_hdr->arcount);
    answer_end = qdcount + ancount;
    authority_end = qdcount + ancount + nscount;
    additional_end = (unsigned __int16)(authority_end + arcount);
    dns_cache->error_status = 0;
    dns_cache->rcode = rcode;
    if ( (flags_raw & 0x8000) != 0 )
    {
      opcode = ((unsigned int)flags_raw >> 11) & 0xF;
      if ( dns_cache->qtype == 30 ) ...
      else ...
    }
    else ...
    println(a1: "tcpip: dns_trace err %d, rcode %d, id=0x%x", err_code, rcode, dns_hdr->id);
    if ( err_code != DNS_PARSE_OK ) ...
    dns_cache->rcode = rcode;
    if ( dns_cache->qtype != 30 )
    {
      if ( rcode != DNS_RCODE_NOERROR ) ...
      dns_cache->field_1D4 = 0;
      dns_cache->a_count = 0;
      label = (dns_sublabel *)&dns_hdr[1];
      LOWORD(offt) = 0;
      dns_cache->aaaa_count = 0;
      memset_zero(dst: dns_cache->aaaa_addr[0], n: 0x50u);
      *(_DWORD *)dns_cache->answer_aaaa = 0;
      rr_next = 0;
      *(_DWORD *)&dns_cache->answer_aaaa[4] = 0;
      *(_DWORD *)&dns_cache->answer_aaaa[8] = 0;
      dns_cache->name_ptr = (unsigned int)dns_cache->name;
      *(_DWORD *)&dns_cache->answer_aaaa[12] = 0;
      while ( 2 )
      {
        rr_index = rr_next;
        if ( rr_next >= additional_end ) ...
        memset_zero(dst: decoded_name, n: 0x100u);
        if ( (unsigned __int8)label->len >> 6 != 3 )
        {
          name_end = dns_decode_name(wire_name: label, out_cur: decoded_name);
          name_len = (_WORD)name_end - (_WORD)label;
          label = (dns_sublabel *)name_end;
          LOWORD(offt) = name_len;
          if ( *name_end == 0 )
            label = (dns_sublabel *)(name_end + 1);
        }
        label_byte = (unsigned __int8)label->len;
        if ( label_byte >> 6 == 3 )
        {
          next = (unsigned __int8)label->sublabel[0];
          label = (dns_sublabel *)((char *)label + 2);
          offt = next + ((label_byte & 0x3F) << 8);
          src_name = (char *)dns_hdr + offt;
          prefix_len = strlen_impl(s: decoded_name);
          dns_decode_name(wire_name: src_name, out_cur: &decoded_name[prefix_len]);
        }
        name_offset = offt;
        rr_cursor = dns_read_be16(p: (unsigned __int8 *)label, &out);
        label = (dns_sublabel *)dns_read_be16(p: rr_cursor, out: &dns_class);
        if ( dns_class != DNS_CLASS_IN )
        {
          err_code = DNS_PARSE_BAD_CLASS;
          goto LABEL_73;
        }
        if ( err_code != DNS_PARSE_OK || rr_index < qdcount ) ...
        offt = __builtin_bswap32(read_le32(p: (unsigned __int8 *)label)) & 0xFFFFFF00
             | (unsigned __int8)label->sublabel[2];
        rdata_ptr = (int *)dns_read_be16(p: (unsigned __int8 *)&label->sublabel[3], out: &rdlength);
        rrtype = (unsigned __int16)out;
        rdata_ptr2 = rdata_ptr;
        if ( out == DNS_TYPE_PTR ) ...
        if ( (unsigned __int16)out <= DNS_TYPE_PTR )
        {
          switch ( out )
          {
            case DNS_TYPE_A:
              goto LABEL_46;
            case DNS_TYPE_NS:
              if ( ns_name_offset == 0 )
                ns_name_offset = (unsigned __int16)((_WORD)rdata_ptr - (_WORD)dns_hdr);
              goto LABEL_72;
            case DNS_TYPE_CNAME:
              v28 = (unsigned __int16)rdlength;
              rrtype2 = DNS_TYPE_CNAME;
              rdata_ptr3 = rdata_ptr;
LABEL_62:
              dns_store(entry: dns_cache, rrtype: rrtype2, rdata: rdata_ptr3, rdlength: v28);
              goto LABEL_72;
            case DNS_TYPE_WKS:
              v28 = 1;
              rdata_ptr3 = rdata_ptr;
              rrtype2 = DNS_TYPE_WKS;
              goto LABEL_62;
            default:
LABEL_72:
              label = (dns_sublabel *)((char *)rdata_ptr2 + (unsigned __int16)rdlength);
LABEL_73:
              rr_next = rr_index + 1;
              continue;
          }
        }
        break;
      }
      switch ( out )
      {
        case DNS_TYPE_TXT:
          v28 = (unsigned __int16)rdlength;
          rrtype2 = DNS_TYPE_TXT;
          rdata_ptr3 = rdata_ptr;
          goto LABEL_62;
        case DNS_TYPE_AAAA:
LABEL_46:
          if ( out == DNS_TYPE_A && rdlength != DNS_RDLEN_A )
          {
            err_code = DNS_PARSE_BAD_A_LEN;
            goto LABEL_72;
          }
          ++*((_DWORD *)off_8B05A520 + 5);
          if ( answer_end <= rr_index ) ...
          if ( first_name_offset == 0 ) ...
          println(a1: "tcpip: dns_trace dnc_set_answer1, offset %d", name_offset);
          dns_store(entry: dns_cache, rrtype: out, rdata: rdata_ptr2, (unsigned __int16)rdlength);
          if ( offt == 0 ) ...
          if ( offt - 1 < 9 ) ...
          break;
        case DNS_TYPE_SRV:
          src_name = (_BYTE *)((char *)rdata_ptr - (char *)dns_hdr + 6);
          srv_record = (char *)dns_cache + 376 * (rr_index - qdcount);
          srv_cursor = dns_read_be16(p: (unsigned __int8 *)rdata_ptr, out: (_WORD *)srv_record + 336);
          srv_cursor2 = dns_read_be16(p: srv_cursor, out: (_WORD *)srv_record + 337);
          srv_cursor3 = dns_read_be16(p: srv_cursor2, out: (_WORD *)srv_record + 338);
          *((_DWORD *)srv_record + 261) = src_name;
          dns_decode_name(wire_name: srv_cursor3, out_cur: srv_record + 788);
          ++dns_cache->additional_count;
          if ( offt == 0 ) ...
          break;
        default:
          goto LABEL_72;
      }
      v35 = 5 * offt;
      offt *= 10;
      if ( offt >= 0x80000000 ) ...
      time_now = sub_8B0574A6(a1: v35);
      dns_cache->expiry = sub_8B0574BC(a1: time_now / 0x64, a2: offt);
      goto LABEL_72;
    }
  }
  tcpip_unlock(a1: 7u);
  return 0;
}
```

## dns_decode_name out-of-bounds write

`parse_dns` first iterates through the dns cache entries looking for a matching id and destination port. What is interesting is the calls to `dns_decode_name`:

```c
char *__fastcall dns_decode_name(dns_sublabel *wire_name, _BYTE *out_cur)
{
  unsigned int label_len; // r5
  char *src_cur; // r4
  _BYTE *label_end; // r6

  label_len = wire_name->len;
  src_cur = &wire_name->len;
  if ( wire_name->len != 0 )
  {
    while ( 1 )
    {
      if ( label_len != 0 )
        memcpy_unaligned(dst: out_cur, src: ++src_cur, n: label_len);
      src_cur += label_len;
      label_end = &out_cur[label_len];
      label_len = *src_cur;
      if ( *src_cur == 0 )
        break;
      *label_end = '.';
      out_cur = label_end + 1;
      if ( *src_cur == 0xC0 )
      {
        println(a1: aTcpipDnsFoundC);           // dns found
        return src_cur;
      }
    }
  }
  return src_cur;
}
```

This is where is happening one of the main vulnerabilitiy, we have full control over `wire_name` and accross the different call-sites, `out_cur` might be a stack or a heap buffer. This function is decoding a domain name, the idea is that the first byte represents the length of the subdomain up to 0xff (the length is encoded on 8 bits) and it will append these subdomains to the decoded buffer, adding a dot between each record. A `0xc0` indicates the end of the name buffer.

It means that we can overflow `out_cur` with the only condition that every 255 (at most) bytes a '.' will be appended. The following name buffer triggers the stack overflow at the very first call of `dns_decode_name`:

```
BF <191 bytes> FF <255 bytes> 00
```

During the first call to `dns_decode_name`, `decoded_name` is passed. It is a 256 bytes stack buffer. Which allows an attacker to easily overflow and reach the saved return address and ROP. The other calls to `dns_decode_name` pass a heap buffer: `srv_record`. So it allows cross-object heap out-of-bounds write as well.

## dns_store out-of-bounds write

There are multiple out-of-bounds write in `dns_store` due to the unchecked `rdlength` argument:

```c
// Stores decoded RR data into a DNS cache entry.
int __fastcall dns_store(dns_cache_entry_t *entry, dns_rrtype_t rrtype, int *rdata, unsigned int rdlength)
{
  dns_store_limits_t wks_count; // r0
  dns_store_limits_t aaaa_count; // r0
  int *src_data; // r1
  dns_addr_len_t copy_len; // r2
  unsigned __int8 *dst_addr; // r0
  char *ptr_name; // r0
  int i; // r5
  unsigned int txt_len; // r6
  _BYTE *txt_buf; // r0
  dns_store_limits_t a_count; // r0

  switch ( rrtype )
  {
    case DNS_TYPE_A:
      a_count = entry->a_count;
      // [DNS] max 5 A addresses per entry
      if ( a_count >= DNS_MAX_ADDR_RECORDS )
        goto LABEL_32;
      entry->a_count = a_count + 1;
      copy_len = DNS_A_ADDR_LEN;
      src_data = rdata;
      dst_addr = &entry->a_addr[a_count];
      return memcpy_unaligned_thunk(a1: dst_addr, a2: src_data, a3: copy_len);
    case DNS_TYPE_WKS:
      wks_count = entry->a_count;
      if ( wks_count < DNS_MAX_ADDR_RECORDS )
      {
        entry->a_count = wks_count + 1;
        memcpy_unaligned(dst: &entry->a_addr[wks_count], src: rdata, n: 4u);
      }
      entry->wks_data = *(rdata + 4);
      goto LABEL_32;
    case DNS_TYPE_PTR:
      ptr_name = entry->ptr_name;
      if ( (rdlength - 1) > 0 )
        // [DNS] UNBOUNDED: rdlength-1 bytes into entry->ptr_name[128], rdlength is packet-controlled
        memcpy_unaligned(dst: ptr_name, src: (rdata + 1), n: rdlength - 1);
      i = 0;
      entry->name[rdlength + 255] = 0;
      while ( strlen_impl(s: entry->ptr_name) - 1 > i )
      {
        if ( entry->ptr_name[i] <= 0x1Fu )
          entry->ptr_name[i] = 46;
        ++i;
      }
      goto LABEL_32;
    case DNS_TYPE_TXT:
      if ( entry->txt_list_ptr == 0 )
      {
        entry->txt_list_ptr = dword_8B059F5C + 132;
        entry->txt_count = 0;
      }
      txt_len = *rdata;
      txt_buf = mem_alloc(a1: txt_len + 1);
      *(entry->txt_list_ptr + 8 * entry->txt_count + 4) = txt_buf;
      if ( txt_len != 0 )
        memcpy_unaligned(dst: txt_buf, src: (rdata + 1), n: txt_len);
      *(entry->txt_list_ptr + 8 * entry->txt_count) = txt_len + 1;
      *(*(entry->txt_list_ptr + 8 * entry->txt_count++ + 4) + txt_len) = 0;
LABEL_32:
      JUMPOUT(0x8B059CD4);
    case DNS_TYPE_AAAA:
      aaaa_count = entry->aaaa_count;
      if ( aaaa_count >= DNS_MAX_ADDR_RECORDS )
        goto LABEL_32;
      entry->aaaa_count = aaaa_count + 1;
      src_data = rdata;
      copy_len = DNS_AAAA_ADDR_LEN;
      dst_addr = entry->aaaa_addr[aaaa_count];
      return memcpy_unaligned_thunk(a1: dst_addr, a2: src_data, a3: copy_len);
    default:
      goto LABEL_32;
  }
}
```

For `DNS_TYPE_PTR` we get a large heap out-of-bounds write which is fully user-controlled. The `strlen_impl` loop replaces the bytes under `0x1F` by dots but we can circumvent this by adding null bytes for the first bytes which will bypass the strlen.

## IMS RTT RTP reorder slot index

The reorder buffer has 24 slots. The slot index is computed as ring_idx + (packet_seq - stored_seq) and normalised with a single if (idx > 23) idx -= 24. A forward delta larger than the ring passes the caller's sequence-window gate, leaves idx > 23, and the slot pointer is written at ctx + 0x3C08 + 4*idx, outside the ring. The payload is then memcpy'd to that pointer.

```c
/* sub_8B043248 — RTT DL_putPkt */
int rtp_reorder_store(rtp_reorder_t *ctx, u32 packet_seq, u16 payload_len, u8 *payload)
{
    u32 slot_idx = ctx->ring_idx;                 /* a1[1] */
    u32 *slot = &ctx->slot[slot_idx];             /* ctx+0x3C08+4*slot_idx */

    if (ctx->stored_seq == slot_idx && *slot == 0)
        ret_seq = ctx->stored_seq;

    u32 window = slot_idx - ctx->stored_seq;
    if (slot_idx < ctx->stored_seq)
        window += 24;

    if (*slot != 0) {
        u16 stored_pkt_seq = *(u16 *)(*slot + 8);
        /* only rejects when stored_seq - new_seq > window (backwards gap). */
        if ((int)(stored_pkt_seq - packet_seq) > window)
            return unlock(ctx);

        u32 base = ctx->ring_idx;
        ret_seq = base + packet_seq - stored_pkt_seq;
        if (stored_pkt_seq < packet_seq) {
            u16 next = (ret_seq < 24) ? ret_seq : ret_seq - 24;
            ctx->ring_idx = next;
        }
    }

    /* BUG: a single subtract cannot normalise a forward delta > 24. */
    if (ret_seq > 23)
        ret_seq -= 24;

    u32 heap_used = ctx->heap_used;               /* ctx+0x3C68 */
    if (heap_used > 0x3BAC)
        heap_used = 0;
    u8 *new_slot = (u8 *)ctx + heap_used + 8;

    /* BUG: slot index not bounded -> ctx+0x3C08+4*ret_seq */
    ctx->slot[ret_seq] = new_slot;
    memset(new_slot, 0, 84);
    *(u16 *)(ctx->slot[ret_seq] + 10) = payload_len;
    *(u16 *)(ctx->slot[ret_seq] + 8)  = packet_seq;
    ...
    memcpy(ctx->slot[ret_seq] + 12, payload, payload_len);
}
```

# EGPRS dbuf append without cap

When a TBF slot already holds a buffer for the same BSN, the EGPRS
receive path merges the new block into it with `memcpy(dst->data + dst->len,
src->data, src->len)` and `dst->len = (u8)(dst->len + src->len)`, with no
`len1 + len2 <= 75` check. Each block is validated individually against the
75-byte per-fragment capacity, but the merged length is not. Two 75-byte
fragments write through `dbuf+157`, overwriting the `+84` pool free-list link
and the next slot; repeated same-BSN appends also wrap the `u8` length.

**Decompiled code (renamed).**

```c
/* rlc_dbuf_append_unchecked(dst, src) — dbuf: data at +0, len at +4 (u8) */
int rlc_dbuf_append_unchecked(dbuf_t *dst, dbuf_t *src) // 0x8bbec978
{
    if (dst == NULL) fatal("dbuf1_ptr_null", 145);
    if (src == NULL) fatal("dbuf2_ptr_null", 146);

    /* BUG: no dst->len + src->len <= 75 check. */
    memcpy(dst->data + dst->len, src->data, src->len);

    dst->len = (u8)(dst->len + src->len);   /* BUG: 8-bit truncation */
    return dst->len;
}
```

```c
/* rlc_egprs_dl_receive_unack / _ack — merge on repeated BSN */
dbuf_t *pending = slots[bsn].dbuf;
if (pending == NULL) {
    ...
} else if (block->type != 2) {
    rlc_dbuf_append_unchecked(pending, block->dbuf);
    ...
} else {
    rlc_dbuf_append_unchecked(block->dbuf, pending);
}
```

# Conclusion

I have reproduced these findings in my emulator rather reliably.

If you have interesting VR projects plz contact me at: `kernelresearch[at]proton.me`.