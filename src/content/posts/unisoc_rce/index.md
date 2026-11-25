---
title: "Unisoc T7250 - Multiple RCE baseband bugs"
published: 2026-11-10
tags: ["linux", "nasm", "pwn", "0day", "poc", "research", "baseband", "unisoc"]
category: "research"
draft: true
description: Multiple 0-days in the Unisoc T7250 chipset
---

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
  ip_hdr_words = (int *)pkt->nb_prot;
  ihl_bytes = (4 * *(unsigned __int8 *)ip_hdr_words) & 0x3F;
  if ( pkt->nb_plen < ihl_bytes + 8 )
  {
    pkt_pullup(a1: (int *)&pkta, a2: ihl_bytes + 8, a3: 15);
    if ( pullup_ret != 0 )
    {
LABEL_3:
      ++mib->udpInErrors;
      pkt_free(a1: (unsigned int)pkta);
      return -32;
    }
    ip_hdr_words = (int *)pkta->nb_prot;
  }
  udp_hdr = (udp_hdr_t *)&ip_hdr_words[*(_BYTE *)ip_hdr_words & 0xF];
  udp_len = __rev16(udp_hdr->length);
  memcpy_aligned(result: hdr_copy, a2: ip_hdr_words, a3: ihl_bytes + 8, a4);
  dbg_flags = udp_debug_flags;
  if ( pkta->nb_tlen - ihl_bytes < udp_len || udp_len < 8 )
  {
    if ( (*(_DWORD *)udp_debug_flags & 0x400) != 0 && (*(_DWORD *)udp_debug_flags & 0x100) != 0 )
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
    udp_hdr->checksum = inet_checksum(a1: (unsigned __int16 *)pseudo_src_dst, a2: 6);
  }
  pkt_strip(pkt: pkta, n: ihl_bytes);
  pkta = pkt_pulled;
  if ( pkt_pulled != nullptr )
  {
    nb_tlen = pkt_pulled->nb_tlen;
    if ( nb_tlen > udp_len && pkt_trim(pkt: pkt_pulled, n: nb_tlen - udp_len) != 0 )
      goto LABEL_3;
    println(a1: "tcpip: need check is %d", (char)pkta->cksum_verify);
    if ( pkta->cksum_verify == 1 && udp_csum != 0 )
    {
      pkt_checksum(a1: pkta, a2: 0, a3: 0);
      csum_calc = (unsigned __int16)~v15;
      if ( v15 == -1 )
        csum_calc = 0xFFFF;
      udp_hdr->checksum = udp_csum;
      if ( csum_calc != udp_csum )
      {
        if ( (*(_DWORD *)dbg_flags & 0x400) != 0 && (*(_DWORD *)dbg_flags & 0x100) != 0 )
        {
          println(
            a1: "tcpip: udpdemux - bad xsum %04x right %04x from %u.%u.%u.%u\n",
            udp_csum,
            csum_calc,
            (unsigned __int8)pkta->addr_cache,
            BYTE1(pkta->addr_cache),
            (unsigned __int8)BYTE2(pkta->addr_cache),
            HIBYTE(pkta->addr_cache));
          if ( (*dbg_flags & 2) != 0 )
            ip_dump_packet(result: (unsigned __int16 *)hdr_copy);
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
      udp_ports = (unsigned __int16 *)((char *)hdr_copy + ihl_bytes);
      udp_ntohs(result: (unsigned __int16 *)((char *)hdr_copy + ihl_bytes));
      if ( (*(_DWORD *)dbg_flags & 0x400) != 0 && (*(_DWORD *)dbg_flags & 0x100) != 0 )
        println(
          a1: "UDP: pkt[%u] from %u.%u.%u.%u:%d to %d\n",
          udp_len,
          (unsigned __int8)pkta->addr_cache,
          BYTE1(pkta->addr_cache),
          (unsigned __int8)BYTE2(pkta->addr_cache),
          HIBYTE(pkta->addr_cache),
          *udp_ports,
          udp_ports[1]);
      if ( *udp_ports == 53 )
      {
        tcpip_unlock(a1: 0);
        ret = dns_response_parse_unchecked(a1: (int)pkta, a2: udp_ports + 1);
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
            return udp_mcast_deliver(a1: (unsigned int)pkta, a2: mcast_ctx[0], a3: &upcall_info);
          if ( ip_dst == -1
            || (rx_iface = pkta->iface, ip_dst == rx_iface->ipv4_addr1)
            || HIBYTE(ip_dst) == 255
            || ip_dst == rx_iface->ipv4_addr2
            || ip_dst == rx_iface->ipv4_addr3
            || __builtin_bswap32(ip_dst) >> 28 == 14 )
          {
            if ( (*(_DWORD *)dbg_flags & 0x400) != 0 && (*(_DWORD *)dbg_flags & 0x100) != 0 )
              println(a1: aUdpIgnoringIpB, *(_DWORD *)dbg_flags << 21);
            ++mib->udpInErrors;
          }
          else
          {
            if ( (*(_DWORD *)dbg_flags & 0x400) != 0 && (*(_DWORD *)dbg_flags & 0x100) != 0 )
            {
              println(a1: "UDP: unexpected port %04x\n", udp_ports[1]);
              if ( (*dbg_flags & 2) != 0 )
                ip_dump_packet(result: (unsigned __int16 *)hdr_copy);
            }
            udp_ntohs(result: udp_ports);
            icmp_send_unreachable(
              a1: 3,
              a2: pkta->addr_cache,
              a3: ip_dst,
              a4: (int)hdr_copy,
              a5: 0,
              a6: (int)pkta->iface);
            ++mib->udpNoPorts;
          }
          pkt_free(a1: (unsigned int)pkta);
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
        udp_mcast_mark_recipient(a1: (int)pkta, a2: (int)pseudo_src_dst, a3: (int)pcb, a4: mcast_ctx);
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
      pkt_free(a1: (unsigned int)pkta);
      return ret;
    }
  }
  ++mib->udpInErrors;
  return -32;
}
```

This function iterates through `udp_pcb_list` which is referencing the opened sockets and if there is a match `recv_cb` is called to process the packet and send it to the corresponding socket/service. If the source port if 53, meaning that the packet is coming from a DNS server, `dns_response_parse_unchecked` is parsing the packet (a dns response), if no matching DNS cache entry is found the packet goes through the normal `udp_pcb_list` loop.

If you have interesting VR projects plz contact me at: `kernelresearch[at]proton.me`.