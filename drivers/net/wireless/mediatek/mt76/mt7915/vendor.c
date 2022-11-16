// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2020, MediaTek Inc. All rights reserved.
 */

#include <net/netlink.h>

#include "mt7915.h"
#include "mcu.h"
#include "vendor.h"

static const struct nla_policy
csi_ctrl_policy[NUM_MTK_VENDOR_ATTRS_CSI_CTRL] = {
	[MTK_VENDOR_ATTR_CSI_CTRL_CFG] = {.type = NLA_NESTED },
	[MTK_VENDOR_ATTR_CSI_CTRL_CFG_MODE] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_CSI_CTRL_CFG_TYPE] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL1] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL2] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_CSI_CTRL_MAC_ADDR] = { .type = NLA_NESTED },
	[MTK_VENDOR_ATTR_CSI_CTRL_INTERVAL] = { .type = NLA_U32 },
	[MTK_VENDOR_ATTR_CSI_CTRL_DUMP_NUM] = { .type = NLA_U16 },
	[MTK_VENDOR_ATTR_CSI_CTRL_DATA] = { .type = NLA_NESTED },
};

static const struct nla_policy
wireless_ctrl_policy[NUM_MTK_VENDOR_ATTRS_WIRELESS_CTRL] = {
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_FIXED_MCS] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_OFDMA] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_PPDU_TX_TYPE] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_NUSERS_OFDMA] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_MIMO] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_BA_BUFFER_SIZE] = {.type = NLA_U16 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_AMPDU] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_AMSDU] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_MU_EDCA] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_CTRL_CERT] = {.type = NLA_U8 },
};

static const struct nla_policy
wireless_dump_policy[NUM_MTK_VENDOR_ATTRS_WIRELESS_DUMP] = {
	[MTK_VENDOR_ATTR_WIRELESS_DUMP_AMPDU] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_WIRELESS_DUMP_AMSDU] = { .type = NLA_U8 },
};

static const struct nla_policy
hemu_ctrl_policy[NUM_MTK_VENDOR_ATTRS_HEMU_CTRL] = {
	[MTK_VENDOR_ATTR_HEMU_CTRL_ONOFF] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_HEMU_CTRL_DUMP] = {.type = NLA_U8 },
};

static const struct nla_policy
three_wire_ctrl_policy[NUM_MTK_VENDOR_ATTRS_3WIRE_CTRL] = {
	[MTK_VENDOR_ATTR_3WIRE_CTRL_MODE] = {.type = NLA_U8 },
};

static const struct nla_policy
rfeature_ctrl_policy[NUM_MTK_VENDOR_ATTRS_RFEATURE_CTRL] = {
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_HE_GI] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_HE_LTF] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE_CFG] = { .type = NLA_NESTED },
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE_EN] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_ACK_PLCY] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TXBF] = { .type = NLA_U8 },
};

static const struct nla_policy
phy_capa_ctrl_policy[NUM_MTK_VENDOR_ATTRS_PHY_CAPA_CTRL] = {
	[MTK_VENDOR_ATTR_PHY_CAPA_CTRL_SET] = { .type = NLA_NESTED },
	[MTK_VENDOR_ATTR_PHY_CAPA_CTRL_DUMP] = { .type = NLA_NESTED },
};

static const struct nla_policy
phy_capa_dump_policy[NUM_MTK_VENDOR_ATTRS_PHY_CAPA_DUMP] = {
	[MTK_VENDOR_ATTR_PHY_CAPA_DUMP_MAX_SUPPORTED_BSS] = { .type = NLA_U16 },
	[MTK_VENDOR_ATTR_PHY_CAPA_DUMP_MAX_SUPPORTED_STA] = { .type = NLA_U16 },
};

static const struct nla_policy
edcca_ctrl_policy[NUM_MTK_VENDOR_ATTRS_EDCCA_CTRL] = {
       [MTK_VENDOR_ATTR_EDCCA_CTRL_MODE] = { .type = NLA_U8 },
       [MTK_VENDOR_ATTR_EDCCA_CTRL_PRI20_VAL] = { .type = NLA_U8 },
       [MTK_VENDOR_ATTR_EDCCA_CTRL_SEC20_VAL] = { .type = NLA_U8 },
       [MTK_VENDOR_ATTR_EDCCA_CTRL_SEC40_VAL] = { .type = NLA_U8 },
       [MTK_VENDOR_ATTR_EDCCA_CTRL_SEC80_VAL] = { .type = NLA_U8 },
       [MTK_VENDOR_ATTR_EDCCA_CTRL_COMPENSATE] = { .type = NLA_S8 },
};

static const struct nla_policy
ibf_ctrl_policy[NUM_MTK_VENDOR_ATTRS_IBF_CTRL] = {
	[MTK_VENDOR_ATTR_IBF_CTRL_ENABLE] = { .type = NLA_U8 },
};

struct csi_null_tone {
	u8 start;
	u8 end;
};

struct csi_reorder{
	u8 dest;
	u8 start;
	u8 end;
};

struct csi_mask {
	struct csi_null_tone null[10];
	u8 pilot[8];
	struct csi_reorder ro[3];
};

static const struct csi_mask csi_mask_groups[] = {
	/* OFDM */
	{ .null = { { 0 }, { 27, 37 } },
	  .ro = { {0, 0, 63} },
	},
	{ .null = { { 0, 69 }, { 96 }, { 123, 127 } },
	  .ro = { { 0, 96 }, { 38, 70, 95 }, { 1, 97, 122 } },
	},
	{ .null = { { 0, 5 }, { 32 }, { 59, 127 } },
	  .ro = { { 0, 32 }, { 38, 6, 31 }, { 1, 33, 58 } },
	},
	{ .null = { { 0, 5 }, { 32 }, { 59, 69 }, { 96 }, { 123, 127 } },
	  .ro = { { 0, 0, 127 } },
	},
	{ .null = { { 0, 133 }, { 160 }, { 187, 255 } },
	  .ro = { { 0, 160 }, { 1, 161, 186 }, { 38, 134, 159 } },
	},
	{ .null = { { 0, 197 }, { 224 }, { 251, 255 } },
	  .ro = { { 0, 224 }, { 1, 225, 250 }, { 38, 198, 223 } },
	},
	{ .null = { { 0, 5 }, { 32 }, { 59, 255 } },
	  .ro = { { 0, 32 }, { 1, 33, 58 }, { 38, 6, 31 } },
	},
	{ .null = { { 0, 69 }, { 96 }, { 123, 255 } },
	  .ro = { { 0, 96 }, { 1, 97, 122 }, { 38, 70, 95 } },
	},
	{ .null = { { 0, 133 }, { 160 }, { 187, 197 }, { 224 }, { 251, 255 } },
	  .ro = { { 0, 192 }, { 2, 198, 250 }, { 74, 134, 186 } },
	},
	{ .null = { { 0, 5 }, { 32 }, { 59, 69 }, { 96 }, { 123, 255 } },
	  .ro = { { 0, 64 }, { 2, 70, 122 }, { 74, 6, 58 } },
	},
	{ .null = { { 0, 5 }, { 32 }, { 59, 69 }, { 96 }, { 123, 133 },
		    { 160 }, { 187, 197 }, { 224 }, { 251, 255 } },
	  .ro = { { 0, 0, 255 } },
	},

	/* HT/VHT */
	{ .null = { { 0 }, { 29, 35 } },
	  .pilot = { 7, 21, 43, 57 },
	  .ro = { { 0, 0, 63 } },
	},
	{ .null = { { 0, 67 }, { 96 }, { 125, 127 } },
	  .pilot = { 75, 89, 103, 117 },
	  .ro = { { 0, 96 }, { 36, 68, 95 }, { 1, 97, 124 } },
	},
	{ .null = { { 0, 3 }, { 32 }, { 61, 127 } },
	  .pilot = { 11, 25, 39, 53 },
	  .ro = { { 0, 32 }, { 36, 4, 31 }, { 1, 33, 60 } },
	},
	{ .null = { { 0, 1 }, { 59, 69 }, { 127 } },
	  .pilot = { 11, 25, 53, 75, 103, 117 },
	  .ro = { { 0, 0, 127 } },
	},
	{ .null = { { 0, 131 }, { 160 }, { 189, 255 } },
	  .pilot = { 139, 153, 167, 181 },
	  .ro = { { 0, 160 }, { 1, 161, 188 }, { 36, 132, 159 } },
	},
	{ .null = { { 0, 195 }, { 224 }, { 253 }, { 255 } },
	  .pilot = { 203, 217, 231, 245 },
	  .ro = { { 0, 224 }, { 1, 225, 252 }, { 36, 196, 223 } },
	},
	{ .null = { { 0, 3 }, { 32 }, { 61, 255 } },
	  .pilot = { 11, 25, 39, 53 },
	  .ro = { { 0, 32 }, { 1, 33, 60 }, { 36, 4, 31 } },
	},
	{ .null = { { 0, 67 }, { 96 }, { 125, 255 } },
	  .pilot = { 75, 89, 103, 117 },
	  .ro = { { 0, 96 }, { 1, 97, 124 }, { 36, 68, 95 } },
	},
	{ .null = { { 0, 133 }, { 191, 193 }, { 251, 255 } },
	  .pilot = { 139, 167, 181, 203, 217, 245 },
	  .ro = { { 0, 192 }, { 2, 194, 250 }, { 70, 134, 190 } },
	},
	{ .null = { { 0, 5 }, { 63, 65 }, { 123, 127 } },
	  .pilot = { 11, 39, 53, 75, 89, 117 },
	  .ro = { { 0, 64 }, { 2, 66, 122 }, { 70, 6, 62 } },
	},
	{ .null = { { 0, 1 }, { 123, 133 }, { 255 } },
	  .pilot = { 11, 39, 75, 103, 153, 181, 217, 245 },
	  .ro = { { 0, 0, 255 } },
	},

	/* HE */
	{ .null = { { 0 }, { 31, 33 } },
	  .pilot = { 12, 29, 35, 52 },
	  .ro = { { 0, 0, 63 } },
	},
	{ .null = { { 30, 34 }, { 96 } },
	  .pilot = { 4, 21, 43, 60, 70, 87, 105, 122 },
	  .ro = { { 0, 96 }, { 34, 66, 95 }, { 1, 97, 126 } },
	},
	{ .null = { { 32 }, { 94, 98 } },
	  .pilot = { 6, 23, 41, 58, 68, 85, 107, 124 },
	  .ro = { { 0, 32 }, { 34, 2, 31 }, { 1, 31, 62 } },
	},
	{ .null = { { 0 }, { 62, 66 } },
	  .pilot = { 9, 26, 36, 53, 75, 92, 102, 119 },
	  .ro = { { 0, 0, 127 } },
	},
	{ .null = { { 30, 34 }, { 160 } },
	  .pilot = { 4, 21, 43, 60, 137, 154, 166, 183 },
	  .ro = { { 0, 160 }, { 1, 161, 190 }, { 34, 130, 159 } },
	},
	{ .null = { { 94, 98 }, { 224 } },
	  .pilot = { 68, 85, 107, 124, 201, 218, 230, 247 },
	  .ro = { { 0, 224 }, { 1, 225, 254 }, { 34, 194, 223 } },
	},
	{ .null = { { 32 }, { 158, 162 } },
	  .pilot = { 9, 26, 38, 55, 132, 149, 171, 188 },
	  .ro = { { 0, 32 }, { 1, 33, 62 }, { 34, 2, 31 } },
	},
	{ .null = { { 96 }, { 222, 226 } },
	  .pilot = { 73, 90, 102, 119, 196, 213, 235, 252 },
	  .ro = { { 0, 96 }, { 1, 97, 126 }, { 34, 66, 95 } },
	},
	{ .null = { { 62, 66 }, { 192 } },
	  .pilot = { 36, 53, 75, 92, 169, 186, 198, 215 },
	  .ro = { { 0, 192 }, { 1, 193, 253 }, { 67, 131, 191 } },
	},
	{ .null = { { 64 }, { 190, 194 } },
	  .pilot = { 41, 58, 70, 87, 164, 181, 203, 220 },
	  .ro = { { 0, 64 }, { 1, 65, 125 }, { 67, 3, 63 } },
	},
	{ .null = { { 0 }, { 126, 130 } },
	  .pilot = { 6, 23, 100, 117, 139, 156, 233, 250 },
	  .ro = { { 0, 0, 255 } },
	},
};

static inline u8 csi_group_idx(u8 mode, u8 ch_bw, u8 data_bw, u8 pri_ch_idx)
{
	if (ch_bw < 2 || data_bw < 1)
		return mode * 11 + ch_bw * ch_bw + pri_ch_idx;
	else
		return mode * 11 + ch_bw * ch_bw + (data_bw + 1) * 2 + pri_ch_idx;
}

static int mt7915_vendor_csi_ctrl(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data,
				  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_CSI_CTRL];
	int err;

	err = nla_parse(tb, MTK_VENDOR_ATTR_CSI_CTRL_MAX, data, data_len,
			csi_ctrl_policy, NULL);
	if (err)
		return err;

	if (tb[MTK_VENDOR_ATTR_CSI_CTRL_CFG]) {
		u8 mode = 0, type = 0, v1 = 0, v2 = 0;
		u8 mac_addr[ETH_ALEN] = {};
		struct nlattr *cur;
		int rem;

		nla_for_each_nested(cur, tb[MTK_VENDOR_ATTR_CSI_CTRL_CFG], rem) {
			switch(nla_type(cur)) {
			case MTK_VENDOR_ATTR_CSI_CTRL_CFG_MODE:
				mode = nla_get_u8(cur);
				break;
			case MTK_VENDOR_ATTR_CSI_CTRL_CFG_TYPE:
				type = nla_get_u8(cur);
				break;
			case MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL1:
				v1 = nla_get_u8(cur);
				break;
			case MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL2:
				v2 = nla_get_u8(cur);
				break;
			default:
				return -EINVAL;
			};
		}

		if (tb[MTK_VENDOR_ATTR_CSI_CTRL_MAC_ADDR]) {
			int idx = 0;

			nla_for_each_nested(cur, tb[MTK_VENDOR_ATTR_CSI_CTRL_MAC_ADDR], rem) {
				mac_addr[idx++] = nla_get_u8(cur);
			}
		}

		mt7915_mcu_set_csi(phy, mode, type, v1, v2, mac_addr);

		spin_lock_bh(&phy->csi.csi_lock);

		phy->csi.enable = !!mode;

		if (mode == 2 && type == 5) {
			if (v1 >= 1)
				phy->csi.mask = 1;
			if (v1 == 2)
				phy->csi.reorder = 1;
		}

		/* clean up old csi stats */
		if ((mode == 0 || mode == 2) && !list_empty(&phy->csi.csi_list)) {
			struct csi_data *c, *tmp_c;

			list_for_each_entry_safe(c, tmp_c, &phy->csi.csi_list,
						 node) {
				list_del(&c->node);
				kfree(c);
				phy->csi.count--;
			}
		} else if (mode == 1) {
			phy->csi.last_record = 0;
		}

		spin_unlock_bh(&phy->csi.csi_lock);
	}

	if (tb[MTK_VENDOR_ATTR_CSI_CTRL_INTERVAL])
		phy->csi.interval = nla_get_u32(tb[MTK_VENDOR_ATTR_CSI_CTRL_INTERVAL]);

	return 0;
}

static void
mt7915_vendor_csi_tone_mask(struct mt7915_phy *phy, struct csi_data *csi)
{
	static const u8 mode_map[] = {
		[MT_PHY_TYPE_OFDM] = 0,
		[MT_PHY_TYPE_HT] = 1,
		[MT_PHY_TYPE_VHT] = 1,
		[MT_PHY_TYPE_HE_SU] = 2,
	};
	const struct csi_mask *cmask;
	int i;

	if (csi->rx_mode == MT_PHY_TYPE_CCK || !phy->csi.mask)
		return;

	if (csi->data_bw == IEEE80211_STA_RX_BW_40)
		csi->pri_ch_idx /= 2;

	cmask = &csi_mask_groups[csi_group_idx(mode_map[csi->rx_mode],
					       csi->ch_bw,
					       csi->data_bw,
					       csi->pri_ch_idx)];

	for (i = 0; i < 10; i++) {
		const struct csi_null_tone *ntone = &cmask->null[i];
		u8 start = ntone->start;
		u8 end = ntone->end;
		int j;

		if (!start && !end && i > 0)
			break;

		if (!end)
			end = start;

		for (j = start; j <= end; j++) {
			csi->data_i[j] = 0;
			csi->data_q[j] = 0;
		}
	}

	for (i = 0; i < 8; i++) {
		u8 pilot = cmask->pilot[i];

		if (!pilot)
			break;

		csi->data_i[pilot] = 0;
		csi->data_q[pilot] = 0;
	}

	if (!phy->csi.reorder)
		return;

	for (i = 0; i < 3; i++) {
		const struct csi_reorder *ro = &cmask->ro[i];
		u8 dest = ro->dest;
		u8 start = ro->start;
		u8 end = ro->end;

		if (!dest && !start && !end)
			break;

		if (dest == start)
			continue;

		if (end) {
			memmove(&csi->data_i[dest], &csi->data_i[start],
				end - start + 1);
			memmove(&csi->data_q[dest], &csi->data_q[start],
				end - start + 1);
		} else {
			csi->data_i[dest] = csi->data_i[start];
			csi->data_q[dest] = csi->data_q[start];
		}
	}
}

static int
mt7915_vendor_csi_ctrl_dump(struct wiphy *wiphy, struct wireless_dev *wdev,
			    struct sk_buff *skb, const void *data, int data_len,
			    unsigned long *storage)
{
#define RESERVED_SET	BIT(31)
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_CSI_CTRL];
	int err = 0;

	if (*storage & RESERVED_SET) {
		if ((*storage & GENMASK(15, 0)) == 0)
			return -ENOENT;
		(*storage)--;
	}

	if (data) {
		err = nla_parse(tb, MTK_VENDOR_ATTR_CSI_CTRL_MAX, data, data_len,
				csi_ctrl_policy, NULL);
		if (err)
			return err;
	}

	if (!(*storage & RESERVED_SET) && tb[MTK_VENDOR_ATTR_CSI_CTRL_DUMP_NUM]) {
		*storage = nla_get_u16(tb[MTK_VENDOR_ATTR_CSI_CTRL_DUMP_NUM]);
		*storage |= RESERVED_SET;
	}

	spin_lock_bh(&phy->csi.csi_lock);

	if (!list_empty(&phy->csi.csi_list)) {
		struct csi_data *csi;
		void *a, *b;
		int i;

		csi = list_first_entry(&phy->csi.csi_list, struct csi_data, node);

		mt7915_vendor_csi_tone_mask(phy, csi);

		a = nla_nest_start(skb, MTK_VENDOR_ATTR_CSI_CTRL_DATA);

		if (nla_put_u8(skb, MTK_VENDOR_ATTR_CSI_DATA_VER, 1) ||
		    nla_put_u8(skb, MTK_VENDOR_ATTR_CSI_DATA_RSSI, csi->rssi) ||
		    nla_put_u8(skb, MTK_VENDOR_ATTR_CSI_DATA_SNR, csi->snr) ||
		    nla_put_u8(skb, MTK_VENDOR_ATTR_CSI_DATA_BW, csi->data_bw) ||
		    nla_put_u8(skb, MTK_VENDOR_ATTR_CSI_DATA_CH_IDX, csi->pri_ch_idx) ||
		    nla_put_u8(skb, MTK_VENDOR_ATTR_CSI_DATA_MODE, csi->rx_mode))
			goto out;

		if (nla_put_u16(skb, MTK_VENDOR_ATTR_CSI_DATA_TX_ANT, csi->tx_idx) ||
		    nla_put_u16(skb, MTK_VENDOR_ATTR_CSI_DATA_RX_ANT, csi->rx_idx))
			goto out;

		if (nla_put_u32(skb, MTK_VENDOR_ATTR_CSI_DATA_INFO, csi->info) ||
		    nla_put_u32(skb, MTK_VENDOR_ATTR_CSI_DATA_H_IDX, csi->h_idx) ||
		    nla_put_u32(skb, MTK_VENDOR_ATTR_CSI_DATA_TS, csi->ts))
			goto out;

		b = nla_nest_start(skb, MTK_VENDOR_ATTR_CSI_DATA_TA);
			for (i = 0; i < ARRAY_SIZE(csi->ta); i++)
				if (nla_put_u8(skb, i, csi->ta[i]))
					goto out;
		nla_nest_end(skb, b);

		b = nla_nest_start(skb, MTK_VENDOR_ATTR_CSI_DATA_I);
			for (i = 0; i < ARRAY_SIZE(csi->data_i); i++)
				if (nla_put_u16(skb, i, csi->data_i[i]))
					goto out;
		nla_nest_end(skb, b);

		b = nla_nest_start(skb, MTK_VENDOR_ATTR_CSI_DATA_Q);
			for (i = 0; i < ARRAY_SIZE(csi->data_q); i++)
				if (nla_put_u16(skb, i, csi->data_q[i]))
					goto out;
		nla_nest_end(skb, b);

		nla_nest_end(skb, a);

		list_del(&csi->node);
		kfree(csi);
		phy->csi.count--;

		err = phy->csi.count;
	}
out:
	spin_unlock_bh(&phy->csi.csi_lock);

	return err;
}

static const struct nla_policy
amnt_ctrl_policy[NUM_MTK_VENDOR_ATTRS_AMNT_CTRL] = {
	[MTK_VENDOR_ATTR_AMNT_CTRL_SET] = {.type = NLA_NESTED },
	[MTK_VENDOR_ATTR_AMNT_CTRL_DUMP] = { .type = NLA_NESTED },
};

static const struct nla_policy
amnt_set_policy[NUM_MTK_VENDOR_ATTRS_AMNT_SET] = {
	[MTK_VENDOR_ATTR_AMNT_SET_INDEX] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_AMNT_SET_MACADDR] = { .type = NLA_NESTED },
};

static const struct nla_policy
amnt_dump_policy[NUM_MTK_VENDOR_ATTRS_AMNT_DUMP] = {
	[MTK_VENDOR_ATTR_AMNT_DUMP_INDEX] = {.type = NLA_U8 },
	[MTK_VENDOR_ATTR_AMNT_DUMP_LEN] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_AMNT_DUMP_RESULT] = { .type = NLA_NESTED },
};

struct mt7915_amnt_data {
	u8 idx;
	u8 addr[ETH_ALEN];
	s8 rssi[4];
	u32 last_seen;
};

struct mt7915_smesh {
	u8 band;
	u8 write;
	u8 enable;
	bool a2;
	bool a1;
	bool data;
	bool mgnt;
	bool ctrl;
} __packed;

struct mt7915_smesh_event {
	u8 band;
	__le32 value;
} __packed;

static int
mt7915_vendor_smesh_ctrl(struct mt7915_phy *phy, u8 write,
			 u8 enable, u32 *value)
{
	struct mt7915_dev *dev = phy->dev;
	struct mt7915_smesh req = {
		.band = phy != &dev->phy,
		.write = write,
		.enable = enable,
		.a2 = 1,
		.a1 = 1,
		.data = 1,
	};
	struct mt7915_smesh_event *res;
	struct sk_buff *skb;
	int ret = 0;

	ret = mt76_mcu_send_and_get_msg(&dev->mt76, MCU_EXT_CMD(SMESH_CTRL),
					&req, sizeof(req), !write, &skb);

	if (ret || write)
		return ret;

	res = (struct mt7915_smesh_event *) skb->data;

	if (!value)
		return -EINVAL;

	*value = res->value;

	dev_kfree_skb(skb);

	return 0;
}

static int
mt7915_vendor_amnt_muar(struct mt7915_phy *phy, u8 muar_idx, u8 *addr)
{
	struct mt7915_dev *dev = phy->dev;
	struct {
		u8 mode;
		u8 force_clear;
		u8 clear_bitmap[8];
		u8 entry_count;
		u8 write;
		u8 band;

		u8 index;
		u8 bssid;
		u8 addr[ETH_ALEN];
	} __packed req = {
		.entry_count = 1,
		.write = 1,
		.band = phy != &dev->phy,
		.index = muar_idx,
	};

	ether_addr_copy(req.addr, addr);

	return mt76_mcu_send_msg(&dev->mt76, MCU_EXT_CMD(MUAR_UPDATE), &req,
				 sizeof(req), true);
}

static int
mt7915_vendor_amnt_set_en(struct mt7915_phy *phy, u8 enable)
{
	u32 status;
	int ret;

	ret = mt7915_vendor_smesh_ctrl(phy, 0, enable, &status);
	if (ret)
		return ret;

	status = status & 0xff;

	if (status == enable)
		return 0;

	ret = mt7915_vendor_smesh_ctrl(phy, 1, enable, &status);
	if (ret)
		return ret;

	return 0;
}

static int
mt7915_vendor_amnt_set_addr(struct mt7915_phy *phy, u8 index, u8 *addr)
{
	struct mt7915_air_monitor_ctrl *amnt_ctrl = &phy->amnt_ctrl;
	struct mt7915_air_monitor_group *group;
	struct mt7915_air_monitor_entry *entry = &amnt_ctrl->entry[index];
	const u8 zero_addr[ETH_ALEN] = {};
	int enable = !ether_addr_equal(addr, zero_addr);
	int ret, i, j;

	if (enable == 1 && entry->enable == 1) {
		ether_addr_copy(entry->addr, addr);
	} else if (enable == 1 && entry->enable == 0){
		for (i = 0; i < MT7915_AIR_MONITOR_MAX_GROUP; i++) {
			group = &(amnt_ctrl->group[i]);
			if (group->used[0] == 0)
				j = 0;
			else
				j = 1;

			group->enable = 1;
			group->used[j] = 1;
			entry->enable = 1;
			entry->group_idx = i;
			entry->group_used_idx = j;
			entry->muar_idx = 32 + 2 * i + 2 * i + 2 * j;
			ether_addr_copy(entry->addr, addr);
			break;
		}
	} else {
		group = &(amnt_ctrl->group[entry->group_idx]);

		group->used[entry->group_used_idx] = 0;
		if (group->used[0] == 0 && group->used[1] == 0)
			group->enable = 0;

		entry->enable = 0;
		ether_addr_copy(entry->addr, addr);
	}

	amnt_ctrl->enable &= ~(1 << entry->group_idx);
	amnt_ctrl->enable |= entry->enable << entry->group_idx;
	ret = mt7915_vendor_amnt_muar(phy, entry->muar_idx, addr);
	if (ret)
		return ret;

	return mt7915_vendor_amnt_set_en(phy, amnt_ctrl->enable);
}

void mt7915_vendor_amnt_fill_rx(struct mt7915_phy *phy, struct sk_buff *skb)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct mt7915_air_monitor_ctrl *ctrl = &phy->amnt_ctrl;
	struct ieee80211_hdr *hdr = mt76_skb_get_hdr(skb);
	__le16 fc = hdr->frame_control;
	u8 addr[ETH_ALEN];
	int i;

	if (!ieee80211_has_fromds(fc))
		ether_addr_copy(addr, hdr->addr2);
	else if (ieee80211_has_tods(fc))
		ether_addr_copy(addr, hdr->addr4);
	else
		ether_addr_copy(addr, hdr->addr3);

	for (i = 0; i < MT7915_AIR_MONITOR_MAX_ENTRY; i++) {
		struct mt7915_air_monitor_entry *entry;

		if (ether_addr_equal(addr, ctrl->entry[i].addr)) {
			entry = &ctrl->entry[i];
			entry->rssi[0] = status->chain_signal[0];
			entry->rssi[1] = status->chain_signal[1];
			entry->rssi[2] = status->chain_signal[2];
			entry->rssi[3] = status->chain_signal[3];
			entry->last_seen = jiffies;
		}
	}

	if (ieee80211_has_tods(fc) &&
	    !ether_addr_equal(hdr->addr3, phy->mt76->macaddr))
		return;
	else if (!ether_addr_equal(hdr->addr1, phy->mt76->macaddr))
		return;
}

int mt7915_vendor_amnt_sta_remove(struct mt7915_phy *phy,
				  struct ieee80211_sta *sta)
{
	u8 zero[ETH_ALEN] = {};
	int i;

	if (!phy->amnt_ctrl.enable)
		return 0;

	for (i = 0; i < MT7915_AIR_MONITOR_MAX_ENTRY; i++)
		if (ether_addr_equal(sta->addr, phy->amnt_ctrl.entry[i].addr))
			return mt7915_vendor_amnt_set_addr(phy, i, zero);

	return 0;
}

static int
mt7915_vendor_amnt_ctrl(struct wiphy *wiphy, struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct nlattr *tb1[NUM_MTK_VENDOR_ATTRS_AMNT_CTRL];
	struct nlattr *tb2[NUM_MTK_VENDOR_ATTRS_AMNT_SET];
	struct nlattr *cur;
	u8 index = 0, i = 0;
	u8 mac_addr[ETH_ALEN] = {};
	int err, rem;

	err = nla_parse(tb1, MTK_VENDOR_ATTR_AMNT_CTRL_MAX, data, data_len,
			amnt_ctrl_policy, NULL);
	if (err)
		return err;

	if (!tb1[MTK_VENDOR_ATTR_AMNT_CTRL_SET])
		return -EINVAL;

	err = nla_parse_nested(tb2, MTK_VENDOR_ATTR_AMNT_SET_MAX,
		tb1[MTK_VENDOR_ATTR_AMNT_CTRL_SET], amnt_set_policy, NULL);

	if (!tb2[MTK_VENDOR_ATTR_AMNT_SET_INDEX] ||
		!tb2[MTK_VENDOR_ATTR_AMNT_SET_MACADDR])
		return -EINVAL;

	index = nla_get_u8(tb2[MTK_VENDOR_ATTR_AMNT_SET_INDEX]);
	nla_for_each_nested(cur, tb2[MTK_VENDOR_ATTR_AMNT_SET_MACADDR], rem) {
		mac_addr[i++] = nla_get_u8(cur);
	}

	return mt7915_vendor_amnt_set_addr(phy, index, mac_addr);
}

static int
mt7915_amnt_dump(struct mt7915_phy *phy, struct sk_buff *skb,
		 u8 amnt_idx, int *attrtype)
{
	struct mt7915_air_monitor_entry *entry =
			&phy->amnt_ctrl.entry[amnt_idx];
	struct mt7915_amnt_data data;
	u32 last_seen = 0;

	if (entry->enable == 0)
		return 0;

	last_seen = jiffies_to_msecs(jiffies - entry->last_seen);

	data.idx = amnt_idx;
	ether_addr_copy(data.addr, entry->addr);
	data.rssi[0] = entry->rssi[0];
	data.rssi[1] = entry->rssi[1];
	data.rssi[2] = entry->rssi[2];
	data.rssi[3] = entry->rssi[3];
	data.last_seen = last_seen;

	nla_put(skb, (*attrtype)++, sizeof(struct mt7915_amnt_data), &data);

	return 1;
}

static int
mt7915_vendor_amnt_ctrl_dump(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct sk_buff *skb, const void *data, int data_len,
			     unsigned long *storage)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct nlattr *tb1[NUM_MTK_VENDOR_ATTRS_AMNT_CTRL];
	struct nlattr *tb2[NUM_MTK_VENDOR_ATTRS_AMNT_DUMP];
	void *a, *b;
	int err = 0, attrtype = 0, i, len = 0;
	u8 amnt_idx;

	if (*storage == 1)
		return -ENOENT;
	*storage = 1;

	err = nla_parse(tb1, MTK_VENDOR_ATTR_AMNT_CTRL_MAX, data, data_len,
			amnt_ctrl_policy, NULL);
	if (err)
		return err;

	if (!tb1[MTK_VENDOR_ATTR_AMNT_CTRL_DUMP])
		return -EINVAL;

	err = nla_parse_nested(tb2, MTK_VENDOR_ATTR_AMNT_DUMP_MAX,
			       tb1[MTK_VENDOR_ATTR_AMNT_CTRL_DUMP],
			       amnt_dump_policy, NULL);
	if (err)
		return err;

	if (!tb2[MTK_VENDOR_ATTR_AMNT_DUMP_INDEX])
		return -EINVAL;

	amnt_idx = nla_get_u8(tb2[MTK_VENDOR_ATTR_AMNT_DUMP_INDEX]);

	a = nla_nest_start(skb, MTK_VENDOR_ATTR_AMNT_CTRL_DUMP);
	b = nla_nest_start(skb, MTK_VENDOR_ATTR_AMNT_DUMP_RESULT);

	if (amnt_idx != 0xff) {
		len += mt7915_amnt_dump(phy, skb, amnt_idx, &attrtype);
	} else {
		for (i = 0; i < MT7915_AIR_MONITOR_MAX_ENTRY; i++) {
			len += mt7915_amnt_dump(phy, skb, i, &attrtype);
		}
	}

	nla_nest_end(skb, b);

	nla_put_u8(skb, MTK_VENDOR_ATTR_AMNT_DUMP_LEN, len);

	nla_nest_end(skb, a);

	return len + 1;
}

static int mt7915_vendor_rfeature_ctrl(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data,
				  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct mt7915_dev *dev = phy->dev;
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_RFEATURE_CTRL];
	int err;
	u32 val;

	err = nla_parse(tb, MTK_VENDOR_ATTR_RFEATURE_CTRL_MAX, data, data_len,
			rfeature_ctrl_policy, NULL);
	if (err)
		return err;

	val = CAPI_RFEATURE_CHANGED;

	if (tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_HE_GI]) {
		val |= FIELD_PREP(RATE_CFG_MODE, RATE_PARAM_FIXED_GI)|
			FIELD_PREP(RATE_CFG_VAL, nla_get_u8(tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_HE_GI]));
		ieee80211_iterate_stations_atomic(hw, mt7915_capi_sta_rc_work, &val);
		ieee80211_queue_work(hw, &dev->rc_work);
	}
	else if (tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_HE_LTF]) {
		val |= FIELD_PREP(RATE_CFG_MODE, RATE_PARAM_FIXED_HE_LTF)|
			FIELD_PREP(RATE_CFG_VAL, nla_get_u8(tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_HE_LTF]));
                ieee80211_iterate_stations_atomic(hw, mt7915_capi_sta_rc_work, &val);
		ieee80211_queue_work(hw, &dev->rc_work);
	}
	else if (tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE_CFG]) {
		u8 enable, trig_type;
		int rem;
		struct nlattr *cur;

		nla_for_each_nested(cur, tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE_CFG], rem) {
			switch(nla_type(cur)) {
			case MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE_EN:
				enable = nla_get_u8(cur);
				break;
			case MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TYPE:
				trig_type = nla_get_u8(cur);
				break;
			default:
				return -EINVAL;
			};
		}

		err = mt7915_mcu_set_rfeature_trig_type(phy, enable, trig_type);
		if (err)
			return err;
	}
	else if (tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_ACK_PLCY]) {
		u8 ack_policy;

		ack_policy = nla_get_u8(tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_ACK_PLCY]);
#define HE_TB_PPDU_ACK 4
		switch (ack_policy) {
		case HE_TB_PPDU_ACK:
			return mt7915_mcu_set_mu_dl_ack_policy(phy, ack_policy);
		default:
			return 0;
		}
	}
	else if (tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TXBF]) {
		u8 trig_txbf;

		trig_txbf = nla_get_u8(tb[MTK_VENDOR_ATTR_RFEATURE_CTRL_TRIG_TXBF]);
		/* CAPI only issues trig_txbf=disable */
	}

	return 0;
}

static int mt7915_vendor_wireless_ctrl(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data,
				  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct mt7915_dev *dev = phy->dev;
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_WIRELESS_CTRL];
	int err;
	u8 val8;
	u16 val16;
	u32 val32;

	err = nla_parse(tb, MTK_VENDOR_ATTR_WIRELESS_CTRL_MAX, data, data_len,
			wireless_ctrl_policy, NULL);
	if (err)
		return err;

	val32 = CAPI_WIRELESS_CHANGED;

	if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_FIXED_MCS]) {
		val32 &= ~CAPI_WIRELESS_CHANGED;
		val32 |= CAPI_RFEATURE_CHANGED |
			FIELD_PREP(RATE_CFG_MODE, RATE_PARAM_FIXED_MCS) |
			FIELD_PREP(RATE_CFG_VAL, nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_FIXED_MCS]));
		ieee80211_iterate_stations_atomic(hw, mt7915_capi_sta_rc_work, &val32);
		ieee80211_queue_work(hw, &dev->rc_work);
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_OFDMA]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_OFDMA]);
		val32 |= FIELD_PREP(RATE_CFG_MODE, RATE_PARAM_FIXED_OFDMA) |
			 FIELD_PREP(RATE_CFG_VAL, val8);
		ieee80211_iterate_active_interfaces_atomic(hw, IEEE80211_IFACE_ITER_RESUME_ALL,
			mt7915_set_wireless_vif, &val32);
		if (val8 == 3) /* DL20and80 */
			mt7915_mcu_set_dynalgo(phy, 1); /* Enable dynamic algo */
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_BA_BUFFER_SIZE]) {
		val16 = nla_get_u16(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_BA_BUFFER_SIZE]);
		hw->max_tx_aggregation_subframes = val16;
		hw->max_rx_aggregation_subframes = val16;
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_MU_EDCA]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_MU_EDCA]);
		mt7915_mcu_set_mu_edca(phy, val8);
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_PPDU_TX_TYPE]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_PPDU_TX_TYPE]);
		mt7915_mcu_set_ppdu_tx_type(phy, val8);
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_NUSERS_OFDMA]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_NUSERS_OFDMA]);
		if (FIELD_GET(OFDMA_UL, dev->dbg.muru_onoff) == 1)
			mt7915_mcu_set_nusers_ofdma(phy, MURU_UL_USER_CNT, val8);
		else
			mt7915_mcu_set_nusers_ofdma(phy, MURU_DL_USER_CNT, val8);
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_MIMO]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_MIMO]);
		val32 |= FIELD_PREP(RATE_CFG_MODE, RATE_PARAM_FIXED_MIMO) |
			 FIELD_PREP(RATE_CFG_VAL, val8);
		ieee80211_iterate_active_interfaces_atomic(hw, IEEE80211_IFACE_ITER_RESUME_ALL,
			mt7915_set_wireless_vif, &val32);
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_CERT]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_CERT]);
		mt7915_mcu_set_cfg(phy, CFGINFO_CERT_CFG, val8); /* Cert Enable for OMI */
		mt7915_mcu_set_bypass_smthint(phy, val8); /* Cert bypass smooth interpolation */
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_AMPDU]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_AMPDU]);
		mt7915_set_wireless_ampdu(hw, val8);
	} else if (tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_AMSDU]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_WIRELESS_CTRL_AMSDU]);
		mt7915_set_wireless_amsdu(hw, val8);
	}

	return 0;
}

static int
mt7915_vendor_wireless_ctrl_dump(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct sk_buff *skb, const void *data, int data_len,
			     unsigned long *storage)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	int len = 0;
	if (*storage == 1)
		return -ENOENT;
	*storage = 1;


	if (nla_put_u8(skb,
	    MTK_VENDOR_ATTR_WIRELESS_DUMP_AMPDU, ieee80211_hw_check(hw, AMPDU_AGGREGATION)) ||
	    nla_put_u8(skb,
	    MTK_VENDOR_ATTR_WIRELESS_DUMP_AMSDU, ieee80211_hw_check(hw, SUPPORTS_AMSDU_IN_AMPDU)))
		return -ENOMEM;
	len += 2;

	return len;
}

static int mt7915_vendor_hemu_ctrl(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data,
				  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_HEMU_CTRL];
	int err;
	u8 val8;
	u32 val32 = 0;

	err = nla_parse(tb, MTK_VENDOR_ATTR_HEMU_CTRL_MAX, data, data_len,
			hemu_ctrl_policy, NULL);
	if (err)
		return err;

	if (tb[MTK_VENDOR_ATTR_HEMU_CTRL_ONOFF]) {
		val8 = nla_get_u8(tb[MTK_VENDOR_ATTR_HEMU_CTRL_ONOFF]);
		val32 |= FIELD_PREP(RATE_CFG_MODE, RATE_PARAM_AUTO_HEMU) |
			 FIELD_PREP(RATE_CFG_VAL, val8);
		ieee80211_iterate_active_interfaces_atomic(hw, IEEE80211_IFACE_ITER_RESUME_ALL,
			mt7915_set_wireless_vif, &val32);
	}

	return 0;
}


static int
mt7915_vendor_hemu_ctrl_dump(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct sk_buff *skb, const void *data, int data_len,
			     unsigned long *storage)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct mt7915_dev *dev = phy->dev;
	int len = 0;

	if (*storage == 1)
		return -ENOENT;
	*storage = 1;

	if (nla_put_u8(skb, MTK_VENDOR_ATTR_HEMU_CTRL_DUMP, dev->dbg.muru_onoff))
		return -ENOMEM;
	len += 1;

	return len;
}


static int
mt7915_vendor_phy_capa_ctrl_dump(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct sk_buff *skb, const void *data, int data_len,
			     unsigned long *storage)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct mt7915_dev *dev = phy->dev;
	void *a;
	int len = 0;

	if (*storage == 1)
		return -ENOENT;
	*storage = 1;

	a = nla_nest_start(skb, MTK_VENDOR_ATTR_PHY_CAPA_CTRL_DUMP);

	if (nla_put_u16(skb,
	    MTK_VENDOR_ATTR_PHY_CAPA_DUMP_MAX_SUPPORTED_BSS, MT7915_MAX_BSS) ||
	    nla_put_u16(skb,
	    MTK_VENDOR_ATTR_PHY_CAPA_DUMP_MAX_SUPPORTED_STA, MT7915_WTBL_STA))
		return -ENOMEM;
	len += 2;

	nla_nest_end(skb, a);

	return len;
}

static int mt7915_vendor_edcca_ctrl(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data,
				  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_EDCCA_CTRL];
	int err;
	u8 edcca_mode;
	s8 edcca_compensation;

	err = nla_parse(tb, MTK_VENDOR_ATTR_EDCCA_CTRL_MAX, data, data_len,
			edcca_ctrl_policy, NULL);
	if (err)
		return err;

	if (!tb[MTK_VENDOR_ATTR_EDCCA_CTRL_MODE])
		return -EINVAL;

	edcca_mode = nla_get_u8(tb[MTK_VENDOR_ATTR_EDCCA_CTRL_MODE]);
	if (edcca_mode == EDCCA_CTRL_SET_EN) {
		u8 edcca_value[3] = {0};
		if (!tb[MTK_VENDOR_ATTR_EDCCA_CTRL_PRI20_VAL] ||
			!tb[MTK_VENDOR_ATTR_EDCCA_CTRL_COMPENSATE]) {
			return -EINVAL;
		}
		edcca_value[0] =
			nla_get_u8(tb[MTK_VENDOR_ATTR_EDCCA_CTRL_PRI20_VAL]);
		edcca_compensation =
			nla_get_s8(tb[MTK_VENDOR_ATTR_EDCCA_CTRL_COMPENSATE]);

		err = mt7915_mcu_set_edcca(phy, edcca_mode, edcca_value,
					 edcca_compensation);
		if (err)
			return err;
	}
	return 0;
}

static int mt7915_vendor_3wire_ctrl(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data,
				    int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_3WIRE_CTRL];
	int err;
	u8 three_wire_mode;

	err = nla_parse(tb, MTK_VENDOR_ATTR_3WIRE_CTRL_MAX, data, data_len,
			three_wire_ctrl_policy, NULL);
	if (err)
		return err;

	if (!tb[MTK_VENDOR_ATTR_3WIRE_CTRL_MODE])
		return -EINVAL;

	three_wire_mode = nla_get_u8(tb[MTK_VENDOR_ATTR_3WIRE_CTRL_MODE]);

	return mt7915_mcu_set_cfg(phy, CFGINFO_3WIRE_EN_CFG, three_wire_mode);
}

static int mt7915_vendor_ibf_ctrl(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data,
				  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct mt7915_dev *dev = phy->dev;
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_IBF_CTRL];
	int err;
	u8 val;

	err = nla_parse(tb, MTK_VENDOR_ATTR_IBF_CTRL_MAX, data, data_len,
			ibf_ctrl_policy, NULL);
	if (err)
		return err;

	if (tb[MTK_VENDOR_ATTR_IBF_CTRL_ENABLE]) {
		val = nla_get_u8(tb[MTK_VENDOR_ATTR_IBF_CTRL_ENABLE]);

		dev->ibf = !!val;

		err = mt7915_mcu_set_txbf(dev, MT_BF_TYPE_UPDATE);
		if (err)
			return err;
	}
	return 0;
}

static int
mt7915_vendor_ibf_ctrl_dump(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct sk_buff *skb, const void *data, int data_len,
			     unsigned long *storage)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7915_phy *phy = mt7915_hw_phy(hw);
	struct mt7915_dev *dev = phy->dev;

	if (*storage == 1)
		return -ENOENT;
	*storage = 1;

	if (nla_put_u8(skb, MTK_VENDOR_ATTR_IBF_DUMP_ENABLE, dev->ibf))
		return -ENOMEM;

	return 1;
}


static const struct wiphy_vendor_command mt7915_vendor_commands[] = {
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_CSI_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_csi_ctrl,
		.dumpit = mt7915_vendor_csi_ctrl_dump,
		.policy = csi_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_CSI_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_AMNT_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_amnt_ctrl,
		.dumpit = mt7915_vendor_amnt_ctrl_dump,
		.policy = amnt_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_AMNT_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_RFEATURE_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_rfeature_ctrl,
		.policy = rfeature_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_RFEATURE_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_WIRELESS_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_wireless_ctrl,
		.dumpit = mt7915_vendor_wireless_ctrl_dump,
		.policy = wireless_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_WIRELESS_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_HEMU_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_hemu_ctrl,
		.dumpit = mt7915_vendor_hemu_ctrl_dump,
		.policy = hemu_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_HEMU_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_PHY_CAPA_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			WIPHY_VENDOR_CMD_NEED_RUNNING,
		.dumpit = mt7915_vendor_phy_capa_ctrl_dump,
		.policy = phy_capa_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_PHY_CAPA_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_EDCCA_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_edcca_ctrl,
		.policy = edcca_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_EDCCA_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_3WIRE_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_3wire_ctrl,
		.policy = three_wire_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_3WIRE_CTRL_MAX,
	},
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_IBF_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7915_vendor_ibf_ctrl,
		.dumpit = mt7915_vendor_ibf_ctrl_dump,
		.policy = ibf_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_IBF_CTRL_MAX,
	}
};

void mt7915_vendor_register(struct mt7915_phy *phy)
{
	phy->mt76->hw->wiphy->vendor_commands = mt7915_vendor_commands;
	phy->mt76->hw->wiphy->n_vendor_commands = ARRAY_SIZE(mt7915_vendor_commands);
}
