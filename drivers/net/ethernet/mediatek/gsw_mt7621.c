/*   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   Copyright (C) 2009-2015 John Crispin <blogic@openwrt.org>
 *   Copyright (C) 2009-2015 Felix Fietkau <nbd@nbd.name>
 *   Copyright (C) 2013-2015 Michael Lee <igvtee@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>

#include <ralink_regs.h>

#include "mtk_eth_soc.h"

//UBNT
#ifdef CONFIG_NET_REALTEK_RTL8367_PLUGIN
#include "rtl8367c_asicdrv_port.h"
#include "rtl8367c_asicdrv.h"
#include "rtk_types.h"
#include "rtk_switch.h"
#include "rtk_hal.h"
#include "rtl8367c_reg.h"
#include "port.h"
#include "vlan.h"
#include "led.h"
#include "interrupt.h"
#include "smi.h"
#include "svlan.h"
#endif
//UBNT

#include <linux/ubntw.h>
#include "gsw_mt7620.h"

extern struct ubnt_bd_t ubnt_bd_g;
extern void __iomem *fe_sysctl_base;
extern void __iomem *fe_base;

struct mt7620_gsw *gsw_mt7621;
EXPORT_SYMBOL(gsw_mt7621);
#ifdef CONFIG_NET_REALTEK_RTL8367_PLUGIN
int init_rtl8367s(void);
void set_rtl8367s_rgmii(void);
#endif

#ifdef CONFIG_DTB_UBNT_ER
void update_flow_control_status_handler(unsigned long unused);
struct timer_list update_flow_control_status_timer;

void update_flow_control_status_handler(unsigned long unused)
{
	u32 reg;

	reg = mt7530_mdio_r32(gsw_mt7621, 0x1fe0);

	if(!(reg & BIT(31))) {
		// Restart flow control add ON2OFF support
		mt7530_mdio_w32(gsw_mt7621, 0x1fe0, reg | BIT(31) | BIT(28));

		// Clear interrupt status
		mt7530_mdio_w32(gsw_mt7621, 0x700c, BIT(17));
	} else {
		mod_timer(&update_flow_control_status_timer, jiffies + HZ);
	}
}
#endif

void reg_bit_zero(void __iomem *addr, unsigned int bit, unsigned int len)
{
	int reg_val;
	int i;

	reg_val = sys_reg_read(addr);
	for (i = 0; i < len; i++)
		reg_val &= ~(1 << (bit + i));
	sys_reg_write(addr, reg_val);
}

void reg_bit_one(void __iomem *addr, unsigned int bit, unsigned int len)
{
	unsigned int reg_val;
	unsigned int i;

	reg_val = sys_reg_read(addr);
	for (i = 0; i < len; i++)
		reg_val |= 1 << (bit + i);
	sys_reg_write(addr, reg_val);
}

void mtk_switch_w32(struct mt7620_gsw *gsw, u32 val, unsigned reg)
{
	iowrite32(val, gsw->base + reg);
}

u32 mtk_switch_r32(struct mt7620_gsw *gsw, unsigned reg)
{
	return ioread32(gsw->base + reg);
}

static irqreturn_t gsw_interrupt_mt7621(int irq, void *_priv)
{
	struct fe_priv *priv = (struct fe_priv *)_priv;
	struct mt7620_gsw *gsw = (struct mt7620_gsw *)priv->soc->swpriv;
	u32 reg, i;
	struct net_device *dev;
	char ifname[8] = {0};

	reg = mt7530_mdio_r32(gsw, 0x700c);

	for (i = 0; i < 5; i++) {
		if (reg & BIT(i)) {
			unsigned int link;

			link = mt7530_mdio_r32(gsw,
					       0x3008 + (i * 0x100)) & 0x1;

			if (link != priv->link[i]) {
				priv->link[i] = link;
				sprintf(ifname, "eth%d", i);
				dev = dev_get_by_name(&init_net, ifname);
				if (link) {
					netdev_info(priv->netdev,
						    "port %d link up\n", i);

					if(!dev) {
						printk(KERN_ERR "%s: dev(link-up) = NULL\n", __func__);
						mt7530_mdio_w32(gsw, 0x700c, 0x1f);
						return IRQ_HANDLED;
					}
					else
						netif_carrier_on(dev);
				}
				else {
					netdev_info(priv->netdev,
						    "port %d link down\n", i);
					
					if(!dev) {
						printk(KERN_ERR "%s: dev(link-down) = NULL\n", __func__);
						mt7530_mdio_w32(gsw, 0x700c, 0x1f);
						return IRQ_HANDLED;
					}
					else
						netif_carrier_off(dev);
				}
				dev_put(dev);
			}
			mt7530_mdio_w32(gsw, 0x700c, BIT(i));
		}
	}

	// For transmit queue 0 timed out issue
	// Free buffer lower than low water mark
	if (reg & BIT(17)) {
		printk(KERN_WARNING "Warning - free internal queue memory lower than low water mark!!\n");
		
		// Disable flow control
		reg = mt7530_mdio_r32(gsw, 0x1fe0);
		mt7530_mdio_w32(gsw, 0x1fe0, reg & ~(BIT(31)));

		// Make sure flow control has been disabled
		reg = mt7530_mdio_r32(gsw, 0x1fe0);

		if(!(reg & BIT(31))) {
			// Restart flow control add ON2OFF support
			reg = mt7530_mdio_r32(gsw, 0x1fe0);
			mt7530_mdio_w32(gsw, 0x1fe0, reg | BIT(31) | BIT(28));

			// Clear interrupt status
			mt7530_mdio_w32(gsw, 0x700c, BIT(17));
		} else {
			// Flow control didn't disable yet. Add timer to handle it.
			mod_timer(&update_flow_control_status_timer, jiffies + HZ);
		}
	}

	return IRQ_HANDLED;
}

#ifdef CONFIG_NET_REALTEK_RTL8367_PLUGIN
//UBNT- Add RTL8367 interrupt
irqreturn_t rtl8367_gsw_interrupt(int irq, void *resv)
{
	rtk_int_status_t	statusmask;
	rtk_int_info_t		adv_info;
	unsigned int		i=0;

	//UBNT - Added for disable GPIO interrupt register
	reg_bit_one(rt_sysc_membase + 0x690, 0, 64);
	reg_bit_one(rt_sysc_membase + 0x6A0, 0, 48);
	//UBNT

	//printk("%s: %s !!!!!\n", __func__, "rtl8367_interrupt");
	rtk_switch_init();

	memset(&statusmask, 0, sizeof(rtk_int_status_t));
    rtk_int_status_get(&statusmask);

	if(statusmask.value[0] & (1 << INT_TYPE_LINK_STATUS))
	{
		//printk("%s: Port Link Up !!!!!\n", __func__);

		/* Get advanced information */
		rtk_int_advanceInfo_get(ADV_PORT_LINKUP_PORT_MASK, &adv_info);

		for(i=0; i<RTK_PORT_MAX; i++)
		{
			if(RTK_PORTMASK_IS_PORT_SET(adv_info.portMask, i) == 1)
			{
				printk("%s: Port%d Link Up !!!!!\n", __func__, i+5);
			}
		}

		rtk_int_advanceInfo_get(ADV_PORT_LINKDOWN_PORT_MASK, &adv_info);

		for(i=0; i<RTK_PORT_MAX; i++)
		{
			if(RTK_PORTMASK_IS_PORT_SET(adv_info.portMask, i))
			{
				printk("%s: Port%d Link Down !!!!!\n", __func__, i+5);
			}
		}

		/* Clear status */
		statusmask.value[0] = (0x0001 << INT_TYPE_LINK_STATUS);
		rtk_int_status_set(&statusmask);
	}

	return IRQ_HANDLED;
}
#endif

#ifdef CONFIG_DTB_UBNT_ER
static void mt7530_phy_setting(struct mt7620_gsw *gsw)
{
	u32 i;
	u32 reg_value;

	for (i = 0; i < 5; i++) {
		/* Disable EEE */
		_mt7620_mdio_write_cl45(i, 0x7, 0x3c, 0);
		/* Enable HW auto downshift */
		_mt7620_mii_write(gsw, i, 31, 0x1);
		reg_value = _mt7620_mii_read(gsw, i, 0x14);
		reg_value |= (1 << 4);
		_mt7620_mii_write(gsw, i, 0x14, reg_value);
		/* Increase SlvDPSready time */
		_mt7620_mii_write(gsw, i, 31, 0x52b5);
		_mt7620_mii_write(gsw, i, 16, 0xafae);
		_mt7620_mii_write(gsw, i, 18, 0x2f);
		_mt7620_mii_write(gsw, i, 16, 0x8fae);
		/* Incease post_update_timer */
		_mt7620_mii_write(gsw, i, 31, 0x3);
		_mt7620_mii_write(gsw, i, 17, 0x4b);
		/* Adjust 100_mse_threshold */
		_mt7620_mdio_write_cl45(i, 0x1e, 0x123, 0xffff);
		/* Disable mcc */
		_mt7620_mdio_write_cl45(i, 0x1e, 0xa6, 0x300);
	}
}
#endif

static void mt7621_hw_init(struct mt7620_gsw *gsw, struct device_node *np)
{
#if !defined(CONFIG_NET_REALTEK_RTL8367_PLUGIN)
	u32 i;
	u32 val;

	/* wardware reset the switch */
	fe_reset(RST_CTRL_MCM);
	mdelay(10);

	/* reduce RGMII2 PAD driving strength */
	rt_sysc_m32(3 << 4, 0, SYSC_PAD_RGMII2_MDIO);

	/* gpio mux - RGMII1=Normal mode */
	rt_sysc_m32(BIT(14), 0, SYSC_GPIO_MODE);

	/* UBNT: step 2 - Set GMAC2 as GPIO mode */
	rt_sysc_m32(BIT(15), BIT(15), SYSC_GPIO_MODE);

	/* set GMAC1 RGMII mode */
	rt_sysc_m32(3 << 12, 0, SYSC_REG_CFG1);

	/* enable MDIO to control MT7530 */
	rt_sysc_m32(3 << 12, 0, SYSC_GPIO_MODE);

	/* turn off all PHYs */
	for (i = 0; i <= 4; i++) {
		val = _mt7620_mii_read(gsw, i, 0x0);
		val |= BIT(11);
		_mt7620_mii_write(gsw, i, 0x0, val);
	}

	/* reset the switch */
	mt7530_mdio_w32(gsw, 0x7000, 0x3);
	usleep_range(10, 20);

	if ((rt_sysc_r32(SYSC_REG_CHIP_REV_ID) & 0xFFFF) == 0x0101) {
		/* (GE1, Force 1000M/FD, FC ON, MAX_RX_LENGTH 1536) */
		mtk_switch_w32(gsw, 0x2305e30b, GSW_REG_MAC_P0_MCR);
		mt7530_mdio_w32(gsw, 0x3600, 0x5e30b);
	} else {
		/* (GE1, Force 1000M/FD, FC ON, MAX_RX_LENGTH 1536) */
		mtk_switch_w32(gsw, 0x2305e33b, GSW_REG_MAC_P0_MCR);
		mt7530_mdio_w32(gsw, 0x3600, 0x5e33b);
	}

	/* (GE2, Link down) */
	mtk_switch_w32(gsw, 0x8000, GSW_REG_MAC_P1_MCR);

	/* Set switch max RX frame length to 15k */
	mt7530_mdio_w32(gsw, GSW_REG_GMACCR, 0x3F3F);

	/* UBNT: Step1: Set 0x7804[13]=1 and 0x7804[6]=1 (you can refer to attached file that I set 0x7804[13]=1 in setup_internal_gsw() )" */
	/* Enable Port 6, P5 as GMAC5, P5 disable */
	val = mt7530_mdio_r32(gsw, 0x7804);
	val &= ~BIT(8);
	val &= ~BIT(6);
//	val |= BIT(6) | BIT(13) | BIT(16);
	val |= BIT(13) | BIT(16);
	mt7530_mdio_w32(gsw, 0x7804, val);

	val = rt_sysc_r32(0x10);
	val = (val >> 6) & 0x7;
	if (val >= 6) {
		/* 25Mhz Xtal - do nothing */
	} else if (val >= 3) {
		/* 40Mhz */

		/* disable MT7530 core clock */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x410);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x0);

		/* disable MT7530 PLL */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x40d);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x2020);

		/* for MT7530 core clock = 500Mhz */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x40e);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x119);

		/* enable MT7530 PLL */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x40d);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x2820);

		usleep_range(20, 40);

		/* enable MT7530 core clock */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x410);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
	} else {
		/* 20Mhz Xtal - TODO */
	}

	/* RGMII */
	_mt7620_mii_write(gsw, 0, 14, 0x1);

	/* set MT7530 central align */
	val = mt7530_mdio_r32(gsw, 0x7830);
	val &= ~BIT(0);
	val |= BIT(1);
	mt7530_mdio_w32(gsw, 0x7830, val);
	val = mt7530_mdio_r32(gsw, 0x7a40);
	val &= ~BIT(30);
	mt7530_mdio_w32(gsw, 0x7a40, val);
	mt7530_mdio_w32(gsw, 0x7a78, 0x855);

	/* delay setting for 10/1000M */
	mt7530_mdio_w32(gsw, 0x7b00, 0x102);
	mt7530_mdio_w32(gsw, 0x7b04, 0x14);

	/* lower Tx Driving*/
	mt7530_mdio_w32(gsw, 0x7a54, 0x44);
	mt7530_mdio_w32(gsw, 0x7a5c, 0x44);
	mt7530_mdio_w32(gsw, 0x7a64, 0x44);
	mt7530_mdio_w32(gsw, 0x7a6c, 0x44);
	mt7530_mdio_w32(gsw, 0x7a74, 0x44);
	mt7530_mdio_w32(gsw, 0x7a7c, 0x44);

	/* turn on all PHYs */
	for (i = 0; i <= 4; i++) {
		val = _mt7620_mii_read(gsw, i, 0);
		val &= ~BIT(11);
		_mt7620_mii_write(gsw, i, 0, val);
	}

	/* enable irq */
	val = mt7530_mdio_r32(gsw, 0x7808);
	val |= 3 << 16;
	mt7530_mdio_w32(gsw, 0x7808, val);

	val = _mt7620_mii_read(gsw, 7, 0x1f);
	if ((val & 0x000f) == 0x0006)
		printk("     phy 7 (ar8033) speed is 100 (0x%x)\n", (val & 0x000f));
	else if ((val & 0x000f) == 0x0002)
		printk("     phy 7 (ar8033) speed is 1000 (0x%x)\n", (val & 0x000f));
	else
		printk("     phy 7 (ar8033) speed is unknown (0x%x)\n", (val & 0x000f));

	_mt7620_mii_write(gsw, 7, 0x00, 0x0140);
	val = _mt7620_mii_read(gsw, 7, 0x00);
	printk("     phy 7 (ar8033) reg 0x00==0x%x\n", val);
	mt7530_mdio_w32(gsw, 0x3500, 0x7e33b);
#else
	void __iomem *gpio_base_virt = ioremap(0x10005000, 0x1000);
	u32 reg_value;
	u32 xtal_mode;
	u32 i;

	reg_bit_zero(fe_sysctl_base + 0x2c, 11, 1);
	reg_bit_one((fe_base + 0x10000) + 0x0390, 1, 1);	/* TRGMII mode */

	/*Hardware reset Switch */
	reg_bit_zero((void __iomem *)gpio_base_virt + 0x520, 1, 1);
	mdelay(1);
	reg_bit_one((void __iomem *)gpio_base_virt + 0x520, 1, 1);
	mdelay(100);

	/* Assert MT7623 RXC reset */
	reg_bit_one((fe_base + 0x10000) + 0x0300, 31, 1);
	/*For MT7623 reset MT7530 */
	reg_bit_one(fe_sysctl_base + 0x34, 2, 1);
	mdelay(1);
	reg_bit_zero(fe_sysctl_base + 0x34, 2, 1);
	mdelay(100);

	/* Wait for Switch Reset Completed */
	for (i = 0; i < 100; i++) {
		mdelay(10);
		reg_value = mt7530_mdio_r32(gsw, 0x7800);
		if (reg_value != 0) {
			pr_info("MT7530 Reset Completed!!\n");
			break;
		}
		if (i == 99)
			pr_err("MT7530 Reset Timeout!!\n");
	}

	for (i = 0; i <= 4; i++) {
		/*turn off PHY */
		reg_value = _mt7620_mii_read(gsw, i, 0x0);
		reg_value |= (0x1 << 11);
		_mt7620_mii_write(gsw, i, 0x0, reg_value);
	}
	mt7530_mdio_w32(gsw, 0x7000, 0x3);	/* reset switch */
	usleep_range(100, 110);

	/* (GE1, Force 1000M/FD, FC ON) */
	sys_reg_write((fe_base + 0x10000) + 0x100, 0x2305e33b);
	/*
	 * Disable TX/RX flow control on CPU port
	 * which makes the internal hardware circuit queue got full
	 * and then would cause the hardware can't serve
	 * following incoming packets and can't send TX complete interrupt on time.
	 */
	mt7530_mdio_w32(gsw, 0x3600, 0x5e30b);
	reg_value = mt7530_mdio_r32(gsw, 0x3600);
	/* (GE2, Link down) */
	sys_reg_write((fe_base + 0x10000) + 0x200, 0x00008000);

	/* Set switch max RX frame length to 15k */
	mt7530_mdio_w32(gsw, GSW_REG_GMACCR, 0x3F3F);

	reg_value = mt7530_mdio_r32(gsw, 0x7804);
	reg_value &= ~(1 << 8);	/* Enable Port 6 */
	reg_value |= (1 << 6);	/* Disable Port 5 */
	reg_value |= (1 << 13);	/* Port 5 as GMAC, no Internal PHY */

	// Changed RGMII2 mode to GPIO mode
	reg_bit_one(fe_sysctl_base + 0x60, 15, 1);

	/*GMAC2= RGMII mode */
	reg_bit_zero((fe_sysctl_base + 0x14), 14, 2);
	
  	if (!strcmp(ubnt_bd_g.type, "e50")) {
		// Disbale MT7530 P5
		mt7530_mdio_w32(gsw, 0x3500, 0x8000);
		
		/* (GE2, Force 1000) */
		sys_reg_write((fe_base + 0x10000) + 0x200, 0x2305e33b);
	} else {
		/* MT7530 P5 Force 1000 */
		mt7530_mdio_w32(gsw, 0x3500, 0x5e33b);
	} 

	reg_value &= ~(1 << 6);	/* enable MT7530 P5 */
	reg_value |= ((1 << 7) | (1 << 13) | (1 << 16));

	//WAN_AT_P0
	reg_value |= (1 << 20);

	reg_value &= ~(1 << 5);
	reg_value |= (1 << 16);	/* change HW-TRAP */
	pr_info("change HW-TRAP to 0x%x\n", reg_value);
	mt7530_mdio_w32(gsw, 0x7804, reg_value);
	reg_value = mt7530_mdio_r32(gsw, 0x7800);
	reg_value = (reg_value >> 9) & 0x3;
	if (reg_value == 0x3) {	/* 25Mhz Xtal */
		xtal_mode = 1;
		/*Do Nothing */
	} else if (reg_value == 0x2) {	/* 40Mhz */
		xtal_mode = 2;
		/* disable MT7530 core clock */
		_mt7620_mdio_write_cl45(0, 0x1f, 0x410, 0x0);

		_mt7620_mdio_write_cl45(0, 0x1f, 0x40d, 0x2020);
		_mt7620_mdio_write_cl45(0, 0x1f, 0x40e, 0x119);
		_mt7620_mdio_write_cl45(0, 0x1f, 0x40d, 0x2820);
		usleep_range(20, 30);	/* suggest by CD */
		_mt7620_mdio_write_cl45(0, 0x1f, 0x410, 0x1);
	} else {
		xtal_mode = 3;
	 /*TODO*/}

	/* set MT7530 central align */
	reg_value = mt7530_mdio_r32(gsw, 0x7830);
	reg_value &= ~1;
	reg_value |= 1 << 1;
	mt7530_mdio_w32(gsw, 0x7830, reg_value);

	reg_value = mt7530_mdio_r32(gsw, 0x7a40);
	reg_value &= ~(1 << 30);
	mt7530_mdio_w32(gsw, 0x7a40, reg_value);

	reg_value = 0x855;
	mt7530_mdio_w32(gsw, 0x7a78, reg_value);

	mt7530_mdio_w32(gsw, 0x7b00, 0x102);	/* delay setting for 10/1000M */
	mt7530_mdio_w32(gsw, 0x7b04, 0x10);	/* delay setting for 10/1000M */

	/*Tx Driving */
	mt7530_mdio_w32(gsw, 0x7a54, 0x44);	/* lower GE1 driving */
	mt7530_mdio_w32(gsw, 0x7a5c, 0x44);	/* lower GE1 driving */
	mt7530_mdio_w32(gsw, 0x7a64, 0x44);	/* lower GE1 driving */
	mt7530_mdio_w32(gsw, 0x7a6c, 0x44);	/* lower GE1 driving */
	mt7530_mdio_w32(gsw, 0x7a74, 0x44);	/* lower GE1 driving */
	mt7530_mdio_w32(gsw, 0x7a7c, 0x44);	/* lower GE1 driving */

	mt7530_phy_setting(gsw);
	for (i = 0; i <= 4; i++) {
		/*turn on PHY */
		reg_value = _mt7620_mii_read(gsw, i, 0x0);
		reg_value &= ~(0x1 << 11);
		_mt7620_mii_write(gsw, i, 0x0, reg_value);
	}

	reg_value = mt7530_mdio_r32(gsw, 0x7808);
	reg_value |= (3 << 16);	/* Enable INTR */
	mt7530_mdio_w32(gsw, 0x7808, reg_value);

	iounmap(gpio_base_virt);
#endif
}

static const struct of_device_id mediatek_gsw_match[] = {
	{ .compatible = "mediatek,mt7621-gsw" },
	{},
};
MODULE_DEVICE_TABLE(of, mediatek_gsw_match);

int mtk_gsw_init(struct fe_priv *priv)
{
	struct device_node *np = priv->switch_np;
	struct platform_device *pdev = of_find_device_by_node(np);
	struct mt7620_gsw *gsw;

	if (!pdev)
		return -ENODEV;

	if (!of_device_is_compatible(np, mediatek_gsw_match->compatible))
		return -EINVAL;

	gsw = platform_get_drvdata(pdev);
	priv->soc->swpriv = gsw;

	mt7621_hw_init(gsw, np);

	if (gsw->irq) {
		request_irq(gsw->irq, gsw_interrupt_mt7621, 0,
			    "gsw", priv);

		// Interrupt supports queue memory low water warning and link status change
		mt7530_mdio_w32(gsw, 0x7008, 0x2001f);
	}

#ifdef CONFIG_DTB_UBNT_ER
	//Add default VLAN settings for ER

	/*LAN/WAN ports as security mode */
	mt7530_mdio_w32(gsw_mt7621, 0x2004, 0xff0003);
	mt7530_mdio_w32(gsw_mt7621, 0x2004, 0xff0003);	/* port0 */
	mt7530_mdio_w32(gsw_mt7621, 0x2104, 0xff0003);	/* port1 */
	mt7530_mdio_w32(gsw_mt7621, 0x2204, 0xff0003);	/* port2 */
	mt7530_mdio_w32(gsw_mt7621, 0x2304, 0xff0003);	/* port3 */
	mt7530_mdio_w32(gsw_mt7621, 0x2404, 0xff0003);	/* port4 */
	mt7530_mdio_w32(gsw_mt7621, 0x2504, 0x20ff0003);	/* port5 - tag on */
	mt7530_mdio_w32(gsw_mt7621, 0x2604, 0x20ff0003);	/* port6 - tag on */

	//Set port VLAN info
	mt7530_mdio_w32(gsw_mt7621, 0x2010, 0x810000c0);
	mt7530_mdio_w32(gsw_mt7621, 0x2110, 0x810000c0);
	mt7530_mdio_w32(gsw_mt7621, 0x2210, 0x810000c0);
	mt7530_mdio_w32(gsw_mt7621, 0x2310, 0x810000c0);
	mt7530_mdio_w32(gsw_mt7621, 0x2410, 0x810000c0);
	mt7530_mdio_w32(gsw_mt7621, 0x2510, 0x81000000);
	mt7530_mdio_w32(gsw_mt7621, 0x2610, 0x81000000);

	/*set PVID */
	mt7530_mdio_w32(gsw_mt7621, 0x2014, PORT_VID_BASE(ubnt_bd_g.type) + 0x10000);	/* port0 */
	mt7530_mdio_w32(gsw_mt7621, 0x2114, PORT_VID_BASE(ubnt_bd_g.type) + 0x10001);	/* port1 */
	mt7530_mdio_w32(gsw_mt7621, 0x2214, PORT_VID_BASE(ubnt_bd_g.type) + 0x10002);	/* port2 */
	mt7530_mdio_w32(gsw_mt7621, 0x2314, PORT_VID_BASE(ubnt_bd_g.type) + 0x10003);	/* port3 */
	mt7530_mdio_w32(gsw_mt7621, 0x2414, PORT_VID_BASE(ubnt_bd_g.type) + 0x10004);	/* port4 */
	//mt7530_mdio_w32(gsw_mt7621, 0x2514, SWITCH_VID + 0x10000);	/* P5 */
	//mt7530_mdio_w32(gsw_mt7621, 0x2614, PORT_VID_BASE(ubnt_bd_g.type) + 0x1000A);	/* CPU */

	/*VLAN member */
	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40410001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001000);

	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40420001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001001);

	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40440001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001002);

	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40480001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001003);

	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40500001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001004);

	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40600001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001005);
		
	if (strcmp(ubnt_bd_g.type, "e55") == 0
			|| strcmp(ubnt_bd_g.type, "e56") == 0) {
		mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40600001);
		mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001006);

		mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40600001);
		mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001007);

		mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40600001);
		mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001008);

		mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40600001);
		mt7530_mdio_w32(gsw_mt7621, 0x90, PORT_VID_BASE(ubnt_bd_g.type) + 0x80001009);
	}
	//mt7530_mdio_w32(gsw_mt7621, 0x2514, PORT_VID_BASE(ubnt_bd_g.type) + 0x1000A);	/* P5 */
	//mt7530_mdio_w32(gsw_mt7621, 0x2614, PORT_VID_BASE(ubnt_bd_g.type) + 0x1000A);	/* CPU */

	mt7530_mdio_w32(gsw_mt7621, 0x94, 0x40600001);
	mt7530_mdio_w32(gsw_mt7621, 0x90, 0x80001ffe);
#endif /* CONFIG_DTB_UBNT_ER */

#ifdef CONFIG_NET_REALTEK_RTL8367_PLUGIN
	if (strcmp(ubnt_bd_g.type, "e55") == 0
			|| strcmp(ubnt_bd_g.type, "e56") == 0) {
		set_rtl8367s_rgmii();

		rtk_int_polarity_set(INT_POLAR_END);
		rtk_int_control_set(INT_TYPE_LINK_STATUS, DISABLED);

		#if 0
		if(gsw->rtl8367_irq) {
			request_irq(gsw->rtl8367_irq, rtl8367_gsw_interrupt, 0,
			    	"rtl8367_int", priv);
			mdelay(100);
		}
		#endif

		rtk_int_polarity_set(INT_POLAR_LOW);
		rtk_int_control_set(INT_TYPE_LINK_STATUS, ENABLED);
	}
#endif

	return 0;
}

#ifdef CONFIG_NET_REALTEK_RTL8367_PLUGIN
//UBNT - Added RTL8367 support
int init_rtl8367s(void)
{
	static int switch_init;
	rtk_vlan_cfg_t pVlanCfg;
	rtk_portmask_t portmask;
	rtk_svlan_memberCfg_t svlanCfg;
	rtk_vlan_t svid;
	int i;

	#if 0
	reg_bit_zero(RALINK_SYSCTL_BASE+0x600, 7, 1); //Set GPIO_7 to input mode
	reg_bit_one(RALINK_SYSCTL_BASE+0x650, 7, 1);  //Enable rising edge interrupt for GPIO_7
	reg_bit_one(RALINK_SYSCTL_BASE+0x660, 7, 1);  //Enable falling edge interrupt for GPIO_7
	#else
	rt_sysc_m32(BIT(7), 0, 0x600);
	rt_sysc_m32(BIT(7), BIT(7), 0x650);
	rt_sysc_m32(BIT(7), BIT(7), 0x660);
	#endif

	if (switch_init)
		return 0;

	rtl8367c_setAsicReg(RTL8367C_REG_CHIP_RESET, RTL8367C_CHIP_RST_MASK);

	mdelay(500);

	rtk_hal_switch_init();

	switch_init = 1;

	memset(&pVlanCfg, 0, sizeof(rtk_vlan_cfg_t));
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, UTP_PORT0);
	//RTK_PORTMASK_PORT_SET(pVlanCfg.untag, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.untag, UTP_PORT0);
	//pVlanCfg.fid_msti = 0xF;
	rtk_vlan_set(PORT_VID_BASE(ubnt_bd_g.type)+5, &pVlanCfg);

	memset(&pVlanCfg, 0, sizeof(rtk_vlan_cfg_t));
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, UTP_PORT1);
	//RTK_PORTMASK_PORT_SET(pVlanCfg.untag, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.untag, UTP_PORT1);
	//pVlanCfg.fid_msti = 0xF;
	rtk_vlan_set(PORT_VID_BASE(ubnt_bd_g.type)+6, &pVlanCfg);

	memset(&pVlanCfg, 0, sizeof(rtk_vlan_cfg_t));
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, UTP_PORT2);
	//RTK_PORTMASK_PORT_SET(pVlanCfg.untag, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.untag, UTP_PORT2);
	//pVlanCfg.fid_msti = 0xF;
	rtk_vlan_set(PORT_VID_BASE(ubnt_bd_g.type)+7, &pVlanCfg);

	memset(&pVlanCfg, 0, sizeof(rtk_vlan_cfg_t));
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, UTP_PORT3);
	//RTK_PORTMASK_PORT_SET(pVlanCfg.untag, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.untag, UTP_PORT3);
	//pVlanCfg.fid_msti = 0xF;
	rtk_vlan_set(PORT_VID_BASE(ubnt_bd_g.type)+8, &pVlanCfg);

	memset(&pVlanCfg, 0, sizeof(rtk_vlan_cfg_t));
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.mbr, UTP_PORT4);
	//RTK_PORTMASK_PORT_SET(pVlanCfg.untag, EXT_PORT0);
	RTK_PORTMASK_PORT_SET(pVlanCfg.untag, UTP_PORT4);
	//pVlanCfg.fid_msti = 0xF;
	rtk_vlan_set(PORT_VID_BASE(ubnt_bd_g.type)+9, &pVlanCfg);

	memset(&pVlanCfg, 0, sizeof(rtk_vlan_cfg_t));
	rtk_vlan_set(1, &pVlanCfg);
	rtk_vlan_set(2, &pVlanCfg);

	rtk_vlan_portPvid_set(UTP_PORT0, PORT_VID_BASE(ubnt_bd_g.type)+5, 0);
	rtk_vlan_portPvid_set(UTP_PORT1, PORT_VID_BASE(ubnt_bd_g.type)+6, 0);
	rtk_vlan_portPvid_set(UTP_PORT2, PORT_VID_BASE(ubnt_bd_g.type)+7, 0);
	rtk_vlan_portPvid_set(UTP_PORT3, PORT_VID_BASE(ubnt_bd_g.type)+8, 0);
	rtk_vlan_portPvid_set(UTP_PORT4, PORT_VID_BASE(ubnt_bd_g.type)+9, 0);
	//rtk_vlan_portPvid_set(EXT_PORT0, PORT_VID_BASE(ubnt_bd_g.type)+10, 0);

	rtk_vlan_portIgrFilterEnable_set(UTP_PORT0, DISABLED);
	rtk_vlan_portIgrFilterEnable_set(UTP_PORT1, DISABLED);
	rtk_vlan_portIgrFilterEnable_set(UTP_PORT2, DISABLED);
	rtk_vlan_portIgrFilterEnable_set(UTP_PORT3, DISABLED);
	rtk_vlan_portIgrFilterEnable_set(UTP_PORT4, DISABLED);

	//rtk_vlan_egrFilterEnable_set(DISABLED);

	rtk_svlan_init();
	rtk_svlan_servicePort_add(EXT_PORT0);
	rtk_svlan_tpidEntry_set(0x8100);

	for(i=0; i<5; i++) {
		rtk_svlan_servicePort_add(EXT_PORT0);
		rtk_svlan_tpidEntry_set(0x8100);
		memset(&svlanCfg, 0x00, sizeof(rtk_svlan_memberCfg_t));
		svlanCfg.svid = 4089 + i;
		RTK_PORTMASK_PORT_SET(svlanCfg.memberport, i);
		RTK_PORTMASK_PORT_SET(svlanCfg.memberport, EXT_PORT0);
		RTK_PORTMASK_PORT_SET(svlanCfg.untagport, i);
		rtk_svlan_memberPortEntry_set(4089 + i, &svlanCfg);
	}

	for(i = 0; i < 5; i++)
    {
        rtk_svlan_defaultSvlan_set(i, 4089 + i);
    }

	//UBNT_Andrew 2018/04/24
	// Add LED support
	RTK_PORTMASK_PORT_SET(portmask, UTP_PORT0);
	RTK_PORTMASK_PORT_SET(portmask, UTP_PORT1);
	RTK_PORTMASK_PORT_SET(portmask, UTP_PORT2);
	RTK_PORTMASK_PORT_SET(portmask, UTP_PORT3);
	RTK_PORTMASK_PORT_SET(portmask, UTP_PORT4);

	rtk_led_enable_set(LED_GROUP_0, &portmask);
	rtk_led_enable_set(LED_GROUP_1, &portmask);
	rtk_led_operation_set(LED_OP_PARALLEL);
	rtk_led_blinkRate_set(LED_BLINKRATE_128MS);
	rtk_led_groupConfig_set(LED_GROUP_1, LED_CONFIG_LINK_ACT);
	//UBNT

	return 0;
}

void set_rtl8367s_rgmii(void)
{
	rtk_port_mac_ability_t mac_cfg;
	rtk_mode_ext_t mode;

	init_rtl8367s();

	mode = MODE_EXT_RGMII;
	mac_cfg.forcemode = MAC_FORCE;
	mac_cfg.speed = PORT_SPEED_1000M;
	mac_cfg.duplex = PORT_FULL_DUPLEX;
	mac_cfg.link = PORT_LINKUP;
	mac_cfg.nway = DISABLED;
	mac_cfg.txpause = ENABLED;
	mac_cfg.rxpause = ENABLED;
	//UBNT_Andrew 2018/04/24 - Change EXT_PORT1 to EXT_PORT0; reset rx delay from 3 to 1
	rtk_port_macForceLinkExt_set(EXT_PORT0, mode, &mac_cfg);
	rtk_port_rgmiiDelayExt_set(EXT_PORT0, 1, 1);
	//UBNT
	rtk_port_phyEnableAll_set(ENABLED);
}

void sw_ioctl(struct ra_switch_ioctl_data *ioctl_data)
{
	unsigned int cmd;

	cmd = ioctl_data->cmd;
	switch (cmd) {
	case SW_IOCTL_DUMP_MIB:
		rtk_hal_dump_mib();
		break;
	case SW_IOCTL_SET_EGRESS_RATE:
		rtk_hal_set_egress_rate(ioctl_data);
		break;

	case SW_IOCTL_SET_INGRESS_RATE:
		rtk_hal_set_ingress_rate(ioctl_data);
		break;

	case SW_IOCTL_DUMP_VLAN:
		rtk_hal_dump_vlan();
		break;

	case SW_IOCTL_SET_VLAN:
		rtk_hal_set_vlan(ioctl_data);
		break;

	case SW_IOCTL_DUMP_TABLE:
		rtk_hal_dump_table();
		break;

	case SW_IOCTL_GET_PHY_STATUS:
		rtk_hal_get_phy_status(ioctl_data);
		break;

	case SW_IOCTL_SET_PORT_MIRROR:
		rtk_hal_set_port_mirror(ioctl_data);
		break;

	case SW_IOCTL_READ_REG:
		rtk_hal_read_reg(ioctl_data);
		break;

	case SW_IOCTL_WRITE_REG:
		rtk_hal_write_reg(ioctl_data);
		break;

	case SW_IOCTL_QOS_EN:
		rtk_hal_qos_en(ioctl_data);
		break;

	case SW_IOCTL_QOS_SET_TABLE2TYPE:
		rtk_hal_qos_set_table2type(ioctl_data);
		break;

	case SW_IOCTL_QOS_GET_TABLE2TYPE:
		rtk_hal_qos_get_table2type(ioctl_data);
		break;

	case SW_IOCTL_QOS_SET_PORT2TABLE:
		rtk_hal_qos_set_port2table(ioctl_data);
		break;

	case SW_IOCTL_QOS_GET_PORT2TABLE:
		rtk_hal_qos_get_port2table(ioctl_data);
		break;

	case SW_IOCTL_QOS_SET_PORT2PRI:
		rtk_hal_qos_set_port2pri(ioctl_data);
		break;

	case SW_IOCTL_QOS_GET_PORT2PRI:
		rtk_hal_qos_get_port2pri(ioctl_data);
		break;

	case SW_IOCTL_QOS_SET_DSCP2PRI:
		rtk_hal_qos_set_dscp2pri(ioctl_data);
		break;

	case SW_IOCTL_QOS_GET_DSCP2PRI:
		rtk_hal_qos_get_dscp2pri(ioctl_data);
		break;

	case SW_IOCTL_QOS_SET_PRI2QUEUE:
		rtk_hal_qos_set_pri2queue(ioctl_data);
		break;

	case SW_IOCTL_QOS_GET_PRI2QUEUE:
		rtk_hal_qos_get_pri2queue(ioctl_data);
		break;

	case SW_IOCTL_QOS_SET_QUEUE_WEIGHT:
		rtk_hal_qos_set_queue_weight(ioctl_data);
		break;

	case SW_IOCTL_QOS_GET_QUEUE_WEIGHT:
		rtk_hal_qos_get_queue_weight(ioctl_data);
		break;

	case SW_IOCTL_ENABLE_IGMPSNOOP:
		rtk_hal_enable_igmpsnoop(ioctl_data);
		break;

	case SW_IOCTL_DISABLE_IGMPSNOOP:
		rtk_hal_disable_igmpsnoop();
		break;

	case SW_IOCTL_SET_PHY_TEST_MODE:
		rtk_hal_set_phy_test_mode(ioctl_data);
		break;

	case SW_IOCTL_GET_PHY_REG:
		rtk_hal_get_phy_reg(ioctl_data);
		break;

	case SW_IOCTL_SET_PHY_REG:
		rtk_hal_set_phy_reg(ioctl_data);
		break;

	//UBNT_Andrew 2018/06/08
	case SW_IOCTL_SET_PVID:
		rtk_hal_set_pvid(ioctl_data);
		break;

	case SW_IOCTL_VLAN_TAG:
		rtk_hal_set_vlan_tag(ioctl_data);
		break;

	case SW_IOCTL_TABLE_CLEAR:
		rtk_hal_table_clear(ioctl_data);
		break;
	case SW_IOCTL_TAGMODE:
		rtk_hal_set_tagmode(ioctl_data);
		break;
	case SW_IOCTL_TRANSPARENT:
		rtk_hal_set_transparent(ioctl_data);
		break;
	case SW_IOCTL_CLEAR_SVLAN:
		rtk_hal_clear_svlan();
		break;
	case SW_IOCTL_SET_SVLAN:
		rtk_hal_set_svlan(ioctl_data);
		break;
	case SW_IOCTL_SET_SVLAN_DEFAULT:
		rtk_hal_set_svlan_default(ioctl_data);
		break;
	case SW_IOCTL_SET_SVLAN_UNTAG:
		rtk_hal_set_svlan_untag(ioctl_data);
		break;
	case SW_IOCTL_SET_SVLAN_UNMATCH:
		rtk_hal_set_svlan_unmatch(ioctl_data);
		break;
	//UBNT_Andrew

	default:
		break;
	}
}
//UBNT
#endif

static int mt7621_gsw_probe(struct platform_device *pdev)
{
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mt7620_gsw *gsw;

	gsw = devm_kzalloc(&pdev->dev, sizeof(struct mt7620_gsw), GFP_KERNEL);
	if (!gsw)
		return -ENOMEM;

	gsw->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(gsw->base))
		return PTR_ERR(gsw->base);

	gsw->dev = &pdev->dev;
	gsw->irq = platform_get_irq(pdev, 0);

	platform_set_drvdata(pdev, gsw);

	gsw_mt7621 = gsw;

#ifdef CONFIG_DTB_UBNT_ER
	setup_timer(&update_flow_control_status_timer, update_flow_control_status_handler, NULL);
#endif

	return 0;
}

static int mt7621_gsw_remove(struct platform_device *pdev)
{
#ifdef CONFIG_DTB_UBNT_ER
	if(timer_pending(&update_flow_control_status_timer)) {
		del_timer_sync(&update_flow_control_status_timer);
	}
#endif

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct platform_driver gsw_driver = {
	.probe = mt7621_gsw_probe,
	.remove = mt7621_gsw_remove,
	.driver = {
		.name = "mt7621-gsw",
		.owner = THIS_MODULE,
		.of_match_table = mediatek_gsw_match,
	},
};

module_platform_driver(gsw_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Crispin <blogic@openwrt.org>");
MODULE_DESCRIPTION("GBit switch driver for Mediatek MT7621 SoC");
MODULE_VERSION(MTK_FE_DRV_VERSION);
