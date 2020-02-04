#include <linux/types.h>
#include <linux/autoconf.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/random.h>

#include <asm/rt2880/rt_mmap.h>
#if defined (CONFIG_RALINK_RT6855A)
#include <asm/tc3162/tc3162.h>
#endif

#include "slt.h"
#include "phy_test.h"
#include "gpio.h"

static unsigned int payload_checking_fail = 0;
static int rx_dma_owner_idx; 
static int rx_dma_owner_idx0;
static struct slt_net_device *slt_net;
static struct PDMA_rxdesc *rx_ring;
static struct ephy_l3r18_reg_s mrl3_18;

int forward_config(void);
static void enable_mdio(int enable);
static unsigned int mii_mgr_read(uint32_t phy_addr, uint32_t phy_register, uint32_t *read_data);
static unsigned int mii_mgr_write(uint32_t phy_addr, uint32_t phy_register, uint32_t write_data);
#if defined(CONFIG_RALINK_RT6855A)
static void slt_rt6855a_gsw_init(void);
#endif
static void slt_fe_sw_init(void);
static void slt_set_fe_pdma_glo_cfg(void);
static int slt_fe_pdma_init(void);
static int slt_net_start_xmit(struct sk_buff* skb);
static int slt_ephy_dc_offset_test(unsigned int port);
static int slt_ephy_snr_test(unsigned int port, unsigned int count);


void skb_dump(struct sk_buff* sk) 
{
        unsigned int i;

        printk("skb_dump: from %s with len %d (%d) headroom=%d tailroom=%d\n",
                sk->dev?sk->dev->name:"ip stack",sk->len,sk->truesize,
                skb_headroom(sk),skb_tailroom(sk));

        //for(i=(unsigned int)sk->head;i<=(unsigned int)sk->tail;i++) {
        for(i=(unsigned int)sk->head;i<=(unsigned int)sk->data+20;i++) {
                if((i % 20) == 0)
                        printk("\n");
                if(i==(unsigned int)sk->data) printk("{");
                printk("%02X-",*((unsigned char*)i));
                if(i==(unsigned int)sk->tail) printk("}");
        }
        printk("\n");
}

static void slt_set_fe_pdma_glo_cfg(void)
{
        int pdma_glo_cfg=0;

#if defined(CONFIG_RALINK_RT6855A) 
	pdma_glo_cfg = (TX_WB_DDONE | RX_DMA_EN | TX_DMA_EN | PDMA_BT_SIZE_32DWORDS);
#elif defined (CONFIG_RALINK_MT7620)
	pdma_glo_cfg = (TX_WB_DDONE | RX_DMA_EN | TX_DMA_EN | PDMA_BT_SIZE_16DWORDS);
	pdma_glo_cfg |= (RX_2B_OFFSET);
#endif

	sysRegWrite(PDMA_GLO_CFG, pdma_glo_cfg);
}


static int slt_fe_pdma_init(void)
{
	int i;
	unsigned int regVal;

	while(1) {
		regVal = sysRegRead(PDMA_GLO_CFG);
		if ((regVal & RX_DMA_BUSY)) {
			printk("\nSLT EPHY Test: RX_DMA_BUSY !!! ");
			continue;
		}
		if((regVal & TX_DMA_BUSY)) {
			printk("\nSLT EPHY Test: TX_DMA_BUSY !!! ");
			continue;
		}
		break;
	}

	for (i = 0; i < NUM_TX_DESC; i++)
		slt_net->skb_free[i] = 0;

	slt_net->free_idx =0;
	slt_net->tx_ring0 = pci_alloc_consistent(NULL, NUM_TX_DESC * sizeof(struct PDMA_txdesc), &slt_net->phy_tx_ring0);

	for (i = 0; i < NUM_TX_DESC; i++) {
		memset(&slt_net->tx_ring0[i], 0, sizeof(struct PDMA_txdesc));
		slt_net->tx_ring0[i].txd_info2.LS0_bit = 1;
		slt_net->tx_ring0[i].txd_info2.DDONE_bit = 1;
	}

	/* receiving packet buffer allocation - NUM_RX_DESC x MAX_RX_LENGTH */
        for (i = 0; i < NUM_RX_DESC; i++) {
		slt_net->netrx0_skbuf[i] = dev_alloc_skb(MAX_RX_LENGTH + NET_IP_ALIGN);
		if (slt_net->netrx0_skbuf[i] == NULL )
			printk("rx skbuff buffer allocation failed!");
		else
		    skb_reserve(slt_net->netrx0_skbuf[i], NET_IP_ALIGN);
        }

	/* Initial RX Ring 0*/
	slt_net->rx_ring0 = pci_alloc_consistent(NULL, NUM_RX_DESC * sizeof(struct PDMA_rxdesc), &slt_net->phy_rx_ring0);
	for (i = 0; i < NUM_RX_DESC; i++) {
		memset(&slt_net->rx_ring0[i], 0, sizeof(struct PDMA_rxdesc));
		slt_net->rx_ring0[i].rxd_info2.DDONE_bit = 0;
#if defined (CONFIG_RALINK_MT7620)
		slt_net->rx_ring0[i].rxd_info2.LS0 = 0;
		slt_net->rx_ring0[i].rxd_info2.PLEN0 = MAX_RX_LENGTH;
#else
		slt_net->rx_ring0[i].rxd_info2.LS0 = 1;
#endif
		slt_net->rx_ring0[i].rxd_info1.PDP0 = dma_map_single(NULL, slt_net->netrx0_skbuf[i]->data, MAX_RX_LENGTH, PCI_DMA_FROMDEVICE);
	}

	regVal = sysRegRead(PDMA_GLO_CFG);
	regVal &= 0x000000FF;
	sysRegWrite(PDMA_GLO_CFG, regVal);
	regVal=sysRegRead(PDMA_GLO_CFG);

	/* Tell the adapter where the TX/RX rings are located. */
	sysRegWrite(TX_BASE_PTR0, phys_to_bus((u32) slt_net->phy_tx_ring0));
	sysRegWrite(TX_MAX_CNT0, cpu_to_le32((u32) NUM_TX_DESC));
	sysRegWrite(TX_CTX_IDX0, 0);
	sysRegWrite(PDMA_RST_CFG, PST_DTX_IDX0);

	sysRegWrite(RX_BASE_PTR0, phys_to_bus((u32) slt_net->phy_rx_ring0));
	sysRegWrite(RX_MAX_CNT0,  cpu_to_le32((u32) NUM_RX_DESC));
	sysRegWrite(RX_CALC_IDX0, cpu_to_le32((u32) (NUM_RX_DESC - 1)));
	sysRegWrite(PDMA_RST_CFG, PST_DRX_IDX0);
#if defined (CONFIG_RALINK_RT6855A)
	regVal = sysRegRead(RX_DRX_IDX0);
	regVal = (regVal == 0)? (NUM_RX_DESC - 1) : (regVal - 1);
	sysRegWrite(RX_CALC_IDX0, cpu_to_le32(regVal));
	regVal = sysRegRead(TX_DTX_IDX0);
	sysRegWrite(TX_CTX_IDX0, cpu_to_le32(regVal));
	slt_net->free_idx = regVal;
#endif

	slt_set_fe_pdma_glo_cfg();

	return 1;
}

#if defined (CONFIG_GIGAPHY) || defined (CONFIG_100PHY) || defined (CONFIG_P5_MAC_TO_PHY_MODE)
#if defined (CONFIG_RALINK_RT6855) || defined(CONFIG_RALINK_RT6855A) || \
    defined (CONFIG_RALINK_MT7620) || defined(CONFIG_RALINK_MT7621) 
void enable_auto_negotiate(int unused)
{
	u32 regValue;
	u32 addr = CONFIG_MAC_TO_GIGAPHY_MODE_ADDR;

	/* FIXME: we don't know how to deal with PHY end addr */
	regValue = sysRegRead(ESW_PHY_POLLING);
	regValue |= (1 << 31);
	regValue &= ~(0x1f);
	regValue &= ~(0x1f << 8);
#if defined (CONFIG_RALINK_MT7620) || defined(CONFIG_RALINK_MT7621)
	regValue |= ((addr-1) << 0);//hardware limitation
#else
	regValue |= ((addr) << 0);// setup PHY address for auto polling (start Addr).
#endif
	regValue |= (addr << 8);// setup PHY address for auto polling (End Addr).

	sysRegWrite(ESW_PHY_POLLING, regValue);

#if defined (CONFIG_P4_MAC_TO_PHY_MODE)
	//FIXME: HW auto polling has bug
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3400) &= ~(0x1 << 15);
#endif
#if defined (CONFIG_P5_MAC_TO_PHY_MODE)
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3500) &= ~(0x1 << 15);
#endif
}
#endif
#endif

#if defined (CONFIG_GIGAPHY) || defined (CONFIG_P5_MAC_TO_PHY_MODE)
int isICPlusGigaPHY(int ge)
{
	u32 phy_id0 = 0, phy_id1 = 0;

#ifdef CONFIG_GE2_RGMII_AN
	if (ge == 2) {
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 2, &phy_id0)) {
			printk("\nRead PhyID 1 is Fail!!\n");
			phy_id0 =0;
		}
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 3, &phy_id1)) {
			printk("\nRead PhyID 1 is Fail!!\n");
			phy_id1 = 0;
		}
	}
	else
#endif
#if defined (CONFIG_GE1_RGMII_AN) || defined (CONFIG_P5_MAC_TO_PHY_MODE)
	{
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 2, &phy_id0)) {
			printk("\nRead PhyID 0 is Fail!!\n");
			phy_id0 =0;
		}
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 3, &phy_id1)) {
			printk("\nRead PhyID 0 is Fail!!\n");
			phy_id1 = 0;
		}
	}
#endif

	if ((phy_id0 == EV_ICPLUS_PHY_ID0) && ((phy_id1 & 0xfff0) == EV_ICPLUS_PHY_ID1))
		return 1;

	return 0;
}

int isMarvellGigaPHY(int ge)
{
	u32 phy_id0 = 0, phy_id1 = 0;

#if defined (CONFIG_GE2_RGMII_AN) || defined (CONFIG_P4_MAC_TO_PHY_MODE)
	if (ge == 2) {
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 2, &phy_id0)) {
			printk("\nRead PhyID 1 is Fail!!\n");
			phy_id0 =0;
		}
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 3, &phy_id1)) {
			printk("\nRead PhyID 1 is Fail!!\n");
			phy_id1 = 0;
		}
	}
	else
#endif
#if defined (CONFIG_GE1_RGMII_AN) || defined (CONFIG_P5_MAC_TO_PHY_MODE)
	{
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 2, &phy_id0)) {
			printk("\nRead PhyID 0 is Fail!!\n");
			phy_id0 =0;
		}
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 3, &phy_id1)) {
			printk("\nRead PhyID 0 is Fail!!\n");
			phy_id1 = 0;
		}
	}
#endif

	if ((phy_id0 == EV_MARVELL_PHY_ID0) && (phy_id1 == EV_MARVELL_PHY_ID1))
		return 1;

	return 0;
}

int isVtssGigaPHY(int ge)
{
	u32 phy_id0 = 0, phy_id1 = 0;

#if defined (CONFIG_GE2_RGMII_AN) || defined (CONFIG_P4_MAC_TO_PHY_MODE)
	if (ge == 2) {
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 2, &phy_id0)) {
			printk("\nRead PhyID 1 is Fail!!\n");
			phy_id0 =0;
		}
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 3, &phy_id1)) {
			printk("\nRead PhyID 1 is Fail!!\n");
			phy_id1 = 0;
		}
	}
	else
#endif
#if defined (CONFIG_GE1_RGMII_AN) || defined (CONFIG_P5_MAC_TO_PHY_MODE)
	{
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 2, &phy_id0)) {
			printk("\nRead PhyID 0 is Fail!!\n");
			phy_id0 =0;
		}
		if (!mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 3, &phy_id1)) {
			printk("\nRead PhyID 0 is Fail!!\n");
			phy_id1 = 0;
		}
	}
#endif

	if ((phy_id0 == EV_VTSS_PHY_ID0) && (phy_id1 == EV_VTSS_PHY_ID1))
		return 1;
	
	return 0;
}
#endif

#if defined(CONFIG_RALINK_MT7620)
void rt_gsw_init(void)
{
#if defined (CONFIG_P5_MAC_TO_PHY_MODE)
	unsigned int phy_val;
#endif

#if defined (CONFIG_RALINK_MT7620)
    *(unsigned long *)(SYSCFG1) |= (0x1 << 8); //PCIE_RC_MODE=1
#endif

#if defined (CONFIG_RALINK_MT7620)
    /*
    * Reg 31: Page Control
    * Bit 15     => PortPageSel, 1=local, 0=global
    * Bit 14:12  => PageSel, local:0~3, global:0~4
    *
    * Reg16~30:Local/Global registers
    *
    */
    /*correct  PHY  setting L3.0*/
    mii_mgr_write(1, 31, 0x4000); //global, page 4
  
    mii_mgr_write(1, 17, 0x7444);
    mii_mgr_write(1, 19, 0x0117);
    mii_mgr_write(1, 22, 0x10cf);
    mii_mgr_write(1, 25, 0x6212);
    mii_mgr_write(1, 26, 0x0777);
    mii_mgr_write(1, 29, 0x4000);
    mii_mgr_write(1, 28, 0xc077);
    mii_mgr_write(1, 24, 0x0000);
    
    mii_mgr_write(1, 31, 0x3000); //global, page 3
    mii_mgr_write(1, 17, 0x4838);

    mii_mgr_write(1, 31, 0x2000); //global, page 2
    mii_mgr_write(1, 21, 0x0517);
    mii_mgr_write(1, 22, 0x0fd2);
    mii_mgr_write(1, 23, 0x00bf);
    mii_mgr_write(1, 24, 0x0aab);
    mii_mgr_write(1, 25, 0x00ae);
    mii_mgr_write(1, 26, 0x0fff);
    
    mii_mgr_write(1, 31, 0x1000); //global, page 1
    mii_mgr_write(1, 17, 0xe7f8);
    
    mii_mgr_write(1, 31, 0x8000); //local, page 0
    mii_mgr_write(0, 30, 0xa000);
    mii_mgr_write(1, 30, 0xa000);
    mii_mgr_write(2, 30, 0xa000);
    mii_mgr_write(3, 30, 0xa000);
#if !defined (CONFIG_RAETH_HAS_PORT4)   
    mii_mgr_write(4, 30, 0xa000);
#endif

#if 1
    mii_mgr_write(0, 4, 0x05e1);
    mii_mgr_write(1, 4, 0x05e1);
    mii_mgr_write(2, 4, 0x05e1);
    mii_mgr_write(3, 4, 0x05e1);
#if !defined (CONFIG_RAETH_HAS_PORT4)   
    mii_mgr_write(4, 4, 0x05e1);
#endif
#endif

    mii_mgr_write(1, 31, 0xa000); //local, page 2
    mii_mgr_write(0, 16, 0x1111);
    mii_mgr_write(1, 16, 0x1010);
    mii_mgr_write(2, 16, 0x1515);
    mii_mgr_write(3, 16, 0x0f0f);
#if !defined (CONFIG_RAETH_HAS_PORT4)   
    mii_mgr_write(4, 16, 0x1313);
#endif

#endif

#if defined (CONFIG_RALINK_MT7620)
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x3600) = 0x5e33b;//CPU Port6 Force Link 1G, FC ON
	*(unsigned long *)(RALINK_ETH_SW_BASE+0x0010) = 0x7f7f7fe0;//Set Port6 CPU Port

#if defined (CONFIG_P5_RGMII_TO_MAC_MODE)
        *(unsigned long *)(RALINK_ETH_SW_BASE+0x3500) = 0x5e33b;//(P5, Force mode, Link Up, 1000Mbps, Full-Duplex, FC ON)
	*(unsigned long *)(0xb0000060) &= ~(1 << 9); //set RGMII to Normal mode
	//rxclk_skew, txclk_skew = 0
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 12); //GE1_MODE=RGMii Mode

#elif defined (CONFIG_P5_MII_TO_MAC_MODE)
    	*(unsigned long *)(RALINK_ETH_SW_BASE+0x3500) = 0x5e337;//(P5, Force mode, Link Up, 100Mbps, Full-Duplex, FC ON)
	*(unsigned long *)(0xb0000060) &= ~(1 << 9); //set RGMII to Normal mode
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 12); //GE1_MODE=Mii Mode
	*(unsigned long *)(SYSCFG1) |= (0x1 << 12);

#elif defined (CONFIG_P5_MAC_TO_PHY_MODE)
	*(unsigned long *)(0xb0000060) &= ~(1 << 9); //set RGMII to Normal mode
	*(unsigned long *)(0xb0000060) &= ~(3 << 7); //set MDIO to Normal mode
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 12); //GE1_MODE=RGMii Mode
	
	enable_auto_negotiate(1);

 	if (isICPlusGigaPHY(1)) {
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 4, &phy_val);
		phy_val |= 1<<10; //enable pause ability
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 4, phy_val);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, &phy_val);
		phy_val |= 1<<9; //restart AN
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, phy_val);
	}else if (isMarvellGigaPHY(1)) {
		printk("Reset MARVELL phy1\n");
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 20, &phy_val);
		phy_val |= 1<<7; //Add delay to RX_CLK for RXD Outputs
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 20, phy_val);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, &phy_val);
		phy_val |= 1<<15; //PHY Software Reset
	 	mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, phy_val);
        }else if (isVtssGigaPHY(1)) {
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 31, 0x0001); //extended page
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 28, &phy_val);
		printk("Vitesse phy skew: %x --> ", phy_val);
		phy_val |= (0x3<<12); // RGMII RX skew compensation= 2.0 ns
		phy_val &= ~(0x3<<14);// RGMII TX skew compensation= 0 ns
		printk("%x\n", phy_val);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 28, phy_val);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 31, 0x0000); //main registers
        }


#elif defined (CONFIG_P5_RMII_TO_MAC_MODE)
    	*(unsigned long *)(RALINK_ETH_SW_BASE+0x3500) = 0x5e337;//(P5, Force mode, Link Up, 100Mbps, Full-Duplex, FC ON)
	*(unsigned long *)(0xb0000060) &= ~(1 << 9); //set RGMII to Normal mode
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 12); //GE1_MODE=RvMii Mode
	*(unsigned long *)(SYSCFG1) |= (0x2 << 12);

#else // Port 5 Disabled //
    *(unsigned long *)(RALINK_ETH_SW_BASE+0x3500) = 0x8000;//link down
#endif
#endif

#if defined (CONFIG_P4_RGMII_TO_MAC_MODE)
	*(unsigned long *)(0xb0000060) &= ~(1 << 10); //set GE2 to Normal mode
	//rxclk_skew, txclk_skew = 0
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 14); //GE2_MODE=RGMii Mode

#elif defined (CONFIG_P4_MII_TO_MAC_MODE)
	*(unsigned long *)(0xb0000060) &= ~(1 << 10); //set GE2 to Normal mode
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 14); //GE2_MODE=Mii Mode
	*(unsigned long *)(SYSCFG1) |= (0x1 << 14);

#elif defined (CONFIG_P4_MAC_TO_PHY_MODE)
	*(unsigned long *)(0xb0000060) &= ~(1 << 10); //set GE2 to Normal mode
	*(unsigned long *)(0xb0000060) &= ~(3 << 7); //set MDIO to Normal mode
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 14); //GE2_MODE=RGMii Mode

	enable_auto_negotiate(1);
 
	if (isICPlusGigaPHY(2)) {
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 4, &phy_val);
		phy_val |= 1<<10; //enable pause ability
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 4, phy_val);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 0, &phy_val);
		phy_val |= 1<<9; //restart AN
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 0, phy_val);
	}else if (isMarvellGigaPHY(2)) {
		printk("Reset MARVELL phy2\n");
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 20, &phy_val);
		phy_val |= 1<<7; //Add delay to RX_CLK for RXD Outputs
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 20, phy_val);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 0, &phy_val);
		phy_val |= 1<<15; //PHY Software Reset
	 	mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 0, phy_val);
        }else if (isVtssGigaPHY(2)) {
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 31, 0x0001); //extended page
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 28, &phy_val);
		printk("Vitesse phy skew: %x --> ", phy_val);
		phy_val |= (0x3<<12); // RGMII RX skew compensation= 2.0 ns
		phy_val &= ~(0x3<<14);// RGMII TX skew compensation= 0 ns
		printk("%x\n", phy_val);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 28, phy_val);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 31, 0x0000); //main registers
        }

#elif defined (CONFIG_P4_RMII_TO_MAC_MODE)
    	*(unsigned long *)(RALINK_ETH_SW_BASE+0x3400) = 0x5e337;//(P5, Force mode, Link Up, 100Mbps, Full-Duplex, FC ON)
	*(unsigned long *)(0xb0000060) &= ~(1 << 10); //set GE2 to Normal mode
	*(unsigned long *)(SYSCFG1) &= ~(0x3 << 14); //GE1_MODE=RvMii Mode
	*(unsigned long *)(SYSCFG1) |= (0x2 << 14);

#else // Port 4 Disabled //
    *(unsigned long *)(SYSCFG1) |= (0x3 << 14); //GE2_MODE=RJ45 Mode
#endif

}
#endif


#if defined(CONFIG_RALINK_RT6855A)
static void slt_rt6855a_gsw_init(void)
{
	u32 phy_val = 0;
	u32 rev = 0;

#if defined (CONFIG_RT6855A_ASIC)
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3600) = 0x5e33b;//CPU Port6 Force Link 1G, FC ON
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x0010) = 0xffffffe0;//Set Port6 CPU Port

	*(unsigned long *)(RALINK_FRAME_ENGINE_BASE + 0x1ec) = 0x0fffffff;//Set PSE should pause 4 tx ring as default
	*(unsigned long *)(RALINK_FRAME_ENGINE_BASE + 0x1f0) = 0x0fffffff;//switch IOT more stable
    
	*(unsigned long *)(CKGCR) &= ~(0x3 << 4); //keep rx/tx port clock ticking, disable internal clock-gating to avoid switch stuck 
  
	/*
	*Reg 31: Page Control
	* Bit 15     => PortPageSel, 1=local, 0=global
	* Bit 14:12  => PageSel, local:0~3, global:0~4
	*
	*Reg16~30:Local/Global registers
	*
	*/
	/*correct  PHY  setting J8.0*/
	mii_mgr_read(0, 31, &rev);
	rev &= (0x0f);

	mii_mgr_write(1, 31, 0x4000); //global, page 4
  
	mii_mgr_write(1, 16, 0xd4cc);
	mii_mgr_write(1, 17, 0x7444);
	mii_mgr_write(1, 19, 0x0112);
	mii_mgr_write(1, 21, 0x7160);
	mii_mgr_write(1, 22, 0x10cf);
	mii_mgr_write(1, 26, 0x0777);
    
	if (rev == 0) {
		mii_mgr_write(1, 25, 0x0102);
		mii_mgr_write(1, 29, 0x8641);
	}
	else {
		mii_mgr_write(1, 25, 0x0212);
		mii_mgr_write(1, 29, 0x4640);
	}

	mii_mgr_write(1, 31, 0x2000); //global, page 2
	mii_mgr_write(1, 21, 0x0655);
	mii_mgr_write(1, 22, 0x0fd3);
	mii_mgr_write(1, 23, 0x003d);
	mii_mgr_write(1, 24, 0x096e);
	mii_mgr_write(1, 25, 0x0fed);
	mii_mgr_write(1, 26, 0x0fc4);
    
	mii_mgr_write(1, 31, 0x1000); //global, page 1
	mii_mgr_write(1, 17, 0xe7f8);

	mii_mgr_write(1, 31, 0xa000); //local, page 2
	mii_mgr_write(0, 16, 0x0e0e);
	mii_mgr_write(1, 16, 0x0c0c);
	mii_mgr_write(2, 16, 0x0f0f);
	mii_mgr_write(3, 16, 0x1010);
	mii_mgr_write(4, 16, 0x0909);

	mii_mgr_write(0, 17, 0x0000);
	mii_mgr_write(1, 17, 0x0000);
	mii_mgr_write(2, 17, 0x0000);
	mii_mgr_write(3, 17, 0x0000);
	mii_mgr_write(4, 17, 0x0000);
#endif

#if defined (CONFIG_RT6855A_ASIC)
#if defined (CONFIG_P5_RGMII_TO_MAC_MODE)
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3500) = 0x5e33b;//(P5, Force mode, Link Up, 1000Mbps, Full-Duplex, FC ON)
#elif defined (CONFIG_P5_MII_TO_MAC_MODE)
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3500) = 0x5e337;//(P5, Force mode, Link Up, 100Mbps, Full-Duplex, FC ON)
#elif defined (CONFIG_P5_MAC_TO_PHY_MODE)
	//rt6855/6 need to modify TX/RX phase
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x7014) = 0xc;//TX/RX CLOCK Phase select
	
	enable_auto_negotiate(1);

	if (isICPlusGigaPHY(1)) {
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 4, &phy_val);
		phy_val |= 1 << 10; //enable pause ability
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 4, phy_val);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, &phy_val);
		phy_val |= 1<<9; //restart AN
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, phy_val);
	}

	if (isMarvellGigaPHY(1)) {
		printk("Reset MARVELL phy1\n");
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 20, &phy_val);
		phy_val |= 1<<7; //Add delay to RX_CLK for RXD Outputs
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 20, phy_val);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, &phy_val);
		phy_val |= 1<<15; //PHY Software Reset
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, phy_val);
	}
	if (isVtssGigaPHY(1)) {
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 31, 0x0001); //extended page
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 28, &phy_val);
		printk("Vitesse phy skew: %x --> ", phy_val);
		phy_val |= (0x3 << 12); // RGMII RX skew compensation= 2.0 ns
		phy_val &= ~(0x3 << 14);// RGMII TX skew compensation= 0 ns
		printk("%x\n", phy_val);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 28, phy_val);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 31, 0x0000); //main registers
	}

#elif defined (CONFIG_P5_RMII_TO_MAC_MODE)
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3500) = 0x5e337;//(P5, Force mode, Link Up, 100Mbps, Full-Duplex, FC ON)
#else // Port 5 Disabled //
	*(unsigned long *)(RALINK_ETH_SW_BASE + 0x3500) = 0x8000;//link down
#endif
#endif

}
#endif

void slt_fe_sw_init(void)
{
#if defined (CONFIG_GIGAPHY) || defined (CONFIG_RAETH_ROUTER) || defined (CONFIG_100PHY)
	unsigned int regValue = 0;
#endif

	// Case1: RT288x/RT3883 GE1 + GigaPhy
#if defined (CONFIG_GE1_RGMII_AN)
	enable_auto_negotiate(1);
	if (isMarvellGigaPHY(1)) {
		printk("\n Reset MARVELL phy\n");
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 20, &regValue);
		regValue |= 1 << 7; //Add delay to RX_CLK for RXD Outputs
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 20, regValue);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, &regValue);
		regValue |= 1 << 15; //PHY Software Reset
	 	mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 0, regValue);

	}
	if (isVtssGigaPHY(1)) {
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 31, 1);
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 28, &regValue);
		printk("Vitesse phy skew: %x --> ", regValue);
		regValue |= (0x3 << 12);
		regValue &= ~(0x3 << 14);
		printk("%x\n", regValue);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 28, regValue);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR, 31, 0);
	}
#endif // CONFIG_GE1_RGMII_AN //

	// Case2: RT3883 GE2 + GigaPhy
#if defined (CONFIG_GE2_RGMII_AN)
	enable_auto_negotiate(2);
	if (isMarvellGigaPHY(2)) {
		printk("\n GMAC2 Reset MARVELL phy\n");
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 20, &regValue);
		regValue |= 1<<7; //Add delay to RX_CLK for RXD Outputs
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 20, regValue);

		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 0, &regValue);
		regValue |= 1<<15; //PHY Software Reset
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 0, regValue);

	}
	if (isVtssGigaPHY(2)) {
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 31, 1);
		mii_mgr_read(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 28, &regValue);
		printk("Vitesse phy skew: %x --> ", regValue);
		regValue |= (0x3<<12);
		regValue &= ~(0x3<<14);
		printk("%x\n", regValue);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 28, regValue);
		mii_mgr_write(CONFIG_MAC_TO_GIGAPHY_MODE_ADDR2, 31, 0);
	}
#endif // CONFIG_GE2_RGMII_AN //

	// Case3: RT305x/RT335x/RT6855/RT6855A + EmbeddedSW
#if defined (CONFIG_RT_3052_ESW)
#if defined(CONFIG_RALINK_MT7620)
	rt_gsw_init();
#elif defined(CONFIG_RALINK_RT6855A)
	slt_rt6855a_gsw_init();
#else
	rt305x_esw_init();
#endif
#endif 
	// Case4:  RT288x/RT388x GE1 + GigaSW
#if defined (CONFIG_GE1_RGMII_FORCE_1000)
	sysRegWrite(MDIO_CFG, INIT_VALUE_OF_FORCE_1000_FD);
#endif 

	// Case5: RT388x GE2 + GigaSW
#if defined (CONFIG_GE2_RGMII_FORCE_1000)
	sysRegWrite(MDIO_CFG2, INIT_VALUE_OF_FORCE_1000_FD);
#endif 


	// Case6: RT288x GE1 /RT388x GE1/GE2 + (10/100 Switch or 100PHY)
#if defined (CONFIG_RAETH_ROUTER) || defined (CONFIG_100PHY)

//set GMAC to MII or RvMII mode
#if defined (CONFIG_GE1_MII_FORCE_100)
	sysRegWrite(MDIO_CFG, INIT_VALUE_OF_FORCE_100_FD);
#endif
#if defined (CONFIG_GE2_MII_FORCE_100)
	sysRegWrite(MDIO_CFG2, INIT_VALUE_OF_FORCE_100_FD);
#endif
	//add switch configuration here for other switch chips.
#if defined (CONFIG_GE1_MII_FORCE_100) ||  defined (CONFIG_GE2_MII_FORCE_100)
	// IC+ 175x: force IC+ switch cpu port is 100/FD
	mii_mgr_write(29, 22, 0x8420);
#endif

#if defined (CONFIG_GE1_MII_AN)
	enable_auto_negotiate(1);
#endif
#if defined (CONFIG_GE2_MII_AN)
	enable_auto_negotiate(2);
#endif

#endif // defined (CONFIG_RAETH_ROUTER) || defined (CONFIG_100PHY) //
}

static void xmit_housekeeping(void)
{
	struct PDMA_txdesc *tx_desc;
	unsigned long skb_free_idx;
	unsigned long tx_dtx_idx;

	tx_dtx_idx = sysRegRead(TX_DTX_IDX0);
	tx_desc = slt_net->tx_ring0;
	skb_free_idx = slt_net->free_idx;
	if ((slt_net->skb_free[skb_free_idx]) != 0 && tx_desc[skb_free_idx].txd_info2.DDONE_bit==1) {
		while ((tx_desc[skb_free_idx].txd_info2.DDONE_bit == 1) && (slt_net->skb_free[skb_free_idx]!= 0)) {
			//dev_kfree_skb_any(slt_net->skb_free[skb_free_idx]);
			slt_net->skb_free[skb_free_idx] = 0;
			skb_free_idx = (skb_free_idx + 1) % NUM_TX_DESC;
		}
		slt_net->free_idx = skb_free_idx;
	}  /* if skb_free != 0 */

}

static unsigned int rt2880_eth_recv(int check_payload)
{
	struct sk_buff	*skb, *rx_skb;
	unsigned int	length = 0;
	unsigned int rx_num = 0;
	unsigned char rand_num;
	unsigned int i;
	
	/* Update to Next packet point that was received.
	 */
	while (1) {
		rx_dma_owner_idx0 = (sysRegRead(RX_CALC_IDX0) + 1) % NUM_RX_DESC;

		if (slt_net->rx_ring0[rx_dma_owner_idx0].rxd_info2.DDONE_bit == 1)  {
		    rx_ring = slt_net->rx_ring0;
		    rx_dma_owner_idx = rx_dma_owner_idx0;
		} 
		else
			break;

		/* skb processing */
		length = rx_ring[rx_dma_owner_idx].rxd_info2.PLEN0;
		rx_skb = slt_net->netrx0_skbuf[rx_dma_owner_idx];
		rx_skb->data = slt_net->netrx0_skbuf[rx_dma_owner_idx]->data;
		rx_skb->len 	= length;
		rx_skb->tail 	= rx_skb->data + length;;
		rx_skb->ip_summed = CHECKSUM_NONE;

		/* We have to check the free memory size is big enough
		 * before pass the packet to cpu*/
		skb = __dev_alloc_skb(MAX_RX_LENGTH + NET_IP_ALIGN, GFP_ATOMIC);

		if (unlikely(skb == NULL)) {
			printk(KERN_ERR "skb not available...\n");
			return rx_num;
		}

		skb_reserve(skb, NET_IP_ALIGN);
	
		if (check_payload == 1) {
			rand_num = (unsigned char)(rx_skb->data[VLAN_ETH_HLEN]);
			for (i = 0; i < EPHY_PACKET_PAYLOAD_LEN; i++) {
				if ((unsigned char)(rx_skb->data[VLAN_ETH_HLEN + i]) != (unsigned char)(rand_num + i)) {
					//printk("SLT EPHY Test: payload checking failed. rx_skb->data[%d]=%x expect=%x rx_num=%x\n", i, (unsigned char)(rx_skb->data[VLAN_ETH_HLEN + i]), (unsigned  char)(rand_num + i), rx_num);
					payload_checking_fail++;
					break;
				}
			}
			if (i == EPHY_PACKET_PAYLOAD_LEN)
				rx_num++;
		}
		else
			rx_num++;

		kfree_skb(rx_skb);


#if defined (CONFIG_RALINK_MT7620)
		rx_ring[rx_dma_owner_idx].rxd_info2.PLEN0 = MAX_RX_LENGTH;
		rx_ring[rx_dma_owner_idx].rxd_info2.LS0 = 0;
#endif
		rx_ring[rx_dma_owner_idx].rxd_info2.DDONE_bit = 0;
		rx_ring[rx_dma_owner_idx].rxd_info1.PDP0 = dma_map_single(NULL, skb->data, MAX_RX_LENGTH, PCI_DMA_FROMDEVICE);
		dma_cache_sync(NULL, &rx_ring[rx_dma_owner_idx], sizeof(struct PDMA_rxdesc), DMA_FROM_DEVICE);

		/*  Move point to next RXD which wants to alloc*/
		sysRegWrite(RX_CALC_IDX0, rx_dma_owner_idx);
		slt_net->netrx0_skbuf[rx_dma_owner_idx] = skb;
	}

	return rx_num;
}

int slt_rt2880_eth_send(struct sk_buff *skb, int gmac_no)
{
	unsigned int	length = skb->len;
	unsigned long	tx_cpu_owner_idx0 = sysRegRead(TX_CTX_IDX0);

	while(slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info2.DDONE_bit == 0)
	{
		printk(KERN_ERR "SLT EPHY Test: TX DMA is Busy !! TX desc is Empty!\n");
	}

	slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info1.SDP0 = virt_to_phys(skb->data);
	slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info2.SDL0 = length;
#if defined (CONFIG_RALINK_MT7620)
	/* BMAP = 6: internal loop */
	//slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info4.FP_BMAP = 6;
	slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info4.FP_BMAP = 0;
#else
	slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info4.PN = gmac_no;
	slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info4.QN = 3;
#endif
	slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info2.DDONE_bit = 0;
	//printk("0.SDP0=%x SDL0=%d LS0_bit=%d\n",slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info1.SDP0, skb_headlen(skb), slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info2.LS0_bit);

    	tx_cpu_owner_idx0 = (tx_cpu_owner_idx0+1) % NUM_TX_DESC;
	while(slt_net->tx_ring0[tx_cpu_owner_idx0].txd_info2.DDONE_bit == 0)
		printk(KERN_ERR "SLT EPHY Test: TXD=%lu TX DMA is Busy !!\n", tx_cpu_owner_idx0);

	sysRegWrite(TX_CTX_IDX0, cpu_to_le32((u32)tx_cpu_owner_idx0));

	return length;
}

static int slt_net_start_xmit(struct sk_buff* skb)
{
	unsigned long tx_cpu_owner_idx;
	unsigned int tx_cpu_owner_idx_next;
	unsigned int num_of_txd;
	unsigned int tx_cpu_owner_idx_next2;

	dma_cache_sync(NULL, skb->data, skb->len, DMA_TO_DEVICE);

	tx_cpu_owner_idx = sysRegRead(TX_CTX_IDX0);
	num_of_txd = 1;
	tx_cpu_owner_idx_next = (tx_cpu_owner_idx + num_of_txd) % NUM_TX_DESC;

	if (((slt_net->skb_free[tx_cpu_owner_idx]) == 0) && (slt_net->skb_free[tx_cpu_owner_idx_next] == 0)) {
		slt_rt2880_eth_send(skb, 1);
		tx_cpu_owner_idx_next2 = (tx_cpu_owner_idx_next + 1) % NUM_TX_DESC;
	}
	else {
		printk("SLT EPHY Test: tx_ring_full, drop packet\n");
		kfree_skb(skb);
		return -1;
	}

	slt_net->skb_free[tx_cpu_owner_idx] = skb;

	return 0;
}

void fe_reset(void)
{
#if defined (CONFIG_RALINK_RT6855A)
	/* FIXME */
#else
	u32 val;
	val = sysRegRead(RSTCTRL);

//ASIC suggest reset mt7620 SW//
#if defined (CONFIG_RALINK_MT7620)
	val = val | RALINK_FE_RST;
	//val = val | RALINK_FE_RST | RALINK_ESW_RST ;
#endif
	sysRegWrite(RSTCTRL, val);
#if defined (CONFIG_RALINK_MT7620)
	val = val & ~(RALINK_FE_RST | RALINK_ESW_RST);
#endif
	sysRegWrite(RSTCTRL, val);
#endif
}

void slt_net_stop(void)
{
	int i;
	unsigned int regValue;

	regValue = sysRegRead(PDMA_GLO_CFG);
	regValue &= ~(TX_WB_DDONE | RX_DMA_EN | TX_DMA_EN);
	sysRegWrite(PDMA_GLO_CFG, regValue);
    	
        for ( i = 0; i < NUM_RX_DESC; i++) {
                if (slt_net->netrx0_skbuf[i] != NULL) {
                        dev_kfree_skb(slt_net->netrx0_skbuf[i]);
			slt_net->netrx0_skbuf[i] = NULL;
		}
        }

	/* TX Ring */
       if (slt_net->tx_ring0 != NULL) {
	   pci_free_consistent(NULL, NUM_TX_DESC*sizeof(struct PDMA_txdesc), slt_net->tx_ring0, slt_net->phy_tx_ring0);
       }

	/* RX Ring */
        pci_free_consistent(NULL, NUM_RX_DESC*sizeof(struct PDMA_rxdesc), slt_net->rx_ring0, slt_net->phy_rx_ring0);

	//printk("Free TX/RX Ring Memory!\n");

	//fe_reset();

	//printk("Done\n");	
	// printk("Done0x%x...\n", readreg(PDMA_GLO_CFG));
}

int forward_config(void)
{
	unsigned int	regVal, regCsg;

	regVal = sysRegRead(GDMA1_FWD_CFG);
	regCsg = sysRegRead(CDMA_CSG_CFG);

	//set unicast/multicast/broadcast frame to cpu
#if defined (CONFIG_RALINK_MT7620)
	/* GDMA1 frames destination port is port0 CPU*/
	regVal &= ~0x7;
#else
	regVal &= ~0xFFFF;
#endif
	regCsg &= ~0x7;

#if defined (CONFIG_RALINK_MT7620)
	//enable ipv4 header checksum check
	regVal |= GDM1_ICS_EN;
	regCsg |= ICS_GEN_EN;

	//enable tcp checksum check
	regVal |= GDM1_TCS_EN;
	regCsg |= TCS_GEN_EN;

	//enable udp checksum check
	regVal |= GDM1_UCS_EN;
	regCsg |= UCS_GEN_EN;

#else // Checksum offload disabled

	//disable ipv4 header checksum check
	regVal &= ~GDM1_ICS_EN;
	regCsg &= ~ICS_GEN_EN;

	//disable tcp checksum check
	regVal &= ~GDM1_TCS_EN;
	regCsg &= ~TCS_GEN_EN;

	//disable udp checksum check
	regVal &= ~GDM1_UCS_EN;
	regCsg &= ~UCS_GEN_EN;

#endif // CONFIG_RAETH_CHECKSUM_OFFLOAD //

	sysRegWrite(GDMA1_FWD_CFG, regVal);
	sysRegWrite(CDMA_CSG_CFG, regCsg);

/*
 * 	PSE_FQ_CFG register definition -
 *
 * 	Define max free queue page count in PSE. (31:24)
 *	RT2883/RT3883 - 0xff908000 (255 pages)
 *	RT3052 - 0x80504000 (128 pages)
 *	RT2880 - 0x80504000 (128 pages)
 *
 * 	In each page, there are 128 bytes in each page.
 *
 *	23:16 - free queue flow control release threshold
 *	15:8  - free queue flow control assertion threshold
 *	7:0   - free queue empty threshold
 *
 *	The register affects QOS correctness in frame engine!
 */

#if defined(CONFIG_RALINK_RT6855A) || defined(CONFIG_RALINK_MT7620)
        /*use default value*/
#else
	sysRegWrite(PSE_FQ_CFG, cpu_to_le32(INIT_VALUE_OF_PSE_FQFC_CFG));
#endif

	/*
	 *FE_RST_GLO register definition -
	 *Bit 0: PSE Rest
	 *Reset PSE after re-programming PSE_FQ_CFG.
	 */
	regVal = 0x1;
	sysRegWrite(FE_RST_GL, regVal);
	sysRegWrite(FE_RST_GL, 0);	// update for RSTCTL issue

	regCsg = sysRegRead(CDMA_CSG_CFG);
	regVal = sysRegRead(GDMA1_FWD_CFG);

	return 1;
}

static int esw_link_status_changed(int port_no)
{
	unsigned long reg_val;

	reg_val = *((volatile u32 *)(RALINK_ETH_SW_BASE+ 0x3008 + (port_no * 0x100)));
	if (reg_val & 0x1) {
		//printk("ESW: Link Status Changed - Port%d Link UP\n", port_no);
		return 1;
	} else {
		//printk("ESW: Link Status Changed - Port%d Link Down\n", port_no);
		return 0;
	}
}

int slt_ephy_test(unsigned int chip_id, int port5_test, int check_payload)
{
	uint32_t rx_num = 0, rx_num_bak = 0;
	struct sk_buff *skb;
	struct vlan_ethhdr *veth;
	uint32_t sent_vid;
	unsigned char da[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char sa[ETH_ALEN] = {0x00, 0x00, 0x12, 0x34, 0x00, 0x01};
	unsigned char rand_num;
	unsigned int i, j;
	unsigned int retry_count;
	int ret = 1;
	int packets_per_loop = 0;
	int pre_run = 1;
#if defined (CONFIG_RALINK_RT6855A)
	uint32_t tmp;
#endif

	slt_net = kmalloc(sizeof(struct slt_net_device), GFP_ATOMIC);

	//fe_reset();
	slt_fe_pdma_init();
	slt_fe_sw_init();
	forward_config();
	
#if defined (CONFIG_RALINK_RT6855A)
	/* disable length filed check */
	//tc_outl(0xbfb5800c, 0x71809);
	tmp = sysRegRead(ESW_AGC);
	tmp &= ~(1L << 4);
	sysRegWrite(ESW_AGC, tmp);
#endif

	skb = dev_alloc_skb(EPHY_PACKET_PAYLOAD_LEN + VLAN_ETH_HLEN);
	if (unlikely(skb == NULL)) {
		printk(KERN_ERR "skb not available...\n");
		ret = -1;
		goto out;
	}
	if (skb->len < EPHY_PACKET_PAYLOAD_LEN + VLAN_ETH_HLEN)
		skb_put(skb, (EPHY_PACKET_PAYLOAD_LEN + VLAN_ETH_HLEN) - skb->len);

	veth = (struct vlan_ethhdr *)(skb->data);
	veth->h_vlan_proto = htons(ETH_P_8021Q);
	memcpy(veth->h_dest, da, ETH_ALEN);
	memcpy(veth->h_source, sa, ETH_ALEN);

#if 0
	/* back to default value for re-testing */
	for (i = 0; i < EPHY_TEST_PORT_NUM; i++) {
		mii_mgr_write(i, 4, 0x5e1);  	
		mii_mgr_write(i, 0, 0xb100);
	}
	mdelay(3000);
#endif

	/* DC offset test */
	if (1) {
		/* DC-offset should be measured in open loop.
		 * do this relay switch at the beginnig of SLT test to save time 
		 */
		//set_eth_relay(chip_id, RELAY_OPEN, 1);	
	
		for (i = 0; i < 5; i++) {
			if (slt_ephy_dc_offset_test(i) == 0) {
				printk("SLT EPHY Test: port %d DC-OFFSET test failed.\n", i);
				ret =  0;
				goto out;
			}
		}	
	}

	/* RGMII test */
	if (port5_test) {
		/* clean rx ring */
		rt2880_eth_recv(0);
		rx_num = 0;
		rx_num_bak = 0;
		payload_checking_fail = 0;
	
		sent_vid = 0x6;
		veth->h_vlan_TCI = htons(sent_vid);
		wait_link_up(0, 1);

		packets_per_loop = 10;
		for (i = 0; i < (EPHY_TEST_PACKET_NUM / packets_per_loop) + pre_run; i++) {
			if (check_payload) {
				get_random_bytes(&rand_num, 1);
				for (j = 0; j < EPHY_PACKET_PAYLOAD_LEN; j++)
					skb->data[VLAN_ETH_HLEN + j] = rand_num + j;
			}

			for (j = 0; j < packets_per_loop; j++)
				slt_net_start_xmit(skb);
					
			//udelay(100);

			rx_num += rt2880_eth_recv(check_payload);
			xmit_housekeeping();

    			retry_count = 0;
			while (((rx_num - rx_num_bak) <  packets_per_loop) 
					&& (retry_count < 100)) {
				udelay(100);
				retry_count++;
				//printk("i=%d retry_count=%d\n", i, retry_count);
				rx_num += rt2880_eth_recv(check_payload);
				xmit_housekeeping();
			}
			rx_num_bak = rx_num;

			if ((pre_run == 1) && (i == 0)) {
				rx_num = 0;
				rx_num_bak = 0;
				payload_checking_fail = 0;	
			}
		}

		printk("Receive Packets=%d\n\r", rx_num);	
		printk("payload checking fail packets=%u\n", payload_checking_fail);
		if (rx_num >= (EPHY_TEST_PACKET_NUM - PKTLOSSTHD2))
			printk("SLT RGMII Test: Port 5 test passed\n");
		else {
			printk("SLT RGMII Test: Port 5 lost packets=%d. Test failed\n\r", EPHY_TEST_PACKET_NUM - rx_num);
			ret = 0;
			goto out;
		}

		pre_run = 0;
	}


	/* 100M 100Meter test */
	if (1) {
		/* clean rx ring */
		rt2880_eth_recv(0);
		rx_num = 0;
		rx_num_bak = 0;
		payload_checking_fail = 0;

		sent_vid = 0x7;
		veth->h_vlan_TCI = htons(sent_vid);
	
		/* set phy force 100M */
		for (i = 0; i < EPHY_TEST_PORT_NUM; i++) {
			mii_mgr_write(i, 4, 0x581);  	
			mii_mgr_write(i, 0, 0x3300);
		}
		set_eth_relay(chip_id, RELAY_100M, 1);
		wait_link_up(1, 0);

		for (i = 0; i < 5; i++) {
			if (slt_ephy_snr_test(i, EPHY_SNR_READ_TIMES) == 0) {
				printk("SLT EPHY Test: port %d SNR test failed.\n", i);
				ret = 0;
				goto out;
			}
		}	

		packets_per_loop = 10;
		for (i = 0; i < (EPHY_TEST_PACKET_NUM / packets_per_loop) + pre_run; i++) {
			if (check_payload) {
				get_random_bytes(&rand_num, 1);
				for (j = 0; j < EPHY_PACKET_PAYLOAD_LEN; j++)
					skb->data[VLAN_ETH_HLEN + j] = rand_num + j;
			}

			for (j = 0; j < packets_per_loop; j++)
				slt_net_start_xmit(skb);

			//udelay(1000);

			rx_num += rt2880_eth_recv(check_payload);
			xmit_housekeeping();
    			retry_count = 0;
			while (((rx_num - rx_num_bak) < (EPHY_TEST_PORT_NUM * packets_per_loop))
					&& (retry_count < 100)) {
				udelay(200);
				retry_count++;
				//printk("i=%d retry_count=%d recv_packets=%d\n", i, retry_count, (rx_num - rx_num_bak));
				rx_num += rt2880_eth_recv(check_payload);
				xmit_housekeeping();
			}
			rx_num_bak = rx_num;

			if ((pre_run == 1) && (i == 0)) {
				rx_num = 0;
				rx_num_bak = 0;
				payload_checking_fail = 0;	
			}
		}

		printk("Receive Packets=%d\n\r", rx_num);	
		printk("payload checking fail packets=%u\n", payload_checking_fail);
		if (rx_num >= ((EPHY_TEST_PACKET_NUM * EPHY_TEST_PORT_NUM) - PKTLOSSTHD2))
			printk("SLT RGMII Test: 100M 100Meter test passed\n");
		else {
			printk("SLT EPHY Test: 100M 100Meter lost packets=%d. Test failed\n\r", 
				(EPHY_TEST_PACKET_NUM * EPHY_TEST_PORT_NUM) - rx_num);
			if (((EPHY_TEST_PACKET_NUM * EPHY_TEST_PORT_NUM) - rx_num) > PKTLOSSTHD3) {
				ret = 0;	
				goto out;
			}
			else {
				ret = -1;
				goto out;
			}
		}
	}

	//if(phy_test_100M_1CM)
	if (1) {
		/* clean rx ring */
		rt2880_eth_recv(0);
		rx_num = 0;
		rx_num_bak = 0;
		payload_checking_fail = 0;

		sent_vid = 0x7;
		veth->h_vlan_TCI = htons(sent_vid);

		/* set phy force 100M */
		for (i = 0; i < EPHY_TEST_PORT_NUM; i++) {
			mii_mgr_write(i, 4, 0x581);  	
			mii_mgr_write(i, 0, 0x3300);
		}
		set_eth_relay(chip_id, RELAY_LPBK, 1);
		wait_link_up(1, 0);
	
		packets_per_loop = 10;
		for (i = 0; i < (EPHY_TEST_PACKET2_NUM / packets_per_loop); i++) {
			if (check_payload) {
				get_random_bytes(&rand_num, 1);
				for (j = 0; j < EPHY_PACKET_PAYLOAD_LEN; j++)
					skb->data[VLAN_ETH_HLEN + j] = rand_num + j;
			}
	
			for (j = 0; j < packets_per_loop; j++)
				slt_net_start_xmit(skb);

			//udelay(1000);

			rx_num += rt2880_eth_recv(check_payload);
			xmit_housekeeping();
    			retry_count = 0;
			while (((rx_num - rx_num_bak) < (EPHY_TEST_PORT_NUM * packets_per_loop))
					&& (retry_count < 100)) {
				udelay(200);
				retry_count++;
				//printk("i=%d retry_count=%d recv_packets=%d\n", i, retry_count, (rx_num - rx_num_bak));
				rx_num += rt2880_eth_recv(check_payload);
				xmit_housekeeping();
			}
			rx_num_bak = rx_num;
		}

		printk("Receive Packets=%d\n\r", rx_num);	
		printk("payload checking fail packets=%u\n", payload_checking_fail);
		if (rx_num >= ((EPHY_TEST_PACKET2_NUM * EPHY_TEST_PORT_NUM) - PKTLOSSTHD4))
			printk("SLT RGMII Test: 100M 1CM test passed\n");
		else {
			printk("SLT EPHY Test: 100M 1CM lost packets=%d. Test failed\n\r", 
				(EPHY_TEST_PACKET2_NUM * EPHY_TEST_PORT_NUM) - rx_num);
			ret = 0;
			goto out;
		}
	}

	//if(phy_test_10M_1CM)
	if (1) {
		/* clean rx ring */
		rt2880_eth_recv(0);
		rx_num = 0;
		rx_num_bak = 0;
		payload_checking_fail = 0;

		sent_vid = 0x7;
		veth->h_vlan_TCI = htons(sent_vid);

		/* set phy force 10M */
		for (i = 0; i < EPHY_TEST_PORT_NUM; i++) {
			mii_mgr_write(i, 4, 0x461);  	
			mii_mgr_write(i, 0, 0x1300);
		}
		set_eth_relay(chip_id, RELAY_LPBK, 1);
		wait_link_up(1, 0);

		packets_per_loop = 10;
		for (i = 0; i < (EPHY_TEST_PACKET2_NUM / packets_per_loop); i++) {
			if (check_payload) {
				get_random_bytes(&rand_num, 1);
				for (j = 0; j < EPHY_PACKET_PAYLOAD_LEN; j++)
					skb->data[VLAN_ETH_HLEN + j] = rand_num + j;
			}

			for (j = 0; j < packets_per_loop; j++)
				slt_net_start_xmit(skb);

			//udelay(1000);

			rx_num += rt2880_eth_recv(check_payload);
			xmit_housekeeping();
    			retry_count = 0;
			while (((rx_num - rx_num_bak) < (EPHY_TEST_PORT_NUM * packets_per_loop))
					&& (retry_count < 100)) {
				udelay(200);
				retry_count++;
				//printk("i=%d retry_count=%d recv_packets=%d\n", i, retry_count, (rx_num - rx_num_bak));
				rx_num += rt2880_eth_recv(check_payload);
				xmit_housekeeping();
			}
			rx_num_bak = rx_num;
		}

		printk("Receive Packets=%d\n\r", rx_num);	
		printk("payload checking fail packets=%u\n", payload_checking_fail);
		if (rx_num >= ((EPHY_TEST_PACKET2_NUM * EPHY_TEST_PORT_NUM) - PKTLOSSTHD4))
			printk("SLT RGMII Test: 10M 1CM test passed\n");
		else {
			printk("SLT EPHY Test: 10M 1CM lost packets=%d. Test failed\n\r", 
				(EPHY_TEST_PACKET2_NUM * EPHY_TEST_PORT_NUM) - rx_num);
			ret = 0;
			goto out;
		}
	}

out:
	slt_net_stop();

	return ret;
}

void enable_mdio(int enable)
{

#if defined (CONFIG_RALINK_RT6855) || defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7621)
#if !defined (CONFIG_P5_MAC_TO_PHY_MODE)
	u32 data = sysRegRead(GPIO_PRUPOSE);
	if (enable)
		data &= ~GPIO_MDIO_BIT;
	else
		data |= GPIO_MDIO_BIT;
	sysRegWrite(GPIO_PRUPOSE, data);
#endif
#elif defined (CONFIG_RALINK_RT6855A)
	/*need to check RT6855A MII/GPIO pin share scheme*/
#endif
}


u32 mii_mgr_read(u32 phy_addr, u32 phy_register, u32 *read_data)
{
	u32 volatile status = 0;
	u32 rc = 0;
	unsigned long volatile t_start = jiffies;
	u32 volatile data = 0;

	/* We enable mdio gpio purpose register, and disable it when exit. */
	enable_mdio(1);

	// make sure previous read operation is complete
	while (1) {
			// 0 : Read/write operation complete
		if(!( sysRegRead(MDIO_PHY_CONTROL_0) & (0x1 << 31))) 
		{
			break;
		}
		else if (time_after(jiffies, t_start + (5 * HZ))) {
			enable_mdio(0);
			printk("\n MDIO Read operation is ongoing !!\n");
			return rc;
		}
	}

	data  = (0x01 << 16) | (0x02 << 18) | (phy_addr << 20) | (phy_register << 25);
	sysRegWrite(MDIO_PHY_CONTROL_0, data);
	data |= (1 << 31);
	sysRegWrite(MDIO_PHY_CONTROL_0, data);
	//printk("\n Set Command [0x%08X] to PHY !!\n",MDIO_PHY_CONTROL_0);

	// make sure read operation is complete
	t_start = jiffies;
	while (1) {
		if (!(sysRegRead(MDIO_PHY_CONTROL_0) & (0x1 << 31))) {
			status = sysRegRead(MDIO_PHY_CONTROL_0);
			*read_data = (u32)(status & 0x0000FFFF);

			enable_mdio(0);
			return 1;
		}
		else if (time_after(jiffies, t_start + (5 * HZ))) {
			enable_mdio(0);
			printk("\n MDIO Read operation is ongoing and Time Out!!\n");
			return 0;
		}
	}
}

u32 mii_mgr_write(u32 phy_addr, u32 phy_register, u32 write_data)
{
	unsigned long volatile t_start=jiffies;
	u32 volatile data;

	enable_mdio(1);

	// make sure previous write operation is complete
	while(1) {
		if (!(sysRegRead(MDIO_PHY_CONTROL_0) & (0x1 << 31))) {
			break;
		}
		else if (time_after(jiffies, t_start + (5 * HZ))) {
			enable_mdio(0);
			printk("\n MDIO Write operation ongoing\n");
			return 0;
		}
	}

	data = (0x01 << 16)| (1<<18) | (phy_addr << 20) | (phy_register << 25) | write_data;
	sysRegWrite(MDIO_PHY_CONTROL_0, data);
	data |= (1<<31);
	sysRegWrite(MDIO_PHY_CONTROL_0, data); //start operation
	//printk("\n Set Command [0x%08X] to PHY !!\n",MDIO_PHY_CONTROL_0);

	t_start = jiffies;

	// make sure write operation is complete
	while (1) {
		//0 : Read/write operation complete
		if (!(sysRegRead(MDIO_PHY_CONTROL_0) & (0x1 << 31))) {
			enable_mdio(0);
			return 1;
		}
		else if (time_after(jiffies, t_start + 5 * HZ)) {
			enable_mdio(0);
			printk("\n MDIO Write operation Time Out\n");
			return 0;
		}
	}
}

int set_eth_relay(unsigned int chip_id, int type, int sleep)
{
	unsigned int ephy_relay_gpio0 = 0, ephy_relay_gpio1 = 0;

#if defined(CONFIG_RALINK_RT6855A)
	if (chip_id == RT6855A_CHIP) {
		if (isRT6855) {
			ephy_relay_gpio0 = 1;
			ephy_relay_gpio1 = 10;
		}
		else if (isRT6856) {
			ephy_relay_gpio0 = 2;
			ephy_relay_gpio1 = 10;
		}
		else {
			return 0;
		}
	}
#elif defined (CONFIG_RALINK_MT7620)
	if (chip_id == MT7620_CHIP) {
			ephy_relay_gpio0 = 0;
			ephy_relay_gpio1 = 37;
	}
#else
	return 0;
#endif

	switch(type) {
		case RELAY_100M:
			GPIO_LOW(ephy_relay_gpio0);
			GPIO_LOW(ephy_relay_gpio1);
			break;
		case RELAY_LPBK:
			GPIO_HIGH(ephy_relay_gpio0);
			GPIO_LOW(ephy_relay_gpio1);
			break;
		case RELAY_OPEN:
			GPIO_HIGH(ephy_relay_gpio0);
			GPIO_HIGH(ephy_relay_gpio1);
			break;
		default:	
			break;
	}

	if (sleep)
		msleep(2500);

	return 0;
}

int wait_link_up(int esw, int port5)
{
	while (esw) {
		int i, j;
		unsigned int phy_val;

		j = 0;
		for (i = 0; i < EPHY_TEST_PORT_NUM; i++) {
			phy_val = esw_link_status_changed(i);
			if (phy_val == 1) {
				//printk("port%x is link up\n", i);
				j++;
			}
			//else
				//printk("port%x is link down\n", i);
		}
		if (j == EPHY_TEST_PORT_NUM)
			break;

		udelay(500);
	}

	while (port5) {
		unsigned int phy_val;

		phy_val = esw_link_status_changed(EPHY_TEST_PORT_NUM);
		if (phy_val == 1) {
			//printk("port5 is link up\n");
			break;
		}
		//else
			//printk("port5 is link down\n");

		udelay(500);
	}

	return 0;
}

void ephy_write_global_reg(unsigned char port_num, unsigned char page_num, 
			unsigned char reg_num, unsigned int reg_data)
{
	unsigned int val_r31;
	unsigned int phy_addr = port_num;
	unsigned int page_addr = (page_num << 12);

	mii_mgr_read(phy_addr, 31, &val_r31);  // remember last page
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, page_addr);

	mii_mgr_write(phy_addr, reg_num, reg_data);
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, val_r31);
}

unsigned int ephy_read_global_reg(unsigned char port_num, unsigned char page_num, unsigned char reg_num)
{
	unsigned int val, val_r31;
	unsigned int phy_addr = port_num;
	unsigned int page_addr = (page_num << 12);

	mii_mgr_read(phy_addr, 31, &val_r31);
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, page_addr);

	mii_mgr_read(phy_addr, reg_num, &val);

	if (val_r31 != page_addr) 
		mii_mgr_write(phy_addr, 31, val_r31);
    
	return val;
}

unsigned int ephy_read_local_reg(unsigned char port_num, 
			unsigned char page_num, unsigned char reg_num)
{
	unsigned int val, val_r31;
	unsigned int phy_addr = 0 + port_num;
	unsigned int page_addr = (page_num << 12) + 0x8000;

	mii_mgr_read(phy_addr, 31, &val_r31);

	// set page if necessary
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, page_addr);

	mii_mgr_read(phy_addr, reg_num, &val);

	// restore page if necessary
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, val_r31);

	if (page_num == 3) {
		switch (reg_num) {
			case 18:
				mrl3_18.lp_eee_10g = (val >> 3) & 0x0001;
				mrl3_18.lp_eee_1000 = (val >> 2) & 0x0001;
				mrl3_18.lp_eee_100 = (val >> 1) & 0x0001;
				break;
			default:
				break; 
		}
	}

	return val;
}

void ephy_write_local_reg(unsigned char port_num, unsigned char page_num, 
				unsigned char reg_num, unsigned int reg_data)
{
	unsigned int val_r31;
	unsigned int phy_addr = port_num;
	unsigned int page_addr = (page_num << 12) + 0x8000;

	mii_mgr_read(phy_addr, 31, &val_r31);

	// set page if necessary
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, page_addr);

	mii_mgr_write(phy_addr, reg_num, reg_data);

	// restore page if necessary
	if (val_r31 != page_addr)
		mii_mgr_write(phy_addr, 31, val_r31);
}

int read_probe(unsigned char port_num, unsigned char mode)
{
	unsigned int val, val_r31, val_g0r28;
	unsigned int rval, wval;
	unsigned int phy_addr = port_num;
    
	mii_mgr_read(phy_addr, 31, &val_r31);
	mii_mgr_write(phy_addr, 31, 0x0000);
	mii_mgr_read(phy_addr, 28, &val_g0r28);

	switch (mode) {
		case ProbeZfgain:
			wval = 0x0b04 + port_num;           
			mii_mgr_write(phy_addr, 28, wval);
			mii_mgr_read(phy_addr, 27, &val);
			rval = val & 0x3f;
			break;
		case ProbeAgccode:
			wval = 0x2e04 + port_num;           
			mii_mgr_write(phy_addr, 28, wval);
			mii_mgr_read(phy_addr, 27, &val);
			rval = (val >> 1) & 0x1f;
			break;
		case ProbeBoosten:
			wval = 0x2e04 + port_num;           
			mii_mgr_write(phy_addr, 28, wval);
			mii_mgr_read(phy_addr, 27, &val);
			rval = (val >> 6) & 0x01;
			break;
		case ProbeSnr:
			wval = 0x0904 + port_num;           
			mii_mgr_write(phy_addr, 28, wval);
			mii_mgr_read(phy_addr, 27, &val);
			rval = val & 0xff;
			break;  
		case ProbeAdcSign:
			wval = 0x4104 + port_num;           
			mii_mgr_write(phy_addr, 28, wval);
			mii_mgr_read(phy_addr, 27, &val);
			rval = val & 0x7f ;
			if (rval > 64)
				rval -= 128;
			break;
		default:
			printk("\r\nephy error: ReadProbe %d.\r\n", mode);
			rval = 0;
			break;
	}

	mii_mgr_write(phy_addr, 31, 0x0000);
	mii_mgr_write(phy_addr, 28,  val_g0r28);
	mii_mgr_write(phy_addr, 31, val_r31);

	return rval;
}

int read_adc_sum(unsigned char port_num)
{
	unsigned int cnt = 1000;
	int AdcSign_sum = 0;
	int j;
	unsigned int val_g3r20, val_g3r20_newval, val_l0r30, val_l1r22;
	
	val_g3r20 = ephy_read_global_reg(port_num, 3, 20);
	val_g3r20_newval = val_g3r20 & 0x7fff;
	ephy_write_global_reg(port_num, 3, 20, val_g3r20_newval);

	val_l0r30 = ephy_read_local_reg(port_num, 0, 30);
	ephy_write_local_reg(port_num, 0, 30, 0x1510);

	val_l1r22 = ephy_read_local_reg(port_num, 1, 22);
	ephy_write_local_reg(port_num, 1, 22, 0x000c);
	
	
	for (j = 0; j < cnt; j++)
		AdcSign_sum += read_probe(port_num, ProbeAdcSign);

	//shift right to show percent of the dc offset (unit:%)
	AdcSign_sum = (AdcSign_sum >> 6);

	ephy_write_global_reg(port_num, 3, 20, val_g3r20);
	ephy_write_local_reg(port_num, 0, 30, val_l0r30);
	ephy_write_local_reg(port_num, 1, 22, val_l1r22);
	
	return AdcSign_sum;
}


static int slt_ephy_dc_offset_test(unsigned int port)
{
	int dcoff_MDI, dcoff_MDIX;

	/* When link-down power saving mechanism starts, AD will be disabled.
	 * Therefore, AD will keep at the last value.
	 * In order to read the wrong value, 
	 * turn off link-down power saving in dc_offset_test. 
	 */
	mii_mgr_write(0, 30, 0x00);
	mii_mgr_write(0, 26, 0x5200);
	mdelay(100);
	dcoff_MDI = read_adc_sum(port);
	mii_mgr_write(port, 26, 0x9200);
	mdelay(100);
	dcoff_MDIX = read_adc_sum(0);
	printk("port %d dcoff_MDI=%d dcoff_MDIX:%d\r\n", port, dcoff_MDI, dcoff_MDIX);
	
	// Change back to auto-crossover mode
	mii_mgr_write(port, 26, 0x1600);
	
	// Turn on link-down power saving mechanism
	mii_mgr_write(port, 30, 0x8000);
	
	if ((dcoff_MDI < EPHY_DC_OFFSET_THRESHOLD) 
		&& (dcoff_MDI > (0 - EPHY_DC_OFFSET_THRESHOLD)) 
		&& (dcoff_MDIX < EPHY_DC_OFFSET_THRESHOLD) 
		&& (dcoff_MDIX > (0 - EPHY_DC_OFFSET_THRESHOLD)))
		return 1;

	return 0;
}

static int slt_ephy_snr_test(unsigned int port, unsigned int count)
{
	unsigned int snr_sum = 0;
	unsigned int i;
    
	for (i = 0; i < count; i++) {
		snr_sum += read_probe(port, ProbeSnr);
	}

	printk("port %d SNR SUM=%u\n", port, snr_sum);
	if (snr_sum < EPHY_SNR_THRESHOLD)
		return 1;
	else
		return 0;
}


#if 0
set_per_port_valn(void)
{
	unsigned int data;
	
	u32 data = sysRegRead(GPIO_PRUPOSE);
	if (enable)
		data &= ~GPIO_MDIO_BIT;
	else
		data |= GPIO_MDIO_BIT;

	// LAN/WAN ports as security mode
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2004, 0xff0003);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2104, 0xff0003);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2204, 0xff0003);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2304, 0xff0003);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2404, 0xff0003);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2504, 0xff0003);

	// LAN/WAN ports as transparent port
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2010, 0x810000c0);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2110, 0x810000c0);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2210, 0x810000c0);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2310, 0x810000c0);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2410, 0x810000c0);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2510, 0x810000c0);
	// set CPU/P7 port as user port
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2610, 0x81000000);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2710, 0x81000000);

	// port6, Egress VLAN Tag Attribution=tagged
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2604, 0x20ff0003);
	// port7, Egress VLAN Tag Attribution=tagged
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2704, 0x20ff0003);

	// disable special Tag
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2610, 0x081000000);

	// set PVID
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2014, 0x10001);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2114, 0x10002);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2214, 0x10003);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2314, 0x10004);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2414, 0x10005);
	sysRegWrite(RALINK_ETH_SW_BASE + 0x2514, 0x10006);

	// set VLAN member port
	for (i = 0; i < 5; i++) {
		data = sysRegRead(REG_ESW_VLAN_ID_BASE + 4 * (i / 2));
		if ((idx % 2) == 0) {
			value &= 0xfff000;
			value |= vid;
		}
	else {
		value &= 0xfff;
		value |= (vid << 12);
	}

	sysRegWrite(REG_ESW_VLAN_ID_BASE + 4 * (idx / 2), value);

	//set vlan member
	value = (j << 16);
	value |= (1 << 30);//IVL=1
	value |= ((stag & 0xfff) << 4);//stag

	value |= 1;//valid

	if(argc > 7) {
        value |= (eg_con << 29);//eg_con
	value |= (1 << 28);//eg tag control enable    
	}

}
#endif
