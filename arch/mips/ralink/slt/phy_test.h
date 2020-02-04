
#define EPHY_TEST_PACKET_NUM 	10000
#define EPHY_TEST_PACKET2_NUM 	2000
#define EPHY_TEST_PORT_NUM	5
#define PACKETS_PER_LOOP	4

#define EPHY_PACKET_PAYLOAD_LEN		1500
#define EPHY_DC_OFFSET_THRESHOLD	150
#if defined (CONFIG_RALINK_RT6855A)
#define EPHY_SNR_THRESHOLD		5800
#elif defined (CONFIG_RALINK_MT7620)
#define EPHY_SNR_THRESHOLD		7500
#else
#define EPHY_SNR_THRESHOLD		7500
#endif
#define EPHY_SNR_READ_TIMES		1000
#define PKTLOSSTHD2			3
#define PKTLOSSTHD3			50
#define PKTLOSSTHD4			0

#define pause(x)	mdelay(x)

#define ProbeBoosten 	2
#define ProbeZfgain  	0
#define ProbeAgccode 	1
#define ProbeBoosten 	2
#define ProbeSnr     	3
#define ProbeDcoff   	4
#define ProbeAdcoff  	5
#define ProbeAdcSign 	6

/*  Phy Vender ID list */
#define EV_ICPLUS_PHY_ID0 	0x0243  
#define EV_ICPLUS_PHY_ID1	0x0D90  
#define EV_MARVELL_PHY_ID0	0x0141  
#define EV_MARVELL_PHY_ID1	0x0CC2  
#define EV_VTSS_PHY_ID0		0x0007
#define EV_VTSS_PHY_ID1		0x0421

#define RX_DONE_INT1     BIT(17)
#define RX_DONE_INT0     BIT(16)

#define NUM_RX_DESC     1024
#define NUM_TX_DESC     1024


#ifdef CONFIG_RAETH_JUMBOFRAME
#define	MAX_RX_LENGTH	4096
#else
#define	MAX_RX_LENGTH	1536
#endif

#if defined (CONFIG_RALINK_RT6855) || defined(CONFIG_RALINK_RT6855A) || \
      defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7621) 
#define ACL_INT			BIT(15)
#define P5_LINK_CH		BIT(5)
#define P4_LINK_CH		BIT(4)
#define P3_LINK_CH		BIT(3)
#define P2_LINK_CH		BIT(2)
#define P1_LINK_CH		BIT(1)
#define P0_LINK_CH		BIT(0)

#define ESW_IMR			(RALINK_ETH_SW_BASE + 0x7000 + 0x8)
#define ESW_ISR			(RALINK_ETH_SW_BASE + 0x7000 + 0xC)
#define ESW_INT_ALL		(P0_LINK_CH | P1_LINK_CH | P2_LINK_CH | P3_LINK_CH | P4_LINK_CH | P5_LINK_CH | ACL_INT)
#define ESW_AISR		(RALINK_ETH_SW_BASE + 0x8)
#define ESW_AGC			(RALINK_ETH_SW_BASE + 0xc)

#define ESW_PHY_POLLING		(RALINK_ETH_SW_BASE + 0x7000)


#endif


#if defined (CONFIG_RALINK_RT6855)  || defined (CONFIG_RALINK_RT6855A) || \
      defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7621) 

#define PHY_CONTROL_0 		0x7004   
#define MDIO_PHY_CONTROL_0	(RALINK_ETH_SW_BASE + PHY_CONTROL_0)

#define GPIO_MDIO_BIT		(1<<7)
#define GPIO_PURPOSE_SELECT	0x60
#define GPIO_PRUPOSE		(RALINK_SYSCTL_BASE + GPIO_PURPOSE_SELECT)

#endif

/*
     FE_INT_STATUS
*/
#if defined (CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855) || defined(CONFIG_RALINK_RT6855A) || \
    defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7621) 

#define FE_INT_ALL		(TX_DONE_INT3 | TX_DONE_INT2 | \
			         TX_DONE_INT1 | TX_DONE_INT0 | \
	                         RX_DONE_INT0 )

#define DELAY_INT_INIT		0x84048404
#define FE_INT_DLY_INIT		(TX_DLY_INT | RX_DLY_INT)

#define RX_COHERENT      BIT(31)
#define RX_DLY_INT       BIT(30)
#define TX_COHERENT      BIT(29)
#define TX_DLY_INT       BIT(28)

#define RX_DONE_INT1     BIT(17)
#define RX_DONE_INT0     BIT(16)

#define TX_DONE_INT3     BIT(3)
#define TX_DONE_INT2     BIT(2)
#define TX_DONE_INT1     BIT(1)
#define TX_DONE_INT0     BIT(0)
#endif



/* ====================================== */
#define GDM1_DISPAD       BIT(18)
#define GDM1_DISCRC       BIT(17)

//GDMA1 uni-cast frames destination port
#define GDM1_ICS_EN   	   (0x1 << 22)
#define GDM1_TCS_EN   	   (0x1 << 21)
#define GDM1_UCS_EN   	   (0x1 << 20)
#define GDM1_JMB_EN   	   (0x1 << 19)
#define GDM1_STRPCRC   	   (0x1 << 16)
#define GDM1_UFRC_P_CPU     (0 << 12)
#define GDM1_UFRC_P_GDMA1   (1 << 12)
#define GDM1_UFRC_P_PPE     (6 << 12)

//GDMA1 broad-cast MAC address frames
#define GDM1_BFRC_P_CPU     (0 << 8)
#define GDM1_BFRC_P_GDMA1   (1 << 8)
#define GDM1_BFRC_P_PPE     (6 << 8)

//GDMA1 multi-cast MAC address frames
#define GDM1_MFRC_P_CPU     (0 << 4)
#define GDM1_MFRC_P_GDMA1   (1 << 4)
#define GDM1_MFRC_P_PPE     (6 << 4)

//GDMA1 other MAC address frames destination port
#define GDM1_OFRC_P_CPU     (0 << 0)
#define GDM1_OFRC_P_GDMA1   (1 << 0)
#define GDM1_OFRC_P_PPE     (6 << 0)

#define ICS_GEN_EN          (1 << 2)
#define UCS_GEN_EN          (1 << 1)
#define TCS_GEN_EN          (1 << 0)

// MDIO_CFG	bit
#define MDIO_CFG_GP1_FC_TX	(1 << 11)
#define MDIO_CFG_GP1_FC_RX	(1 << 10)

/* ====================================== */
/* ====================================== */
#define GP1_LNK_DWN     BIT(9) 
#define GP1_AN_FAIL     BIT(8) 
/* ====================================== */
/* ====================================== */
#define PSE_RESET       BIT(0)
/* ====================================== */
#define PST_DRX_IDX1       BIT(17)
#define PST_DRX_IDX0       BIT(16)
#define PST_DTX_IDX3       BIT(3)
#define PST_DTX_IDX2       BIT(2)
#define PST_DTX_IDX1       BIT(1)
#define PST_DTX_IDX0       BIT(0)

#define RX_2B_OFFSET	  BIT(31)
#define TX_WB_DDONE       BIT(6)
#define RX_DMA_BUSY       BIT(3)
#define TX_DMA_BUSY       BIT(1)
#define RX_DMA_EN         BIT(2)
#define TX_DMA_EN         BIT(0)

#define PDMA_BT_SIZE_4DWORDS     (0<<4)
#define PDMA_BT_SIZE_8DWORDS     (1<<4)
#define PDMA_BT_SIZE_16DWORDS    (2<<4)
#define PDMA_BT_SIZE_32DWORDS    (3<<4)

/* Register bits.
 */

#define MACCFG_RXEN		(1<<2)
#define MACCFG_TXEN		(1<<3)
#define MACCFG_PROMISC		(1<<18)
#define MACCFG_RXMCAST		(1<<19)
#define MACCFG_FDUPLEX		(1<<20)
#define MACCFG_PORTSEL		(1<<27)
#define MACCFG_HBEATDIS		(1<<28)


#define DMACTL_SR		(1<<1)	/* Start/Stop Receive */
#define DMACTL_ST		(1<<13)	/* Start/Stop Transmission Command */

#define DMACFG_SWR		(1<<0)	/* Software Reset */
#define DMACFG_BURST32		(32<<8)

#define DMASTAT_TS		0x00700000	/* Transmit Process State */
#define DMASTAT_RS		0x000e0000	/* Receive Process State */

#define MACCFG_INIT		0 //(MACCFG_FDUPLEX) // | MACCFG_PORTSEL)



/* Descriptor bits.
 */
#define R_OWN		0x80000000	/* Own Bit */
#define RD_RER		0x02000000	/* Receive End Of Ring */
#define RD_LS		0x00000100	/* Last Descriptor */
#define RD_ES		0x00008000	/* Error Summary */
#define RD_CHAIN	0x01000000	/* Chained */

/* Word 0 */
#define T_OWN		0x80000000	/* Own Bit */
#define TD_ES		0x00008000	/* Error Summary */

/* Word 1 */
#define TD_LS		0x40000000	/* Last Segment */
#define TD_FS		0x20000000	/* First Segment */
#define TD_TER		0x08000000	/* Transmit End Of Ring */
#define TD_CHAIN	0x01000000	/* Chained */


#define TD_SET		0x08000000	/* Setup Packet */


#define POLL_DEMAND 1

#define RSTCTL	(0x34)
#define RSTCTL_RSTENET1	(1<<19)
#define RSTCTL_RSTENET2	(1<<20)

#define INIT_VALUE_OF_RT2883_PSE_FQ_CFG		0xff908000
#define INIT_VALUE_OF_PSE_FQFC_CFG		0x80504000
#define INIT_VALUE_OF_FORCE_100_FD		0x1001BC01
#define INIT_VALUE_OF_FORCE_1000_FD		0x1F01DC01

// Define Whole FE Reset Register
#define RSTCTRL         (RALINK_SYSCTL_BASE + 0x34)

#define phys_to_bus(a) (a & 0x1FFFFFFF)

#define PHY_Enable_Auto_Nego		0x1000
#define PHY_Restart_Auto_Nego		0x0200

/* PHY_STAT_REG = 1; */
#define PHY_Auto_Neco_Comp	0x0020
#define PHY_Link_Status		0x0004

/* PHY_AUTO_NEGO_REG = 4; */
#define PHY_Cap_10_Half  0x0020
#define PHY_Cap_10_Full  0x0040
#define	PHY_Cap_100_Half 0x0080
#define	PHY_Cap_100_Full 0x0100

/* proc definition */

#if !defined (CONFIG_RALINK_RT6855) && !defined(CONFIG_RALINK_RT6855A) && \
    !defined (CONFIG_RALINK_MT7620) && !defined (CONFIG_RALINK_MT7621) 
#define CDMA_OQ_STA	(RALINK_FRAME_ENGINE_BASE+RAPSE_OFFSET+0x4c)
#define GDMA1_OQ_STA	(RALINK_FRAME_ENGINE_BASE+RAPSE_OFFSET+0x50)
#define PPE_OQ_STA	(RALINK_FRAME_ENGINE_BASE+RAPSE_OFFSET+0x54)
#define PSE_IQ_STA	(RALINK_FRAME_ENGINE_BASE+RAPSE_OFFSET+0x58)
#endif


#define SYSCFG1			(RALINK_SYSCTL_BASE + 0x14)

#if defined (CONFIG_RALINK_RT6855) || defined(CONFIG_RALINK_RT6855A) || \
      defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7621) 

/* Old FE with New PDMA */
#define PDMA_RELATED            0x0800
/* 1. PDMA */
#define TX_BASE_PTR0            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x000)
#define TX_MAX_CNT0             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x004)
#define TX_CTX_IDX0             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x008)
#define TX_DTX_IDX0             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x00C)

#define TX_BASE_PTR1            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x010)
#define TX_MAX_CNT1             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x014)
#define TX_CTX_IDX1             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x018)
#define TX_DTX_IDX1             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x01C)

#define TX_BASE_PTR2            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x020)
#define TX_MAX_CNT2             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x024)
#define TX_CTX_IDX2             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x028)
#define TX_DTX_IDX2             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x02C)

#define TX_BASE_PTR3            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x030)
#define TX_MAX_CNT3             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x034)
#define TX_CTX_IDX3             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x038)
#define TX_DTX_IDX3             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x03C)

#define RX_BASE_PTR0            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x100)
#define RX_MAX_CNT0             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x104)
#define RX_CALC_IDX0            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x108)
#define RX_DRX_IDX0             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x10C)

#define RX_BASE_PTR1            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x110)
#define RX_MAX_CNT1             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x114)
#define RX_CALC_IDX1            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x118)
#define RX_DRX_IDX1             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x11C)

#define PDMA_INFO               (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x200)
#define PDMA_GLO_CFG            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x204)
#define PDMA_RST_IDX            (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x208)
#define PDMA_RST_CFG            (PDMA_RST_IDX)
#define DLY_INT_CFG             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x20C)
#define FREEQ_THRES             (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x210)
#define INT_STATUS              (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x220)
#define FE_INT_STATUS		(INT_STATUS)
#define INT_MASK                (RALINK_FRAME_ENGINE_BASE + PDMA_RELATED+0x228)
#define FE_INT_ENABLE		(INT_MASK)
#define SCH_Q01_CFG		(RALINK_FRAME_ENGINE_BASE+RAPDMA_OFFSET+0x280)
#define SCH_Q23_CFG		(RALINK_FRAME_ENGINE_BASE+RAPDMA_OFFSET+0x284)

#define FE_GLO_CFG          RALINK_FRAME_ENGINE_BASE + 0x08
#define FE_RST_GL           RALINK_FRAME_ENGINE_BASE + 0x0C
#define FE_INT_STATUS2	    RALINK_FRAME_ENGINE_BASE + 0x10
#define FE_INT_ENABLE2	    RALINK_FRAME_ENGINE_BASE + 0x14
#define FC_DROP_STA         RALINK_FRAME_ENGINE_BASE + 0x18
#define FOE_TS_T            RALINK_FRAME_ENGINE_BASE + 0x1C

#if defined (CONFIG_PDMA_NEW)
#define GDMA1_RELATED       0x0600
#define GDMA1_FWD_CFG       (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x00)
#define GDMA1_SHPR_CFG      (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x04)
#define GDMA1_MAC_ADRL      (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x08)
#define GDMA1_MAC_ADRH      (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x0C)
#else
#define GDMA1_RELATED       0x0020
#define GDMA1_FWD_CFG       (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x00)
#define GDMA1_SCH_CFG       (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x04)
#define GDMA1_SHPR_CFG      (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x08)
#define GDMA1_MAC_ADRL      (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x0C)
#define GDMA1_MAC_ADRH      (RALINK_FRAME_ENGINE_BASE + GDMA1_RELATED + 0x10)

#define GDMA2_RELATED       0x0060
#define GDMA2_FWD_CFG       (RALINK_FRAME_ENGINE_BASE + GDMA2_RELATED + 0x00)
#define GDMA2_SCH_CFG       (RALINK_FRAME_ENGINE_BASE + GDMA2_RELATED + 0x04)
#define GDMA2_SHPR_CFG      (RALINK_FRAME_ENGINE_BASE + GDMA2_RELATED + 0x08)
#define GDMA2_MAC_ADRL      (RALINK_FRAME_ENGINE_BASE + GDMA2_RELATED + 0x0C)
#define GDMA2_MAC_ADRH      (RALINK_FRAME_ENGINE_BASE + GDMA2_RELATED + 0x10)
#endif

#if defined (CONFIG_RALINK_MT7620)
#define PSE_RELATED         0x0500
#define PSE_FQFC_CFG        (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x00)
#define PSE_IQ_CFG          (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x04)
#define PSE_QUE_STA         (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x08)
#else
#define PSE_RELATED         0x0040
#define PSE_FQ_CFG          (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x00)
#define CDMA_FC_CFG         (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x04)
#define GDMA1_FC_CFG        (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x08)
#define GDMA2_FC_CFG        (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x0C)
#define CDMA_OQ_STA         (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x10)
#define GDMA1_OQ_STA        (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x14)
#define GDMA2_OQ_STA        (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x18)
#define PSE_IQ_STA          (RALINK_FRAME_ENGINE_BASE + PSE_RELATED + 0x1C)
#endif

#if defined (CONFIG_RALINK_MT7620)
#define CDMA_RELATED        0x0400
#define CDMA_CSG_CFG        (RALINK_FRAME_ENGINE_BASE + CDMA_RELATED + 0x00)
#define SMACCR0		    (RALINK_ETH_SW_BASE + 0x3FE4)
#define SMACCR1		    (RALINK_ETH_SW_BASE + 0x3FE8)
#define CKGCR               (RALINK_ETH_SW_BASE + 0x3FF0)
#else
#define CDMA_RELATED        0x0080
#define CDMA_CSG_CFG        (RALINK_FRAME_ENGINE_BASE + CDMA_RELATED + 0x00)
#define CDMA_SCH_CFG        (RALINK_FRAME_ENGINE_BASE + CDMA_RELATED + 0x04)
#define SMACCR0		    (RALINK_ETH_SW_BASE + 0x30E4)
#define SMACCR1		    (RALINK_ETH_SW_BASE + 0x30E8)
#define CKGCR               (RALINK_ETH_SW_BASE + 0x30F0)
#endif

#define PDMA_FC_CFG	    (RALINK_FRAME_ENGINE_BASE+0x100)
#endif

/*=========================================
      PDMA RX Descriptor Format define
=========================================*/

//-------------------------------------------------
typedef struct _PDMA_RXD_INFO1_  PDMA_RXD_INFO1_T;

struct _PDMA_RXD_INFO1_
{
    unsigned int    PDP0;
};
//-------------------------------------------------
typedef struct _PDMA_RXD_INFO2_    PDMA_RXD_INFO2_T;

struct _PDMA_RXD_INFO2_
{
    unsigned int    PLEN1                 : 14;
    unsigned int    LS1                   : 1;
    unsigned int    UN_USED               : 1;
    unsigned int    PLEN0                 : 14;
    unsigned int    LS0                   : 1;
    unsigned int    DDONE_bit             : 1;
};
//-------------------------------------------------
typedef struct _PDMA_RXD_INFO3_  PDMA_RXD_INFO3_T;

struct _PDMA_RXD_INFO3_
{
    unsigned int    UN_USE1;
};
//-------------------------------------------------
typedef struct _PDMA_RXD_INFO4_    PDMA_RXD_INFO4_T;

struct _PDMA_RXD_INFO4_
{
#if defined (CONFIG_PDMA_NEW)
    unsigned int    FOE_Entry           : 14;
    unsigned int    CRSN		: 5;
    unsigned int    SPORT		: 3;
    unsigned int    L4F			: 1;
    unsigned int    L4VLD		: 1;
    unsigned int    TACK		: 1;
    unsigned int    IP4F		: 1;
    unsigned int    IP4			: 1;
    unsigned int    IP6			: 1;
    unsigned int    UN_USE1		: 4;
#else
    unsigned int    FOE_Entry           : 14;
    unsigned int    FVLD                : 1;
    unsigned int    UN_USE1             : 1;
    unsigned int    AI                  : 8;
    unsigned int    SP                  : 3;
    unsigned int    AIS                 : 1;
    unsigned int    L4F                 : 1;
    unsigned int    IPF                  : 1;
    unsigned int    L4FVLD_bit           : 1;
    unsigned int    IPFVLD_bit           : 1;
#endif
};


struct PDMA_rxdesc {
	PDMA_RXD_INFO1_T rxd_info1;
	PDMA_RXD_INFO2_T rxd_info2;
	PDMA_RXD_INFO3_T rxd_info3;
	PDMA_RXD_INFO4_T rxd_info4;
};

/*=========================================
      PDMA TX Descriptor Format define
=========================================*/
//-------------------------------------------------
typedef struct _PDMA_TXD_INFO1_  PDMA_TXD_INFO1_T;

struct _PDMA_TXD_INFO1_
{
    unsigned int    SDP0;
};
//-------------------------------------------------
typedef struct _PDMA_TXD_INFO2_    PDMA_TXD_INFO2_T;

struct _PDMA_TXD_INFO2_
{
    unsigned int    SDL1                  : 14;
    unsigned int    LS1_bit               : 1;
    unsigned int    BURST_bit             : 1;
    unsigned int    SDL0                  : 14;
    unsigned int    LS0_bit               : 1;
    unsigned int    DDONE_bit             : 1;
};
//-------------------------------------------------
typedef struct _PDMA_TXD_INFO3_  PDMA_TXD_INFO3_T;

struct _PDMA_TXD_INFO3_
{
    unsigned int    SDP1;
};
//-------------------------------------------------
typedef struct _PDMA_TXD_INFO4_    PDMA_TXD_INFO4_T;

struct _PDMA_TXD_INFO4_
{

    unsigned int    VIDX                : 4;
    unsigned int    VPRI                : 3;
    unsigned int    INSV                : 1;
    unsigned int    SIDX                : 4;
    unsigned int    INSP                : 1;
#if defined (CONFIG_PDMA_NEW)
    unsigned int    RESV            	: 2;
    unsigned int    UDF            	: 5;
    unsigned int    FP_BMAP            	: 8;
    unsigned int    TSO			: 1;
    unsigned int    TCO                 : 1;
    unsigned int    UCO			: 1;
    unsigned int    ICO		        : 1;
#else
    unsigned int    RESV            	: 1;
    unsigned int    UN_USE3             : 2;
    unsigned int    QN                  : 3;
    unsigned int    UN_USE2             : 1;
    unsigned int    UDF			: 4;
    unsigned int    PN                  : 3;
    unsigned int    UN_USE1             : 1;
    unsigned int    TSO			: 1;
    unsigned int    TCO                 : 1;
    unsigned int    UCO			: 1;
    unsigned int    ICO		        : 1;
#endif
};

struct PDMA_txdesc {
	PDMA_TXD_INFO1_T txd_info1;
	PDMA_TXD_INFO2_T txd_info2;
	PDMA_TXD_INFO3_T txd_info3;
	PDMA_TXD_INFO4_T txd_info4;
};

struct slt_net_device
{
    unsigned int        tx_cpu_owner_idx0;
    unsigned int        rx_cpu_owner_idx0;
    unsigned int        fe_int_status;
    unsigned int        tx_full;
    unsigned int	phy_tx_ring0;
    unsigned int	phy_rx_ring0, phy_rx_ring1;

    struct		sk_buff*	   skb_free[NUM_TX_DESC];
    unsigned int	free_idx;

    struct PDMA_txdesc *tx_ring0;
    struct PDMA_rxdesc *rx_ring0;
    struct sk_buff     *netrx0_skbuf[NUM_RX_DESC];

#if defined (CONFIG_ETHTOOL) && defined (CONFIG_RAETH_ROUTER)
	//struct mii_if_info	mii_info;
#endif
};

struct ephy_l3r18_reg_s {
	unsigned char lp_eee_10g;
	unsigned char lp_eee_1000;
	unsigned char lp_eee_100;  
};


