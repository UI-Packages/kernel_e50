#ifndef PCM_H_
#define PCM_H_

#define SLT_PCM_TEST_TIME			2000
#define SLT_PCM_TEST_PACKET_NUM			50

#if defined (CONFIG_RALINK_MT7620)
#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/ioctl.h>
#include <asm/rt2880/rt_mmap.h>

//#define CONFIG_RALINK_PCM			y
//#define CONFIG_RALINK_PCM_SPICH		0
//#define CONFIG_RALINK_PCMRST_GPIO		0
//#define CONFIG_RALINK_PCMCHNUM		1
#define CONFIG_RALINK_PCMCHNUM			1
#define CONFIG_RALINK_PCMINTDIV			117
#define CONFIG_RALINK_PCMCOMPDIV		48
#define CONFIG_RALINK_PCMSLOTMODE		3
//#define CONFIG_RALINK_PCMGPIO			y
#define CONFIG_RALINK_PCMDIV			60

#define CONFIG_RALINK_PCMFRACDIV		1

#define phys_to_bus(a) (a & 0x1FFFFFFF)

#ifndef u32
#define u32 unsigned int
#endif

#ifndef u16
#define u16 unsigned short
#endif

#ifndef u8
#define u8 unsigned char
#endif

#ifndef REGBIT
#define REGBIT(x, n)		(x << n)
#endif

#define Virtual2Physical(x)             (((int)x) & 0x1fffffff)
#define Physical2Virtual(x)             (((int)x) | 0x80000000)
#define Virtual2NonCache(x)             (((int)x) | 0x20000000)
#define Physical2NonCache(x)            (((int)x) | 0xa0000000)

#define pcm_outw(address, value)	*((volatile uint32_t *)(address)) = cpu_to_le32(value)
#define pcm_inw(address)			le32_to_cpu(*(volatile u32 *)(address))

//#define PCM_DEBUG
#ifdef PCM_DEBUG
#define MSG(fmt, args...) printk("PCM_API: " fmt, ## args)
#else
#define MSG(fmt, args...) { }
#endif

/* Register Map, Ref to RT3052 Data Sheet */

/* System Controller bit field */
#define PCM_CLK_EN			7
#define PCM_CLK_SEL			6
#define	PCM_CLK_DIV			0

/* Register Map Detail */
#define PCM_GLBCFG				(RALINK_PCM_BASE+0x0000)
#define PCM_PCMCFG				(RALINK_PCM_BASE+0x0004)
#define PCM_INT_STATUS			(RALINK_PCM_BASE+0x0008)
#define PCM_INT_EN				(RALINK_PCM_BASE+0x000C)
#define PCM_FF_STATUS			(RALINK_PCM_BASE+0x0010)
#define PCM_CH0_CFG				(RALINK_PCM_BASE+0x0020)
#define PCM_CH1_CFG				(RALINK_PCM_BASE+0x0024)
#define PCM_RSV_REG16			(RALINK_PCM_BASE+0x0030)
#define PCM_FSYNC_CFG			(RALINK_PCM_BASE+0x0030)
#define PCM_CH_CFG2				(RALINK_PCM_BASE+0x0034)	
#define PCM_DIVINT_CFG			(RALINK_PCM_BASE+0x0054)
#define PCM_DIVCOMP_CFG			(RALINK_PCM_BASE+0x0050)
#define PCM_DIGDELAY_CFG		(RALINK_PCM_BASE+0x0060)
#define PCM_CH0_FIFO			(RALINK_PCM_BASE+0x0080)
#define PCM_CH1_FIFO			(RALINK_PCM_BASE+0x0084)

#define PCM_CHFF_STATUS(i)		(((i==0)||(i==1))? (RALINK_PCM_BASE+0x0010+((i)<<2)):\
								(RALINK_PCM_BASE+0x0110+((i-2)<<2)))
#define PCM_CH_CFG(i)			(((i==0)||(i==1))? (RALINK_PCM_BASE+0x0020+((i)<<2)):\
								(RALINK_PCM_BASE+0x0120+((i-2)<<2)))
#define PCM_CH_FIFO(i)			(RALINK_PCM_BASE+0x0080+((i)<<2))

/* PCMCFG bit field */
#define PCM_EXT_CLK_EN			31
#define PCM_CLKOUT				30
#define PCM_EXT_FSYNC			27
#define PCM_LONG_FSYNC			26
#define PCM_FSYNC_POL			25
#define PCM_DRX_TRI				24
#define PCM_SLOTMODE			0

/* GLBCFG bit field */
#define PCM_EN				31
#define DMA_EN				30
#if defined(CONFIG_RALINK_MT7620)
#define PCM_LBK             29
#define PCM_EXT_LBK         28
#endif
#define RFF_THRES			20
#define TFF_THRES			16
#define CH1_TX_EN			9
#define CH0_TX_EN			8
#define CH1_RX_EN			1
#if defined(CONFIG_RALINK_MT7620)
#define CH_EN               0
#else
#define CH0_RX_EN			0
#endif

/* CH0/1_CFG bit field */
#if !defined(CONFIG_RALINK_MT7620)
#define PCM_LBK					31
#define PCM_EXT_LBK				30
#endif
#if defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855) || defined (CONFIG_RALINK_MT7620)
#define PCM_CMP_MODE			27
#else
#define PCM_CMP_MODE			28
#endif
#define PCM_TS_START			0

/* INT_STATUS bit field */
#define CH1T_DMA_FAULT			15
#define CH1T_OVRUN				14
#define CH1T_UNRUN				13
#define CH1T_THRES				12
#define CH1R_DMA_FAULT			11
#define CH1R_OVRUN				10
#define CH1R_UNRUN				9
#define CH1R_THRES				8
#define CH0T_DMA_FAULT			7
#define CH0T_OVRUN				6
#define CH0T_UNRUN				5
#define CH0T_THRES				4
#define CH0R_DMA_FAULT			3
#define CH0R_OVRUN				2
#define CH0R_UNRUN				1
#define CH0R_THRES				0

/* INT_EN bit field */
#define INT15_EN				15
#define INT14_EN				14
#define INT13_EN				13
#define INT12_EN				12
#define INT11_EN				11
#define INT10_EN				10
#define INT9_EN					9
#define INT8_EN					8
#define INT7_EN					7
#define INT6_EN					6
#define INT5_EN					5
#define INT4_EN					4
#define INT3_EN					3
#define INT2_EN					2
#define INT1_EN					1
#define INT0_EN					0

/* FF_STATUS bit field */
#define CH1RFF_AVCNT			12
#define CH1TFF_AVCNT			8
#define CH0RFF_AVCNT			4
#define CH0TFF_AVCNT			0

/* PCM_CFG_FSYNC bit field */
#define CFG_FSYNC_EN			31
#define POP_SAMPLE				30
#define FSYNC_START				12
#define FSYNC_INTV				0

/* PCM_DIVCOMP_CFG bit field */
#define CLK_EN					31

/* Test scenario */
#define PCM_IN_CLK
//#define PCM_SLIC_LOOP
#define PCM_INLOOP
//#define PCM_EXLOOP
#define PCM_STATISTIC

#define PCM_LINEAR
//#define PCM_ULAW
//#define PCM_ALAW
//#define PCM_U2L2U
//#define PCM_A2L2A
//#define PCM_L2U2L
//#define PCM_L2A2L
//#define PCM_SW_L2U
//#define PCM_SW_L2A
#define PCM_TASKLET
#define PCM_RECORD
#define PCM_PLAYBACK
//#define PCM_SLIC_CLOCK
//#define PCM_SW_G729AB
//#define PCM_SW_CODEC
/* Constant definition */
#if defined(CONFIG_GDMA_PCM_I2S_OTHERS)
#define MAX_PCM_CH				1
#else
#define MAX_PCM_CH				CONFIG_RALINK_PCMCHNUM
#endif
#define NTFF_THRES				4
#define NRFF_THRES				4

#define MAX_CODEC_CH				MAX_PCM_CH

#define MAX_PCMMMAP_PAGE			6

#define CONFIG_PCM_CH				MAX_PCM_CH

#ifdef PCM_INLOOP
#define CONFIG_PCM_LBK				1
#define CONFIG_PCM_EXT_LBK			0
#else
#define CONFIG_PCM_LBK				0
#define CONFIG_PCM_EXT_LBK			0
#endif

#ifdef PCM_IN_CLK
#define CONFIG_PCM_EXT_CLK_EN			0
#define CONFIG_PCM_CLKOUT_EN			1	/* It should be always one */
#define CONFIG_PCM_EXT_FSYNC			0
#else
#define CONFIG_PCM_EXT_CLK_EN			0
#define CONFIG_PCM_CLKOUT_EN			1	/* It should be always one */
#define CONFIG_PCM_EXT_FSYNC			0
#endif

/* CMP_MODE setup */
#if defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855) || defined (CONFIG_RALINK_MT7620)

#ifdef PCM_LINEAR
#define CONFIG_PCM_CMP_MODE			0
#endif
#if	defined(PCM_ULAW)||defined(PCM_ALAW)
#define CONFIG_PCM_CMP_MODE			2
#endif
#ifdef PCM_L2U2L
#define CONFIG_PCM_CMP_MODE			4
#endif
#ifdef PCM_L2A2L
#define CONFIG_PCM_CMP_MODE			6
#endif
#ifdef PCM_U2L2U
#define CONFIG_PCM_CMP_MODE			5
#endif
#ifdef PCM_A2L2A
#define CONFIG_PCM_CMP_MODE			7
#endif

#else

#ifdef PCM_LINEAR
#define CONFIG_PCM_CMP_MODE			0
#endif
#if	defined(PCM_ULAW)||defined(PCM_ALAW)
#define CONFIG_PCM_CMP_MODE			1
#endif
#ifdef PCM_U2L2U
#define CONFIG_PCM_CMP_MODE			2
#endif
#ifdef PCM_A2L2A
#define CONFIG_PCM_CMP_MODE			3
#endif

#endif

#define CONFIG_PCM_LONG_FSYNC			0
#define CONFIG_PCM_FSYNC_POL			1
#define CONFIG_PCM_DRX_TRI			1
#define CONFIG_PCM_TS_START			1

#define CONFIG_PCM_TFF_THRES			NTFF_THRES
#define CONFIG_PCM_RFF_THRES			NRFF_THRES

typedef struct pcm_status_t
{
	u32 ch0txdmafault;
	u32 ch0txovrun;
	u32 ch0txunrun;
	u32 ch0txthres;
	u32 ch0rxdmafault;
	u32 ch0rxovrun;
	u32 ch0rxunrun;
	u32 ch0rxthres;

	u32 ch1txdmafault;
	u32 ch1txovrun;
	u32 ch1txunrun;
	u32 ch1txthres;
	u32 ch1rxdmafault;
	u32 ch1rxovrun;
	u32 ch1rxunrun;
	u32 ch1rxthres;

}pcm_status_type;

typedef struct pcm_config_t
{
	u32 pcm_ch_num;
	u32 codec_ch_num;
	u32 nch_active;
	int curchid,txcurchid;
	int txfifo_rd_idx[MAX_PCM_CH];
	int txfifo_wt_idx[MAX_PCM_CH];
	int rxfifo_rd_idx[MAX_PCM_CH];
	int rxfifo_wt_idx[MAX_PCM_CH];
	
	int bsfifo_rd_idx[MAX_PCM_CH];
	int bsfifo_wt_idx[MAX_PCM_CH];
	
	int rx_isr_cnt;
	int tx_isr_cnt;
	int pos;
	char* mmapbuf;
	int mmappos;
	int	mmap_rd_idx;
	int	mmap_wt_idx;
	int bStartRecord;
	int bStartPlayback;
	int iRecordCH;
	int	iPlaybackCH;
	int codec_type[MAX_CODEC_CH];
	
	
	u32 extclk_en;
	u32 clkout_en;
	u32 ext_fsync;
	u32 long_fynsc;
	u32 fsync_pol;
	u32 drx_tri;
	u32 slot_mode;

	u32 tff_thres;
	u32 rff_thres;

	u32	lbk[MAX_PCM_CH];
	u32 ext_lbk[MAX_PCM_CH];
	u32 ts_start[MAX_PCM_CH];
	u32 cmp_mode[MAX_PCM_CH];
#ifdef __KERNEL__	
	spinlock_t lock;
	spinlock_t txlock;
	spinlock_t rxlock;
	wait_queue_head_t	pcm_qh;
#endif	
	union {
		short* TxPage0Buf16Ptr[MAX_PCM_CH];	
		char* TxPage0Buf8Ptr[MAX_PCM_CH];
	};
	union {
		short* TxPage1Buf16Ptr[MAX_PCM_CH];	
		char* TxPage1Buf8Ptr[MAX_PCM_CH];
	};
	union {
		short* RxPage0Buf16Ptr[MAX_PCM_CH];	
		char* RxPage0Buf8Ptr[MAX_PCM_CH];	
	};
	union {
		short* RxPage1Buf16Ptr[MAX_PCM_CH];	
		char* RxPage1Buf8Ptr[MAX_PCM_CH];	
	};
	
	union {
		short* TxFIFOBuf16Ptr[MAX_PCM_CH];	
		char* TxFIFOBuf8Ptr[MAX_PCM_CH];	
	};
	
	union {
		short* RxFIFOBuf16Ptr[MAX_PCM_CH];	
		char* RxFIFOBuf8Ptr[MAX_PCM_CH];
	};
	
	union {
		short* BSFIFOBuf16Ptr[MAX_PCM_CH];	
		char* BSFIFOBuf8Ptr[MAX_PCM_CH];
	};

}pcm_config_type;


extern pcm_config_type* ppcm_config;
extern pcm_status_type* ppcm_status;

void pcm_rx_task(unsigned long pData);
void pcm_tx_task(unsigned long pData);


#define MAX_PCM_PROC_UNIT		3
#if	defined(PCM_ULAW)||defined(PCM_ALAW)||defined(PCM_U2L2U)||defined(PCM_A2L2A)
#define PCM_SAMPLE_SIZE			1
#else
#define PCM_SAMPLE_SIZE			2
#endif

#define PCM_8KHZ_SAMPLES		80

#define MAX_PCM_FIFO			12
#define PCM_FIFO_SAMPLES		(PCM_8KHZ_SAMPLES)
#define PCM_FIFO_SIZE			PCM_FIFO_SAMPLES*PCM_SAMPLE_SIZE

#define MAX_PCM_BSFIFO			12
#define PCM_BS_SIZE			166
#define PCM_BSFIFO_SIZE			(PCM_BS_SIZE*MAX_PCM_BSFIFO)

#define MAX_PCM_PAGE			1
#define PCM_PAGE_SAMPLES		(PCM_8KHZ_SAMPLES*MAX_PCM_PROC_UNIT)
#define PCM_PAGE_SIZE			PCM_PAGE_SAMPLES*PCM_SAMPLE_SIZE

/* driver status definition */
#define PCM_OK				0
#define PCM_OUTOFMEM			0x01
#define PCM_GDMAFAILED			0x02
#define PCM_REQUEST_IRQ_FAILED		0x04

/* driver i/o control command */
#define PCM_SET_RECORD			0
#define PCM_SET_UNRECORD		1	
#define PCM_READ_PCM			2
#define PCM_START			3
#define PCM_STOP			4
#define PCM_SET_PLAYBACK		5
#define PCM_SET_UNPLAYBACK		6
#define PCM_WRITE_PCM			7
#define PCM_SET_CODEC_TYPE		8
#define PCM_EXT_LOOPBACK_ON		9
#define PCM_EXT_LOOPBACK_OFF		10
#define PCM_PUTDATA			11
#define PCM_GETDATA			12

/* Qwert : Add for slic access */
#define PCM_SLIC_DRREAD		30
#define PCM_SLIC_IRREAD		31
#define PCM_SLIC_DRWRITE	32
#define PCM_SLIC_IRWRITE	33

typedef struct pcm_buffer_t
{
	char* pcmbuf;
	int size;
}pcm_record_type, pcm_playback_type;


#elif defined (CONFIG_RALINK_RT6855A)
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h> 
#include <linux/types.h>

#define M_SPI_RESET 		{_regSet(0xBFB00834, 0x800); udelay(200); _regSet(0xBFB00834, 0x0);}
#define M_PCM_RESET		{_regSet(0xBFB00834, 0x40000); udelay(200); _regSet(0xBFB00834, 0x0);}
#define M_PCM_ITR_DISABLE 	{_regSet(R_PCM_ITR_CTRL, 0x0);}
#define M_PCM_ITR_ENABLE 	{_regSet(R_PCM_ITR_CTRL, 0x1FC);}
#define M_DMA_TX_DISABLE	{_regSet(R_PCM_DMA_CTRL,  _regGet(R_PCM_DMA_CTRL) & ~(0x1));}
#define M_DMA_TX_ENABLE		{_regSet(R_PCM_DMA_CTRL,  _regGet(R_PCM_DMA_CTRL) | (0x1));}
#define M_DMA_RX_DISABLE	{_regSet(R_PCM_DMA_CTRL,  _regGet(R_PCM_DMA_CTRL) & ~(0x2));}
#define M_DMA_RX_ENABLE		{_regSet(R_PCM_DMA_CTRL,  _regGet(R_PCM_DMA_CTRL) | (0x2));}
#define M_PCM_SOFT_RST_OFF 	{_regSet(R_PCM_CTRL, \
							_regGet(R_PCM_CTRL) | (ML_PCM_CTRL_SOFT_RST << MS_PCM_CTRL_SOFT_RST));}
#define M_PCM_SOFT_RST_ON 	{_regSet(R_PCM_CTRL, \
							_regGet(R_PCM_CTRL) & ~(ML_PCM_CTRL_SOFT_RST << MS_PCM_CTRL_SOFT_RST));}

#define M_PCM_CONFIG_DONE 	{_regSet(R_PCM_CTRL, \
							_regGet(R_PCM_CTRL) | (ML_PCM_CTRL_CONFIG_SET << MS_PCM_CTRL_CONFIG_SET));}
#define M_PCM_CONFIG_SET 	{_regSet(R_PCM_CTRL, \
							_regGet(R_PCM_CTRL) & ~(ML_PCM_CTRL_CONFIG_SET << MS_PCM_CTRL_CONFIG_SET));}
	

#define PCM_CH_MAX		(8)
#define NUM_OF_CH		(2)
#define DMA_BUF_SZ		(2)
#define SAMPLE_SZ_10MS		(80)
#define SAMPLE_8BIT		(0)
#define SAMPLE_16BIT		(1)
#define SAMPLE_SZ		SAMPLE_16BIT
#define SAMPLE_SZ_LEN		(8 << SAMPLE_SZ)

/* System Control Register: For PCM/GPIO Sharing Control */
#define R_PCM_GPIO_SHARE		(0xBFB00860)

#define MS_PCM_GPIO_SHARE		(0)
#define ML_PCM_GPIO_SHARE		(0x1) 		/* 0: GPIO, 1:PCM */

#define MS_SPI_CS5_GPIO_SHARE		(5)
#define ML_SPI_CS5_GPIO_SHARE		(0x1) 		/* 0: GPIO, 1:SPI_CS */

/* PCM Register Addresses: R - Register */
#define R_PCM_BASEADDR		(0xBFBD0000)
#define R_PCM_CTRL		(R_PCM_BASEADDR + 0x00)
#define R_PCM_TX_SLOT_01	(R_PCM_BASEADDR + 0x04)
#define R_PCM_TX_SLOT_23	(R_PCM_BASEADDR + 0x08)
#define R_PCM_TX_SLOT_45	(R_PCM_BASEADDR + 0x0c)
#define R_PCM_TX_SLOT_67	(R_PCM_BASEADDR + 0x10)
#define R_PCM_RX_SLOT_01	(R_PCM_BASEADDR + 0x14)
#define R_PCM_RX_SLOT_23	(R_PCM_BASEADDR + 0x18)
#define R_PCM_RX_SLOT_45	(R_PCM_BASEADDR + 0x1c)
#define R_PCM_RX_SLOT_67	(R_PCM_BASEADDR + 0x20)
#define R_PCM_ITR_STAT		(R_PCM_BASEADDR + 0x24)
#define R_PCM_ITR_CTRL		(R_PCM_BASEADDR + 0x28)
#define R_PCM_TX_REQ		(R_PCM_BASEADDR + 0x2c)	/* Write any value to initiate Tx request */
#define R_PCM_RX_REQ		(R_PCM_BASEADDR + 0x30)	/* Write any value to initiate Rx request */
#define R_PCM_TX_DESC		(R_PCM_BASEADDR + 0x34)	/* 32-bit Tx Descriptor Base Address */
#define R_PCM_RX_DESC		(R_PCM_BASEADDR + 0x38)	/* 32-bit Rx Descriptor Base Address */
#define R_PCM_DESC_CTRL		(R_PCM_BASEADDR + 0x3c)
#define R_PCM_DMA_CTRL		(R_PCM_BASEADDR + 0x40)
#define R_PCM_DMA_BSWAP		(R_PCM_BASEADDR + 0x44)


/* PCM Register Control Bit Mask: MS - Mask Start (bit-th), ML - Mask Length (bits) */
#define MS_PCM_CTRL_CLK_SOURCE		(0) 
#define ML_PCM_CTRL_CLK_SOURCE		(0x1)		/* 0: Master, 1: Slave */
#define MS_PCM_CTRL_CLK_RATE		(1)
#define ML_PCM_CTRL_CLK_RATE		(0x7)		/* 0: 256K, 1: 512K, 2: 1024K, 3: 2048K, 4: 4096K, 5: 8192K */
#define MS_PCM_CTRL_FSYNC_RATE		(4)
#define ML_PCM_CTRL_FSYNC_RATE		(0x1)		/* 0: 8KHz, 1: 16KHz */
#define MS_PCM_CTRL_FSYNC_LEN		(8)
#define ML_PCM_CTRL_FSYNC_LEN		(0x3)		/* 0: 1 PCLK, 2: 8 PCLK, 3: 16: PCLK */
#define MS_PCM_CTRL_FSYNC_EDGE		(10)
#define ML_PCM_CTRL_FSYNC_EDGE		(0x1)		/* 0: Rising Edge, 1: Falling Edge */
#define MS_PCM_CTRL_DATA_CLK_EDGE	(11)
#define ML_PCM_CTRL_DATA_CLK_EDGE	(0x1)		/* 0: Rising Edge, 1: Falling Edge */		
#define MS_PCM_CTRL_DATA_FSYNC_EDGE	(12)
#define ML_PCM_CTRL_DATA_FSYNC_EDGE	(0x1)		/* 0: Rising Edge, 1: Falling Edge */
#define MS_PCM_CTRL_BIT_ORDER		(16)
#define ML_PCM_CTRL_BIT_ORDER		(0x1)		/* 0: LSB First, 1: MSB First */
#define MS_PCM_CTRL_BYTE_ORDER		(17)
#define ML_PCM_CTRL_BYTE_ORDER		(0x1)		/* 0: Little Endian, 1: Big Endian */
#define MS_PCM_CTRL_FRM_BND		(18)
#define ML_PCM_CTRL_FRM_BND		(0x1f)		/* (0~31)+1 Frames Boundary to trigger Interrupt */
#define MS_PCM_CTRL_SOFT_RST		(24)
#define ML_PCM_CTRL_SOFT_RST		(0x1)		/* 0: Reset, 1: Normal */
#define MS_PCM_CTRL_LOOPBACK		(25)
#define ML_PCM_CTRL_LOOPBACK		(0x1)		/* 0: Disable, 1: Enable */
#define MS_PCM_CTRL_CONFIG_SET		(26)
#define ML_PCM_CTRL_CONFIG_SET		(0x1)		/* 0: DMA Config Set, 1: DMA Config Done */

#define MS_PCM_SLOT_1ST_LEAD_BIT	(0)
#define ML_PCM_SLOT_1ST_LEAD_BIT	(0x3ff)		/* 0~512 bit-th*/
#define MS_PCM_SLOT_1ST_SAMPLE_SZ	(12)
#define ML_PCM_SLOT_1ST_SAMPLE_SZ	(0x1)		/* 0: 8-bit Sample, 1: 16-bit Sample */
#define MS_PCM_SLOT_2ND_LEAD_BIT	(16)
#define ML_PCM_SLOT_2ND_LEAD_BIT	(0x3ff)		/* 0~512 bit-th*/
#define MS_PCM_SLOT_2ND_SAMPLE_SZ	(28)
#define ML_PCM_SLOT_2ND_SAMPLE_SZ	(0x1)		/* 0: 8-bit Sample, 1: 16-bit Sample */

#define MS_ITR_FRM			(0)
#define ML_ITR_FRM			(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_TX_UPD			(2)
#define ML_ITR_TX_UPD			(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_RX_UPD			(3)
#define ML_ITR_RX_UPD			(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_TX_E_DESC		(4)
#define ML_ITR_TX_E_DESC		(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_RX_E_DESC		(5)
#define ML_ITR_RX_E_DESC		(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_TX_E_DMA			(6)
#define ML_ITR_TX_E_DMA			(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_RX_E_DMA			(7)
#define ML_ITR_RX_E_DMA			(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_AHB_ERR			(8)
#define ML_ITR_AHB_ERR			(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_FSYNC_OVT		(9)
#define ML_ITR_FSYNC_OVT		(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 
#define MS_ITR_FSYNC_ERR		(10)
#define ML_ITR_FSYNC_ERR		(0x1)		/* 0: Disable/No-interrupt, 1: Enable/Interrupt */ 

#define MS_PCM_DESC_SIZE 		(0)
#define ML_PCM_DESC_SIZE 		(0xf)		/* 0~8 Descriptors */
#define MS_PCM_DESC_OFFSET		(4)
#define ML_PCM_DESC_OFFSET		(0xf)		/* DWord (4-byte) offset, default: 9 */

#define MS_PCM_DMA_ENABLE_TX 		(0)
#define ML_PCM_DMA_ENABLE_TX		(0x1)		/* 0: Disable, 1: Enable */
#define MS_PCM_DMA_ENABLE_RX 		(1)
#define ML_PCM_DMA_ENABLE_RX		(0x1)		/* 0: Disable, 1: Enable */
#define MS_PCM_DMA_AHB_POL		(2)
#define ML_PCM_DMA_AHB_POL		(0x3)		/* 0: Round-robin, 2: Tx Fisrt, 3: Rx First */
#define MS_PCM_DMA_CH_SZ 		(24)
#define ML_PCM_DMA_CH_SZ 		(0xff)		/* 8-bit Mask for 8-ch, 0: Disable, 1: Enable */

#define MS_PCM_DMA_BSWAP		(0)
#define ML_PCM_DMA_BSWAP		(0x1)		/* 0: Byte Default, 1: Byte Swap */

#define MS_DESC_SAMPLE_SZ		(0)
#define ML_DESC_SAMPLE_SZ		(0x3ff)		/* 0~1024 !!!Samples!!! */
#define MS_DESC_CH_DATA_VALID		(16)			
#define ML_DESC_CH_DATA_VALID		(0xff)		/* 8-bit Mask for 8-ch, 0: Invalid, 1: Valid	 */		
#define MS_DESC_OWN_BY_DMA		(31)
#define ML_DESC_OWN_BY_DMA		(0x1)		/* 0: False, 1: True */

typedef enum {
	E_ITR_FRM_BND,
	E_ITR_RSV0,
	E_ITR_TX_UPD,
	E_ITR_RX_UPD,
	E_ITR_TX_E_DESC,
	E_ITR_RX_E_DESC,
	E_ITR_TX_E_DMA,
	E_ITR_RX_E_DMA,
	E_ITR_AHB_ERR,
	E_ITR_HUNT_OT,
	E_ITR_HUNT_ERR,

	E_ITR_INVALID
} interrupt_e;
#define ITR_SZ 	E_ITR_INVALID

typedef 	union {
	struct {
		uint32_t clkSource :1;
		uint32_t clkRate :3;
		uint32_t fsyncRate :1;
		uint32_t reserved0 :3;
		uint32_t fsyncLen :2;
		uint32_t fsyncEdge :1;
		uint32_t dataClkEdge :1;
		uint32_t dataFsyncEdge :1;
		uint32_t reserved1 :3;
		uint32_t bitOrder :1;
		uint32_t byteOrder :1;
		uint32_t frameBound :5;
		uint32_t reserved2 :1;
		uint32_t softRst :1;
		uint32_t loopback :1;
		uint32_t cfgSet :1;
		uint32_t reserved3 :1;
		uint32_t probing :3;
		uint32_t loopbackData :1;
	}bitField;

	uint32_t value;
} pcmCtrlReg_t;


typedef struct {
	dma_addr_t handle;
	void*	    buf;
	uint32_t	    size;
} dmaBuf_t;

typedef union {
	struct {
		uint32_t sampleSz		:10;
		uint32_t rsvd0			:6;
		uint32_t chanMask 		:8;
		uint32_t rsvd1 			:7;
		uint32_t ownByDma 	:1;
	} bitField;

	uint32_t value;	
} pcmDescCtrl_t;

typedef struct {
	pcmDescCtrl_t 	descCtrl;
	uint32_t			dmaBufAddr[PCM_CH_MAX];	
} pcmDesc_t;

typedef enum {
	E_PCM_CLK_SOURCE_MASTER,
	E_PCM_CLK_SOURCE_SLAVE
} pcmClkSource_e;

typedef enum {
	E_PCM_CLK_256K,
	E_PCM_CLK_512K,
	E_PCM_CLK_1024K,
	E_PCM_CLK_2048K,
	E_PCM_CLK_4096K,
	E_PCM_CLK_8192K
} pcmClk_e;

typedef enum {
	E_PCM_CLK_EDGE_RISING,
	E_PCM_CLK_EDGE_FALLING
} pcmClkEdge_e;

typedef enum {
	E_PCM_FSYNC_8K,
	E_PCM_FSYNC_16K
} pcmFsync_e;

typedef enum {
	E_PCM_FSYNC_EDGE_RISING,
	E_PCM_FSYNC_EDGE_FALLING
} pcmFsyncEdge_e;

typedef enum {
	E_PCM_FSYNC_LEN_1CLK = 0,
	E_PCM_FSYNC_LEN_8CLK = 2,
	E_PCM_FSYNC_LEN_16CLK = 3
} pcmFsyncLen_e;

typedef enum {
	E_PCM_SAMPLE_8BIT,
	E_PCM_SAMPLE_16BIT
} pcmSample_e;

typedef enum {
	E_PCM_BYTE_ORDER_LSB,
	E_PCM_BYTE_ORDER_MSB
} pcmByteOrder_e;

typedef enum {
	E_PCM_BIT_ORDER_LSB,
	E_PCM_BIT_ORDER_MSB
} pcmBitOrder_e;

typedef enum {
	E_PCM_DMA_BYTE_DEFAULT,
	E_PCM_DMA_BYTE_SWAP
} pcmDmaBSwap_e;

typedef enum {
	E_PCM_LOOPBACK_DISABLE,
	E_PCM_LOOPBACK_ENABLE
} pcmLookback_e;

typedef enum {
	E_PCM_SOFT_RST_ON,
	E_PCM_SOFT_RST_OFF
} pcmSoftRst_e;

typedef enum {
	E_PCM_CONFIG_SET,
	E_PCM_CONFIG_DONE
} pcmConfig_e;

typedef enum {
	E_PCM_STATE_INACTIVE,
	E_PCM_STATE_ACTIVE
} pcmState_e;

typedef struct {
	pcmState_e		pcmActiveState;

	pcmClkSource_e	pcmClkSource;
	pcmClk_e			pcmClkRate;
	pcmFsync_e 		pcmFsynRate;
	pcmFsyncLen_e	pcmFsyncLen;
	
	pcmClkEdge_e		pcmFsyncEdge;
	pcmClkEdge_e		pcmDataClkEdge;
	pcmFsyncEdge_e	pcmDataFsyncEdge;
	
	pcmByteOrder_e	pcmByteOrder;
	pcmBitOrder_e	pcmBitOrder;
	pcmDmaBSwap_e	pcmDmaBSwap;

	pcmLookback_e	pcmLoopback;
} pcmConfig_t;


void pcmIsrTH(void);
void pcmStop(void);
void pcmStart(void);
void pcmRxRead(void *pBuf);
void pcmTxWrite(void *pBuf);

void pcmReset(void);
void pcmInit(void);
void pcmExit(void);
#endif

#endif /* PCM_H */

