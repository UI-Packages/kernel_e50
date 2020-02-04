#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/slab.h> 
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/pci.h>

#include <asm/uaccess.h>
#include <asm/io.h>

#include <asm/rt2880/surfboardint.h>

#include "pcm_test.h"
#include "slt.h"

#if defined (CONFIG_RALINK_MT7620)
#include "../../../../drivers/char/ralink_gpio.h"
#include "../../../../drivers/char/ralink_gdma.h"
#endif


#if defined (CONFIG_RALINK_RT6855A)
static pcmCtrlReg_t _gPcmCtrlReg = {
	.bitField.clkSource 		= E_PCM_CLK_SOURCE_MASTER,
	.bitField.clkRate 		= E_PCM_CLK_2048K,
	.bitField.fsyncRate 		= E_PCM_FSYNC_8K,
	.bitField.reserved0 		= 0,
	.bitField.fsyncLen 		= E_PCM_FSYNC_LEN_1CLK,
	.bitField.fsyncEdge 		= E_PCM_CLK_EDGE_RISING,
	.bitField.dataClkEdge 		= E_PCM_CLK_EDGE_RISING,
	.bitField.dataFsyncEdge 	= E_PCM_FSYNC_EDGE_FALLING,
	.bitField.reserved1 		= 0,
	.bitField.bitOrder 		= E_PCM_BIT_ORDER_MSB,
	.bitField.byteOrder 		= E_PCM_BYTE_ORDER_LSB,
	.bitField.frameBound 		= 1,
	.bitField.reserved3 		= 0,
	.bitField.softRst 		= E_PCM_SOFT_RST_OFF,
	.bitField.loopback 		= E_PCM_LOOPBACK_DISABLE,
	.bitField.cfgSet 		= E_PCM_CONFIG_DONE,
	.bitField.reserved2 		= 0,
	.bitField.probing 		= 7,
	.bitField.loopbackData 	= 1
};

pcmDesc_t *_gPcmDescTx;
pcmDesc_t *_gPcmDescRx;

dma_addr_t _gDescTxHdl;
dma_addr_t _gDescRxHdl;

dmaBuf_t _gDmaBufTx[DMA_BUF_SZ][NUM_OF_CH];
dmaBuf_t _gDmaBufRx[DMA_BUF_SZ][NUM_OF_CH];

static uint16_t _txBuf[NUM_OF_CH][SAMPLE_SZ_10MS];
static uint16_t _rxBuf[NUM_OF_CH][SAMPLE_SZ_10MS];

static int _flagDMA = 0;
static int _IsrTHCnt = 0;
static int inloopback = 0;
unsigned slt_pcm_tx_count = 0;
unsigned slt_pcm_rx_count = 0;

uint16_t tone1K[80] = {
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3,
 0x0000, 0x2d5d, 0x4026, 0x2d5c, 0x0000, 0xd2a3, 0xbfda, 0xd2a3
};

static uint32_t _regGet(uint32_t addr) 
{
	return *(volatile unsigned long int *)(addr);
}	

static void _regSet(uint32_t addr, uint32_t value) 
{
	*(volatile unsigned long int *)(addr) = value;
}

void pcmIsrTH(void) 
{
	uint32_t interrupt = _regGet(R_PCM_ITR_STAT);

	if ((interrupt & (1 << E_ITR_RX_UPD)) && (_IsrTHCnt < 200)) {
		pcmTxWrite((void*)_txBuf);
		pcmRxRead((void*)_rxBuf);
	}

	_IsrTHCnt++;
}

void pcmRxRead(void *pBuf) 
{
	int i, j;
	int k;

	for (i = 0; i < DMA_BUF_SZ; i++) {
		if (!(_gPcmDescRx[i].descCtrl.bitField.ownByDma))  {
			for (j = 0; j < NUM_OF_CH; j++) {
				if (_IsrTHCnt > 8) {
					uint16_t *pDmaBufRx = (uint16_t *)_gDmaBufRx[i][j].buf;

					for (k = 0; k < (_gDmaBufRx[i][j].size >> 1); k++) {
						if (pDmaBufRx[k] != tone1K[k]) {
							printk("[%X vs %X](%d)(isr=%d)\n",(uint16_t)pDmaBufRx[k], tone1K[k],k,_IsrTHCnt);
							inloopback++;
							break;
						}
						else
							/* byte count */
							slt_pcm_rx_count += 2;
					}
				}
			}
			_gPcmDescRx[i].descCtrl.bitField.ownByDma = 1;

			_flagDMA = i;
			break;
		}
	}	
}

void pcmTxWrite(void *pBuf) 
{
	int j;

	if (!(_gPcmDescTx[_flagDMA].descCtrl.bitField.ownByDma)) {
		for (j = 0; j < NUM_OF_CH; j++)
			memcpy(_gDmaBufTx[_flagDMA][j].buf, tone1K, _gDmaBufTx[_flagDMA][j].size);

		if (_IsrTHCnt > 8)
			slt_pcm_tx_count += (NUM_OF_CH * _gDmaBufTx[_flagDMA][j].size);
		_gPcmDescTx[_flagDMA].descCtrl.bitField.ownByDma = 1;
	}
	_regSet(R_PCM_TX_REQ, 0x1);	
}

void pcmStop(void) 
{
	M_PCM_ITR_DISABLE
	M_DMA_RX_DISABLE
	M_DMA_TX_DISABLE
}

void pcmStart(void) 
{
	M_PCM_ITR_ENABLE
	M_DMA_RX_ENABLE
	M_DMA_TX_ENABLE

	_regSet(R_PCM_RX_REQ, 0x1);

}

void pcmReset(void) 
{
	int i; 
	uint32_t tmp, val;
              
	M_PCM_SOFT_RST_ON
	udelay(200);
	M_PCM_SOFT_RST_OFF

	_regSet(R_PCM_TX_DESC, _gDescTxHdl);
	_regSet(R_PCM_RX_DESC, _gDescRxHdl);

	_regSet(R_PCM_DESC_CTRL, ((sizeof(pcmDesc_t) >> 2) << MS_PCM_DESC_OFFSET) | (DMA_BUF_SZ << MS_PCM_DESC_SIZE));
	_regSet(R_PCM_DMA_CTRL, ((1 << NUM_OF_CH) -1) << MS_PCM_DMA_CH_SZ);
	
  for (i = 0; i < NUM_OF_CH; i++) {
    tmp = _regGet(R_PCM_TX_SLOT_01 + ((i >> 1) << 2)) & (0xFFFF << (((i+1) & 1) << 4));
    val = ((i * SAMPLE_SZ_LEN) << MS_PCM_SLOT_1ST_LEAD_BIT) | (SAMPLE_SZ << MS_PCM_SLOT_1ST_SAMPLE_SZ);

    _regSet(R_PCM_TX_SLOT_01 + ((i >> 1) << 2),  tmp | (val << ((i&1) << 4)));
  	_regSet(R_PCM_RX_SLOT_01 + ((i >> 1) << 2),  _regGet(R_PCM_TX_SLOT_01 + ((i >> 1) << 2)));
	}

	_regSet(R_PCM_CTRL, _gPcmCtrlReg.value);

	M_PCM_CONFIG_SET
	udelay(200);
	M_PCM_CONFIG_DONE
	
	_IsrTHCnt = 0;
	
}

void pcmInit(void) 
{
	int i, j;

	memset(_txBuf, 0, sizeof(_txBuf));
	memset(_rxBuf, 0, sizeof(_rxBuf));

	_gPcmDescTx = dma_alloc_coherent(NULL, sizeof(pcmDesc_t) * DMA_BUF_SZ, &(_gDescTxHdl), GFP_KERNEL);
	_gPcmDescRx = dma_alloc_coherent(NULL, sizeof(pcmDesc_t) * DMA_BUF_SZ, &(_gDescRxHdl), GFP_KERNEL);

	for (i = 0;i < DMA_BUF_SZ; i++) {
		_gPcmDescTx[i].descCtrl.bitField.sampleSz	= _gPcmDescRx[i].descCtrl.bitField.sampleSz 	= SAMPLE_SZ_10MS;
		_gPcmDescTx[i].descCtrl.bitField.rsvd0	 	= _gPcmDescRx[i].descCtrl.bitField.rsvd0	 	= 0;
		_gPcmDescTx[i].descCtrl.bitField.chanMask = _gPcmDescRx[i].descCtrl.bitField.chanMask 	= (1 << NUM_OF_CH) - 1;
		_gPcmDescTx[i].descCtrl.bitField.rsvd1	 	= _gPcmDescRx[i].descCtrl.bitField.rsvd1	 	= 0;
		//_gPcmDescTx[i].descCtrl.bitField.ownByDma = 0;
		//_gPcmDescRx[i].descCtrl.bitField.ownByDma = 0;
		_gPcmDescTx[i].descCtrl.bitField.ownByDma 	= _gPcmDescRx[i].descCtrl.bitField.ownByDma = 1;

		for (j = 0;j < NUM_OF_CH; j++) {
			_gDmaBufTx[i][j].size = _gDmaBufRx[i][j].size = SAMPLE_SZ_10MS << 1;
			
			_gDmaBufTx[i][j].buf = dma_alloc_coherent(NULL, _gDmaBufTx[i][j].size, &(_gDmaBufTx[i][j].handle), GFP_KERNEL);
			_gPcmDescTx[i].dmaBufAddr[j] = (_gDmaBufTx[i][j].handle);

			_gDmaBufRx[i][j].buf = dma_alloc_coherent(NULL, _gDmaBufRx[i][j].size, &(_gDmaBufRx[i][j].handle), GFP_KERNEL);
			_gPcmDescRx[i].dmaBufAddr[j] = (_gDmaBufRx[i][j].handle);
		}
	}

	M_SPI_RESET
	M_PCM_RESET

	pcmStop();
	udelay(100);
	pcmReset();
}

void pcmExit(void) 
{
	int i, j;

	dma_free_coherent(NULL, sizeof(pcmDesc_t) * DMA_BUF_SZ, _gPcmDescTx, _gDescTxHdl);
	dma_free_coherent(NULL, sizeof(pcmDesc_t) * DMA_BUF_SZ, _gPcmDescRx, _gDescRxHdl);

	for (i = 0;i < DMA_BUF_SZ; i++) {
		for (j = 0;j < NUM_OF_CH; j++) {
			dma_free_coherent(NULL, _gDmaBufTx[i][j].size, _gDmaBufTx[i][j].buf, _gDmaBufTx[i][j].handle);
			dma_free_coherent(NULL, _gDmaBufRx[i][j].size, _gDmaBufRx[i][j].buf, _gDmaBufRx[i][j].handle);
		}
	}

}

static irqreturn_t pcmIsr(int irq, void *devId) 
{
	pcmIsrTH();
	return IRQ_HANDLED;
}

int pcmDriverInit(void) 
{
	int err = 0;

	pcmInit();
	err = request_irq(SURFBOARDINT_PCM, pcmIsr, 0, "PCM", NULL);
	
	if (err) {
		printk(KERN_INFO "request irq fail \n");
		return err;
	}

	pcmStart();

	return 0;
}

void pcmDriverExit(void) 
{
	pcmStop();
	free_irq(SURFBOARDINT_PCM, NULL);
	pcmExit();
}

int pcm_init(void);
int do_pcm(unsigned int cmd);


#elif defined(CONFIG_RALINK_MT7620)

int bPassed = CONFIG_PCM_CH * MAX_PCM_PROC_UNIT;

pcm_config_type* ppcm_config;
pcm_status_type* ppcm_status;

int pcm_clock_setup(void);
int pcm_clock_enable(void);
int pcm_clock_disable(void);
int pcm_open(void);
int pcm_close(void);
int pcm_reg_setup(pcm_config_type* ptrpcm_config); 
int pcm_enable(unsigned int chid, pcm_config_type* ptrpcm_config);
int pcm_disable(unsigned int chid, pcm_config_type* ptrpcm_config);

void pcm_dma_tx_isr(u32 chid);
void pcm_dma_rx_isr(u32 chid);
void pcm_unmask_isr(u32 dma_ch);

void pcm_dump_reg (void);

static irqreturn_t pcm_irq_isr(int irq, void *irqaction);

static dma_addr_t TxPage0[CONFIG_PCM_CH], TxPage1[CONFIG_PCM_CH];
static dma_addr_t RxPage0[CONFIG_PCM_CH], RxPage1[CONFIG_PCM_CH];

#ifdef PCM_TASKLET
struct tasklet_struct pcm_rx_tasklet;
struct tasklet_struct pcm_tx_tasklet;
#endif

unsigned int idiv = CONFIG_RALINK_PCMINTDIV;
unsigned int cdiv = CONFIG_RALINK_PCMCOMPDIV;
unsigned int smode = CONFIG_RALINK_PCMSLOTMODE;

int pcm_init(void)
{
	//MSG("PCMRST map to GPIO%d\n", CONFIG_RALINK_PCMRST_GPIO);
	MSG("Total %d PCM channel number supported\n", MAX_PCM_CH);
#if defined(CONFIG_RALINK_PCMEXTCLK) 	
	MSG("PCMCLK clock source from SoC external OSC\n");
#else
	MSG("PCMCLK clock source from SoC internal clock\n");	
#endif

#if defined(CONFIG_RALINK_PCMFRACDIV)	
	MSG("PCMCLK clock dividor Int[%d], Comp[%d]\n", idiv, cdiv);
#else
	MSG("PCMCLK clock dividor [%d]\n", CONFIG_RALINK_PCMDIV);	
#endif	
	MSG("PCM slot mode is %d\n", smode);
		
	pcm_open();	

	return 0;
}

void pcm_exit(void)
{
	pcm_close();
	
	return ;
}

int pcm_open(void)
{
	int i, data;
	unsigned long flags;
	
	/* set pcm_config */
	ppcm_config = (pcm_config_type*)kmalloc(sizeof(pcm_config_type), GFP_KERNEL);
	if(ppcm_config==NULL)
		return PCM_OUTOFMEM;
	memset(ppcm_config, 0, sizeof(pcm_config_type));

	ppcm_config->pcm_ch_num = CONFIG_PCM_CH;
	ppcm_config->codec_ch_num = MAX_CODEC_CH;
	ppcm_config->nch_active = 0;
	ppcm_config->extclk_en = CONFIG_PCM_EXT_CLK_EN;
	ppcm_config->clkout_en = CONFIG_PCM_CLKOUT_EN;
	ppcm_config->ext_fsync = CONFIG_PCM_EXT_FSYNC;
	ppcm_config->long_fynsc = CONFIG_PCM_LONG_FSYNC;
	ppcm_config->fsync_pol = CONFIG_PCM_FSYNC_POL;
	ppcm_config->drx_tri = CONFIG_PCM_DRX_TRI;
	ppcm_config->slot_mode = smode;//CONFIG_RALINK_PCMSLOTMODE;
	
	ppcm_config->tff_thres = CONFIG_PCM_TFF_THRES;
	ppcm_config->rff_thres = CONFIG_PCM_RFF_THRES;
		
	for ( i = 0 ; i < ppcm_config->pcm_ch_num; i ++ )
	{
		ppcm_config->lbk[i] = CONFIG_PCM_LBK;
		ppcm_config->ext_lbk[i] = CONFIG_PCM_EXT_LBK;
		ppcm_config->cmp_mode[i] = CONFIG_PCM_CMP_MODE;
		ppcm_config->ts_start[i] = CONFIG_PCM_TS_START + i*16;	
		ppcm_config->txfifo_rd_idx[i] = 0;
		ppcm_config->txfifo_wt_idx[i] = 0;
		ppcm_config->rxfifo_rd_idx[i] = 0;
		ppcm_config->rxfifo_wt_idx[i] = 0;
		ppcm_config->bsfifo_rd_idx[i] = 0;
		ppcm_config->bsfifo_wt_idx[i] = 0;

	}

	MSG("allocate fifo buffer\n");
	/* allocate fifo buffer */
	for ( i = 0 ; i < ppcm_config->pcm_ch_num; i ++ )
	{
		ppcm_config->TxFIFOBuf16Ptr[i] = kmalloc(PCM_FIFO_SIZE*MAX_PCM_FIFO, GFP_KERNEL);
		if(ppcm_config->TxFIFOBuf16Ptr[i]==NULL)
		{
			pcm_close();
			return PCM_OUTOFMEM;
		}

		ppcm_config->RxFIFOBuf16Ptr[i] = kmalloc(PCM_FIFO_SIZE*MAX_PCM_FIFO, GFP_KERNEL);
		if(ppcm_config->RxFIFOBuf16Ptr[i]==NULL)
		{
			pcm_close();
			return PCM_OUTOFMEM;
		} 		
	}
	MSG("allocate page buffer\n");
	/* allocate page buffer */
	for ( i = 0 ; i < ppcm_config->pcm_ch_num; i ++ )
	{
		ppcm_config->TxPage0Buf16Ptr[i] = pci_alloc_consistent(NULL, PCM_PAGE_SIZE , &TxPage0[i]);
		if(ppcm_config->TxPage0Buf16Ptr[i]==NULL)
		{
			pcm_close();
			return PCM_OUTOFMEM;
		}
		ppcm_config->TxPage1Buf16Ptr[i] = pci_alloc_consistent(NULL, PCM_PAGE_SIZE , &TxPage1[i]);
		if(ppcm_config->TxPage1Buf16Ptr[i]==NULL)
		{
			pcm_close();
			return PCM_OUTOFMEM;
		}
		ppcm_config->RxPage0Buf16Ptr[i] = pci_alloc_consistent(NULL, PCM_PAGE_SIZE , &RxPage0[i]);
		if(ppcm_config->RxPage0Buf16Ptr[i]==NULL)
		{
			pcm_close();
			return PCM_OUTOFMEM;
		}
		ppcm_config->RxPage1Buf16Ptr[i] = pci_alloc_consistent(NULL, PCM_PAGE_SIZE , &RxPage1[i]);
		if(ppcm_config->RxPage1Buf16Ptr[i]==NULL)
		{
			pcm_close();
			return PCM_OUTOFMEM;
		}
	}
	
	/* PCM controller reset */
	data = pcm_inw(RALINK_SYSCTL_BASE+0x34);
	data |= 0x00000800;
	pcm_outw(RALINK_SYSCTL_BASE+0x34,data);
	data = pcm_inw(RALINK_SYSCTL_BASE+0x34);
	data &= 0xFFFFF7FF;
	pcm_outw(RALINK_SYSCTL_BASE+0x34,data);
	for(i=0;i<100000;i++);
	
	data = pcm_inw(RALINK_SYSCTL_BASE+0x34);
	data |= 0x00040000;
	pcm_outw(RALINK_SYSCTL_BASE+0x34, data);
	data = pcm_inw(RALINK_SYSCTL_BASE+0x34);
	data &= 0xFFFBFFFF;
	pcm_outw(RALINK_SYSCTL_BASE+0x34,data);

	/* Set UARTF_SHARE_MODE field */	
	data = pcm_inw(RALINK_REG_GPIOMODE);
	data &= 0xFFFFFFE1;

	pcm_outw(RALINK_REG_GPIOMODE, data);
	/* PCM/I2S mode */
	data |= 0x00000008;

	pcm_outw(RALINK_REG_GPIOMODE, data);
	MSG("RALINK_REG_GPIOMODE=0x%08X\n",data);

	if(pcm_reg_setup(ppcm_config)!=PCM_OK)
		MSG("PCM:pcm_reg_setup() failed\n");
	
	pcm_clock_setup();
	
	spin_lock_irqsave(&ppcm_config->lock, flags);

	data = pcm_inw(PCM_GLBCFG);
	data |= REGBIT(0x1, PCM_EN);
	pcm_outw(PCM_GLBCFG, data);
	
	pcm_clock_enable();
		
	spin_unlock_irqrestore(&ppcm_config->lock, flags);

	MSG("pcm_open done...\n");

	return PCM_OK;
}

int pcm_reg_setup(pcm_config_type* ptrpcm_config)
{
	unsigned int data = 0;
	int i;	
	/* set GLBCFG's threshold fields */

	data = pcm_inw(PCM_GLBCFG);
#if defined (CONFIG_RALINK_MT7620)
	//data |= REGBIT(CONFIG_PCM_LBK, PCM_LBK);
	data &= ~(REGBIT(CONFIG_PCM_LBK, PCM_LBK));
#else
#endif	
	data |= REGBIT(ptrpcm_config->tff_thres, TFF_THRES);
	data |= REGBIT(ptrpcm_config->rff_thres, RFF_THRES);
	data |= REGBIT(1, PCM_LBK);
	/* michael */
	data &= ~(0x1 << 29);
	pcm_outw(PCM_GLBCFG, data);
	
	/* set PCMCFG */
	data = pcm_inw(PCM_PCMCFG);
	data |= REGBIT(ptrpcm_config->ext_fsync, PCM_EXT_FSYNC);
	data |= REGBIT(ptrpcm_config->long_fynsc, PCM_LONG_FSYNC);
	data |= REGBIT(ptrpcm_config->fsync_pol, PCM_FSYNC_POL);
	data |= REGBIT(ptrpcm_config->drx_tri, PCM_DRX_TRI);
	data &=  ~REGBIT(0x7, PCM_SLOTMODE);
	data |= REGBIT(ptrpcm_config->slot_mode, PCM_SLOTMODE);
	//data |= REGBIT(ptrpcm_config->clkout_en, PCM_CLKOUT);
	MSG("PCM_PCMCFG=0x%08X\n",data);
	pcm_outw(PCM_PCMCFG, data);
#if defined(CONFIG_RALINK_MT7620)
	for (i = 0; i < CONFIG_PCM_CH; i++)
	{
		data = pcm_inw(PCM_CH_CFG(i));
		data &= ~REGBIT(0x7, PCM_CMP_MODE);
		data &= ~REGBIT(0x3FF, PCM_TS_START);
		data |= REGBIT(ptrpcm_config->cmp_mode[i], PCM_CMP_MODE);
		data |= REGBIT(ptrpcm_config->ts_start[i], PCM_TS_START);
		MSG("PCM_CH_CFG(%d)=0x%08X\n",i,data);
		pcm_outw(PCM_CH_CFG(i), data);
	}  
#else	
	/* set CH0/1_CFG */	
	data = pcm_inw(PCM_CH0_CFG);
	data |= REGBIT(ptrpcm_config->lbk[0], PCM_LBK);
	data |= REGBIT(ptrpcm_config->ext_lbk[0], PCM_EXT_LBK);
	data |= REGBIT(ptrpcm_config->cmp_mode[0], PCM_CMP_MODE);
	data |= REGBIT(ptrpcm_config->ts_start[0], PCM_TS_START);
	MSG("PCM_CH0_CFG=0x%08X\n",data);
	pcm_outw(PCM_CH0_CFG, data);

	data = pcm_inw(PCM_CH1_CFG);
	data |= REGBIT(ptrpcm_config->lbk[1], PCM_LBK);
	data |= REGBIT(ptrpcm_config->ext_lbk[1], PCM_EXT_LBK);
	data |= REGBIT(ptrpcm_config->cmp_mode[1], PCM_CMP_MODE);
	data |= REGBIT(ptrpcm_config->ts_start[1], PCM_TS_START);
	MSG("PCM_CH1_CFG=0x%08X\n",data);
	pcm_outw(PCM_CH1_CFG, data);
#endif

#if defined(CONFIG_RALINK_RT3352) || defined(CONFIG_RALINK_RT5350) || defined (CONFIG_RALINK_RT6855) \
	|| defined(CONFIG_RALINK_MT7620)
	data = pcm_inw(PCM_DIGDELAY_CFG);
	data = 0x00008484;
	MSG("PCM_DIGDELAY_CFG=0x%08X\n",data);
	pcm_outw(PCM_DIGDELAY_CFG, data);
#endif
	
	return PCM_OK;
}

int pcm_clock_setup(void)
{
	unsigned long data;

#if defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT5350) \
	|| defined (CONFIG_RALINK_RT6855) || defined(CONFIG_RALINK_MT7620)
	MSG("PCM: enable fractinal PCM_CLK\n");
	pcm_outw(PCM_DIVINT_CFG, idiv);
	pcm_outw(PCM_DIVCOMP_CFG, cdiv|0x80000000);
#else	
	/* System controller PCMCLK_DIV set */
	data = pcm_inw(RALINK_SYSCTL_BASE+0x30);

#if defined(CONFIG_RALINK_PCMEXTCLK)
	data |= REGBIT(1, PCM_CLK_SEL);
#else
	data &= ~REGBIT(1, PCM_CLK_SEL);
#endif	
	data |= REGBIT(1, PCM_CLK_EN);	
	data &= 0xFFFFFFC0;
	data |= REGBIT(CONFIG_RALINK_PCMDIV, PCM_CLK_DIV);
	data |= 0x00000080;
	
	pcm_outw(RALINK_SYSCTL_BASE+0x30, data);
	MSG("RALINK_SYSCTL_BASE+0x30=0x%08X\n",(u32)data);	
#endif	
	
	/* set PCMCFG external PCMCLK control bit */
	data = pcm_inw(PCM_PCMCFG);
#if defined(CONFIG_RALINK_PCMEXTCLK)
	data |= REGBIT(1, PCM_EXT_CLK_EN);
#else
	data &= ~REGBIT(1, PCM_EXT_CLK_EN);
#endif	
	pcm_outw(PCM_PCMCFG, data);
	
	return 0;	
}

int pcm_clock_enable(void)
{
	unsigned long data;
	/* set PCMCFG clock out bit */
	data = pcm_inw(PCM_PCMCFG);	
	data |= REGBIT(1,  PCM_CLKOUT);
	pcm_outw(PCM_PCMCFG, data);
	
	return 0;	
}

int pcm_clock_disable(void)
{
	unsigned long data;
	/* set PCMCFG clock out bit */
	data = pcm_inw(PCM_PCMCFG);	
	data &= ~REGBIT(1,  PCM_CLKOUT);
	pcm_outw(PCM_PCMCFG, data);
	
	return 0;	
}
	
int pcm_close(void)
{
	int i;
		
	MSG("pcm_close\n");	

	for( i = 0 ; i < ppcm_config->pcm_ch_num ; i ++ )
		pcm_disable(i, ppcm_config);
	
	
	/* free buffer */
	for( i = 0 ; i < ppcm_config->pcm_ch_num ; i ++ )
	{
		if(ppcm_config->TxPage0Buf16Ptr[i])
			pci_free_consistent(NULL, PCM_PAGE_SIZE, (void*)ppcm_config->TxPage0Buf16Ptr[i], TxPage0[i]);
		if(ppcm_config->TxPage1Buf16Ptr[i])
			pci_free_consistent(NULL, PCM_PAGE_SIZE, (void*)ppcm_config->TxPage1Buf16Ptr[i], TxPage1[i]);	
		if(ppcm_config->RxPage0Buf16Ptr[i])
			pci_free_consistent(NULL, PCM_PAGE_SIZE, (void*)ppcm_config->RxPage0Buf16Ptr[i], RxPage0[i]);
		if(ppcm_config->RxPage1Buf16Ptr[i])
			pci_free_consistent(NULL, PCM_PAGE_SIZE, (void*)ppcm_config->RxPage1Buf16Ptr[i], RxPage1[i]);					
		if(ppcm_config->TxFIFOBuf16Ptr[i])
			kfree(ppcm_config->TxFIFOBuf16Ptr[i]);	
		if(ppcm_config->RxFIFOBuf16Ptr[i])
			kfree(ppcm_config->RxFIFOBuf16Ptr[i]);
#ifdef PCM_SW_G729AB			
		if(ppcm_config->BSFIFOBuf16Ptr[i])
			kfree(ppcm_config->BSFIFOBuf16Ptr[i]);
#endif						
	}

	kfree(ppcm_config);
	ppcm_config = NULL;
	
	return PCM_OK;
}

int pcm_enable(unsigned int chid, pcm_config_type* ptrpcm_config)
{
	unsigned int GLBCFG_Data=0, int_en;
	
	if(ptrpcm_config->nch_active>=ptrpcm_config->pcm_ch_num)
	{
		MSG("There are %d channels already enabled\n",ptrpcm_config->nch_active);
		return PCM_OK;
	}
	int_en = pcm_inw(PCM_INT_EN);
	GLBCFG_Data = pcm_inw(PCM_GLBCFG);

	pcm_outw(PCM_INT_STATUS, 0x0);
	
	if(ptrpcm_config->nch_active==0)
		GLBCFG_Data |= REGBIT(0x1, DMA_EN);
#if defined (CONFIG_RALINK_MT7620)
	ptrpcm_config->nch_active++;
	GLBCFG_Data |= REGBIT(0x1, (CH_EN + chid));
#else
	switch (chid) {
		case 0:
			MSG("PCM:enable CH0\n");
			GLBCFG_Data |= REGBIT(0x1, CH0_TX_EN);
			GLBCFG_Data |= REGBIT(0x1, CH0_RX_EN);
			
			int_en |= REGBIT(0x1, CH0T_DMA_FAULT);
			int_en |= REGBIT(0x1, CH0R_DMA_FAULT);
			 
			ptrpcm_config->nch_active++;
			break;
		case 1:
			MSG("PCM:enable CH1\n");
			GLBCFG_Data |= REGBIT(0x1, CH1_TX_EN);
			GLBCFG_Data |= REGBIT(0x1, CH1_RX_EN);
			
			int_en |= REGBIT(0x1, CH1T_DMA_FAULT);
			int_en |= REGBIT(0x1, CH1R_DMA_FAULT);
 
			ptrpcm_config->nch_active++;
			break;
		default:
			break;
	}
#endif	

	//GLBCFG_Data |= REGBIT(0x1, PCM_EN);
	pcm_outw(PCM_INT_EN, int_en);
	/* michael */
	GLBCFG_Data &= ~(0x1 << 29);
	pcm_outw(PCM_GLBCFG, GLBCFG_Data);
	
	return PCM_OK;
}

int pcm_disable(unsigned int chid, pcm_config_type* ptrpcm_config)
{
	unsigned int data, int_en;

	if(ptrpcm_config->nch_active<=0)
	{ 
		MSG("No channels needed to disable\n");
		return PCM_OK;
	}
	ppcm_config->txfifo_rd_idx[chid] = 0;
	ppcm_config->txfifo_wt_idx[chid] = 0;
	ppcm_config->rxfifo_rd_idx[chid] = 0;
	ppcm_config->rxfifo_wt_idx[chid] = 0;
	ppcm_config->bsfifo_rd_idx[chid] = 0;
	ppcm_config->bsfifo_wt_idx[chid] = 0;
	
	int_en = pcm_inw(PCM_INT_EN);
	data = pcm_inw(PCM_GLBCFG);
	
#if defined (CONFIG_RALINK_MT7620)
	data &= ~REGBIT(0x1, (CH_EN + chid));
	ptrpcm_config->nch_active--;
#else
	switch (chid) {
		case 0:
			MSG("PCM:disable CH0\n");
			data &= ~REGBIT(0x1, CH0_TX_EN);
			data &= ~REGBIT(0x1, CH0_RX_EN);
			int_en &= ~REGBIT(0x1, CH0T_DMA_FAULT);
			int_en &= ~REGBIT(0x1, CH0R_DMA_FAULT);
			pcm_outw(PCM_INT_EN, int_en);
			ptrpcm_config->nch_active--;

			break;
		case 1:
			MSG("PCM:disable CH1\n");
			data &= ~REGBIT(0x1, CH1_TX_EN);
			data &= ~REGBIT(0x1, CH1_RX_EN);
			int_en &= ~REGBIT(0x1, CH1T_DMA_FAULT);
			int_en &= ~REGBIT(0x1, CH1R_DMA_FAULT);
			pcm_outw(PCM_INT_EN, int_en);
			ptrpcm_config->nch_active--;

			break;
		default:
			break;
	}
#endif	
	if(ptrpcm_config->nch_active<=0)
	{
		//data &= ~REGBIT(0x1, PCM_EN);
		data &= ~REGBIT(0x1, DMA_EN);
	}
	/* michael */
	data &= ~(0x1 << 29);
	pcm_outw(PCM_GLBCFG, data);
	return PCM_OK;
}

void pcm_dma_tx_isr(u32 dma_ch)
{
	int i;
	int chid=0;
	int page=0;
	char* p8PageBuf=NULL, *p8FIFOBuf=NULL, *p8Data;
	u32* pPCM_FIFO=NULL;

	//printk("tx_isr_cnt=%d\n", ppcm_config->tx_isr_cnt);
	if (ppcm_config->tx_isr_cnt == SLT_PCM_TEST_PACKET_NUM)
		return;

	if(ppcm_config->nch_active<=0)
	{
		MSG("No Active Channel for DMA[%d]\n", dma_ch);
		return;
	}	

	ppcm_config->tx_isr_cnt++;

	chid = (dma_ch>>2);
	page = (dma_ch&0x03)-2;
	pPCM_FIFO = (u32*)(PCM_CH_FIFO(chid));

	if(page==0)
		p8PageBuf = ppcm_config->TxPage0Buf8Ptr[chid];
	else
		p8PageBuf = ppcm_config->TxPage1Buf8Ptr[chid];

	if((chid>=CONFIG_PCM_CH)||(page>=2))
	{
		MSG("Invalid TX dma=%d chid=%d page=%d\n", dma_ch, chid, page);
		return;
	}	
	
	p8FIFOBuf = ppcm_config->TxFIFOBuf8Ptr[chid];
	ppcm_config->pos = 0;
	{
	
		for (i = 0 ; i < MAX_PCM_PROC_UNIT ; i ++ )
		{
			if(ppcm_config->txfifo_rd_idx[chid]==ppcm_config->txfifo_wt_idx[chid])
			{
				/* tx fifo empty */
				MSG("TFE[%d](%d) (r=%d,w=%d)(i=%d)\n",chid,dma_ch, ppcm_config->txfifo_rd_idx[chid], 
						ppcm_config->txfifo_wt_idx[chid], ppcm_config->tx_isr_cnt);
				break;
			}
			
			p8Data = p8FIFOBuf + (ppcm_config->txfifo_rd_idx[chid]*PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE);
			memcpy((void*)(p8PageBuf+ppcm_config->pos), p8Data, PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE);	
			
			ppcm_config->pos+=PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE;
			ppcm_config->txfifo_rd_idx[chid] = (ppcm_config->txfifo_rd_idx[chid]+1)%MAX_PCM_FIFO;
		}
	}
	
	ppcm_config->txcurchid = chid;

	if(chid==(CONFIG_PCM_CH-1))	
		tasklet_hi_schedule(&pcm_tx_tasklet);	


	GdmaPcmTx((u32)p8PageBuf, (u32)pPCM_FIFO, chid, page, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);	
	GdmaUnMaskChannel(GDMA_PCM_TX(chid, 1-page)); 
	
	return;
	
}

void pcm_dma_rx_isr(u32 dma_ch)
{
	int i;
	int chid=0; 
	int page=0;
	char* p8PageBuf=NULL, *p8FIFOBuf=NULL, *p8Data;
	u32* pPCM_FIFO=NULL;
	
	//printk("rx_isr_cnt=%d\n", ppcm_config->rx_isr_cnt);
	if (ppcm_config->rx_isr_cnt == SLT_PCM_TEST_PACKET_NUM)
		return;


	if(ppcm_config->nch_active<=0)
	{
		MSG("No Active Channel for DMA[%d]\n", dma_ch);
		return;
	}	
	
	ppcm_config->rx_isr_cnt++;
	chid = (dma_ch>>2);
	page = (dma_ch&0x03);
	pPCM_FIFO = (u32*)(PCM_CH_FIFO(chid));
	if(page==0)
		p8PageBuf = ppcm_config->RxPage0Buf8Ptr[chid];
	else
		p8PageBuf = ppcm_config->RxPage1Buf8Ptr[chid];
	
	if((chid>=CONFIG_PCM_CH)||(page>=2))
	{
		MSG("Invalid TX dma=%d chid=%d page=%d\n", dma_ch, chid, page);
		return;
	}	
	
	p8FIFOBuf = ppcm_config->RxFIFOBuf8Ptr[chid];
	ppcm_config->pos = 0;
	
	for (i = 0 ; i < MAX_PCM_PROC_UNIT ; i ++ )
	{
		if(((ppcm_config->rxfifo_wt_idx[chid]+1)%MAX_PCM_FIFO)==ppcm_config->rxfifo_rd_idx[chid])
		{
			/* rx fifo full */
			printk("RFF[%d](%d) (r=%d,w=%d)(i=%d)",chid,dma_ch,ppcm_config->rxfifo_rd_idx[chid], 
					ppcm_config->rxfifo_wt_idx[chid], ppcm_config->rx_isr_cnt);
			break;
		}
		ppcm_config->rxfifo_wt_idx[chid] = (ppcm_config->rxfifo_wt_idx[chid]+1)%MAX_PCM_FIFO;
		p8Data = p8FIFOBuf + (ppcm_config->rxfifo_wt_idx[chid]*PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE);
		memcpy((void*)p8Data, (void*)(p8PageBuf+ppcm_config->pos), PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE);
		ppcm_config->pos+=PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE;	
	}
	
	ppcm_config->curchid = chid;

	if(chid==(CONFIG_PCM_CH-1))
		tasklet_hi_schedule(&pcm_rx_tasklet);
	

	GdmaPcmRx((u32)pPCM_FIFO, (u32)p8PageBuf, chid, page, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);
	GdmaUnMaskChannel(GDMA_PCM_RX(chid, 1-page));	
	return;
}

#define MAX_SESSION	2
#define MAX_HOOK_FIFO	12
unsigned short* txhook_fifo[MAX_SESSION][MAX_HOOK_FIFO];
unsigned short* rxhook_fifo[MAX_SESSION][MAX_HOOK_FIFO];
int txhook_rd_idx[MAX_SESSION],txhook_wt_idx[MAX_SESSION],rxhook_rd_idx[MAX_SESSION],rxhook_wt_idx[MAX_SESSION];

void pcm_tx_task(unsigned long pData)
{
	pcm_config_type* ptrpcm_config = ppcm_config;
	int txch,rxch,ch; 
	int i;
	short *pTx16Data;
	char *pTx8Data;
	unsigned long flags;
	
	/* handle rx->tx fifo buffer */
	spin_lock_irqsave(&ptrpcm_config->txlock, flags);

	for( ch = 0 ; ch < CONFIG_PCM_CH ; ch ++ )
	{
		rxch = ch;
		//txch = (CONFIG_PCM_CH-1)-ch;
		txch = ch;
			
		for (i = 0 ; i < MAX_PCM_PROC_UNIT ; i ++ )
		{
 			int tx_index;

			tx_index = (ptrpcm_config->txfifo_wt_idx[txch]+1)%MAX_PCM_FIFO;
			if(tx_index==ptrpcm_config->txfifo_rd_idx[txch])
			{
				/* tx fifo full */
				printk("TTFF(%d)[%d] ",i ,txch);
				pTx8Data = NULL;
			}
			else
			{	 
				pTx8Data = ptrpcm_config->TxFIFOBuf8Ptr[txch] + (tx_index*PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE);
			}
			pTx16Data = (short *)pTx8Data;

			if (pTx16Data == NULL) {
				continue;
			}
			
			ptrpcm_config->txfifo_wt_idx[txch] = (ptrpcm_config->txfifo_wt_idx[txch]+1)%MAX_PCM_FIFO;
			

			{
				unsigned short txpat;
				unsigned short rxpat16;
				int j;

				txpat = 0x5948 - (u16)txch;
				rxpat16 = txpat;
				for( j = 0 ; j < PCM_8KHZ_SAMPLES ; j++ )
					//txpat = (unsigned short)(*(pTx16Data+j));
					pTx16Data[j] = (short)txpat;
 			
			}


		}
	
	}
	spin_unlock_irqrestore(&ptrpcm_config->txlock, flags);
	if((ptrpcm_config->bStartRecord)||(ptrpcm_config->bStartPlayback))
	{
		ptrpcm_config->mmappos = 0;
		wake_up_interruptible(&(ptrpcm_config->pcm_qh));
	}
	return;
}

void pcm_rx_task(unsigned long pData)
{
	pcm_config_type* ptrpcm_config = ppcm_config;
	int txch,rxch,ch;
	int i;
	short *pRx16Data;
	char *pRx8Data;
	unsigned long flags;

	spin_lock_irqsave(&ptrpcm_config->rxlock, flags);

	/* handle rx->tx fifo buffer */
	for( ch = 0 ; ch < CONFIG_PCM_CH ; ch ++ )
	{
		rxch = ch;
		//txch = (CONFIG_PCM_CH-1)-ch;
		txch = ch;
	
		for (i = 0 ; i < MAX_PCM_PROC_UNIT ; i ++ )
		{	
			if(ptrpcm_config->rxfifo_rd_idx[rxch]==ptrpcm_config->rxfifo_wt_idx[rxch])
			{
				/* rx fifo empty */
				MSG("RRFE(%d)[%d] ",i ,rxch);
				pRx8Data = NULL;
			}
			else
			{		
				pRx8Data = ptrpcm_config->RxFIFOBuf8Ptr[rxch] + (ptrpcm_config->rxfifo_rd_idx[rxch]*PCM_8KHZ_SAMPLES*PCM_SAMPLE_SIZE);
			}	
			pRx16Data = (short*)pRx8Data;
			if(pRx16Data==NULL)
			{
				bPassed--;
				continue;
			}
			ptrpcm_config->rxfifo_rd_idx[rxch] = (ptrpcm_config->rxfifo_rd_idx[rxch]+1)%MAX_PCM_FIFO;
			{
				unsigned short txpat;
				unsigned short rxpat16;
				int j;

				txpat = 0x5948-(u16)rxch;
				rxpat16 = txpat;
					if(ppcm_config->tx_isr_cnt > 20)
					{
						for( j = 0 ; j < PCM_8KHZ_SAMPLES ; j++ )
						{		
							if((unsigned short)(*(pRx16Data+j))!=(unsigned short)rxpat16)
							{
								MSG("[%d]PCM_INLOOP(%d) PATTERN ERROR TX[0x%04X] RX[0x%04X] \n", ch,j, 
										(unsigned short)rxpat16, (unsigned short)(*(pRx16Data+j)));
								bPassed--;
								break;
							}		
						}
					}
			}


		}
	}
	spin_unlock_irqrestore(&ptrpcm_config->rxlock, flags);
	if(ppcm_config->rx_isr_cnt%99==98)
		MSG("RLBK(p=%d)(i=%d)\n",bPassed,ppcm_config->rx_isr_cnt);
	if((ptrpcm_config->bStartRecord)||(ptrpcm_config->bStartPlayback))
	{
		ptrpcm_config->mmappos = 0;
		wake_up_interruptible(&(ptrpcm_config->pcm_qh));
	}
	return;
}

void pcm_unmask_isr(u32 dma_ch)
{
	char* p8Data;

	MSG("umisr c=%d\n",dma_ch);

	switch(dma_ch)
	{
	case GDMA_PCM0_RX0:
		p8Data = (char*)(ppcm_config->RxPage0Buf16Ptr[0]);
		GdmaPcmRx((u32)PCM_CH0_FIFO, (u32)p8Data, 0, 0, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM0_RX1);
		break;
	case GDMA_PCM0_RX1:	
		p8Data = (char*)(ppcm_config->RxPage1Buf16Ptr[0]);
		GdmaPcmRx((u32)PCM_CH0_FIFO, (u32)p8Data, 0, 1, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);	
		GdmaUnMaskChannel(GDMA_PCM0_RX0);
		break;
	case GDMA_PCM0_TX0:	
		p8Data = (char*)(ppcm_config->TxPage0Buf16Ptr[0]);
		GdmaPcmTx((u32)p8Data, (u32)PCM_CH0_FIFO, 0, 0, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM0_TX1);
		break;
	case GDMA_PCM0_TX1:
		p8Data = (char*)(ppcm_config->TxPage1Buf16Ptr[0]);
		GdmaPcmTx((u32)p8Data, (u32)PCM_CH0_FIFO, 0, 1, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM0_TX0);
		break;
	case GDMA_PCM1_RX0:	
		p8Data = (char*)(ppcm_config->RxPage0Buf16Ptr[1]);
		GdmaPcmRx((u32)PCM_CH1_FIFO, (u32)p8Data, 1, 0, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM1_RX1);
		break;
	case GDMA_PCM1_RX1:		
		p8Data = (char*)(ppcm_config->RxPage1Buf16Ptr[1]);					
		GdmaPcmRx((u32)PCM_CH1_FIFO, (u32)p8Data, 1, 1, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM1_RX0);
		break;	
	case GDMA_PCM1_TX0:	
		p8Data = (char*)(ppcm_config->TxPage0Buf16Ptr[1]);
		GdmaPcmTx((u32)p8Data, (u32)PCM_CH1_FIFO, 1, 0, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM1_TX1);
		break;
	case GDMA_PCM1_TX1:	
		p8Data = (char*)(ppcm_config->TxPage1Buf16Ptr[1]);
		GdmaPcmTx((u32)p8Data, (u32)PCM_CH1_FIFO, 1, 1, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);
		GdmaUnMaskChannel(GDMA_PCM1_TX0);
		break;
	}	
	return; 		
}

/**
 * @brief PCM interrupt handler 
 *
 * When PCM interrupt happened , call related handler 
 * to do the remain job.
 *
 */
irqreturn_t pcm_irq_isr(int irq, void *irqaction)
{
	u32 pcm_status;
	
	pcm_status=pcm_inw(PCM_INT_STATUS);
	MSG("SR=%08X\n",pcm_status);

	pcm_outw(PCM_INT_STATUS, 0xFFFF);
	
	return IRQ_HANDLED;

}

int do_pcm(unsigned int cmd)
{
	int i, Ret;
	char* p8Data;
	unsigned long flags;
	unsigned long data;
	pcm_config_type* ptrpcm_config = ppcm_config;
	
	switch (cmd) {
		case PCM_START:
			MSG("iocmd=PCM_START\n");
					
#ifdef PCM_TASKLET
			tasklet_init(&pcm_rx_tasklet, pcm_rx_task, (u32)ppcm_config);
			tasklet_init(&pcm_tx_tasklet, pcm_tx_task, (u32)ppcm_config);
			MSG("pcm tasklet initialization\n");
#endif			

			for( i = 0; i < ptrpcm_config->pcm_ch_num; i++) {
				p8Data = (char*)(ptrpcm_config->RxPage0Buf16Ptr[i]);
				GdmaPcmRx((u32)PCM_CH_FIFO(i), (u32)p8Data, i, 0, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);
				p8Data = (char*)(ptrpcm_config->RxPage1Buf16Ptr[i]);
				GdmaPcmRx((u32)PCM_CH_FIFO(i), (u32)p8Data, i, 1, PCM_PAGE_SIZE, pcm_dma_rx_isr, pcm_unmask_isr);
				GdmaUnMaskChannel(GDMA_PCM_RX(i,0));
				p8Data = (char*)(ptrpcm_config->TxPage0Buf16Ptr[i]);
				GdmaPcmTx((u32)p8Data, (u32)PCM_CH_FIFO(i), i, 0, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);
				p8Data = (char*)(ptrpcm_config->TxPage1Buf16Ptr[i]);
				GdmaPcmTx((u32)p8Data, (u32)PCM_CH_FIFO(i), i, 1, PCM_PAGE_SIZE, pcm_dma_tx_isr, pcm_unmask_isr);
				GdmaUnMaskChannel(GDMA_PCM_TX(i,0));
			
			}

			Ret = request_irq(SURFBOARDINT_PCM, pcm_irq_isr, IRQF_DISABLED, "Ralink_PCM", NULL);
			if(Ret){
				MSG("PCM: IRQ %d is not free.\n", SURFBOARDINT_PCM);
				return PCM_REQUEST_IRQ_FAILED;
			}
			for( i = 0; i < ptrpcm_config->pcm_ch_num; i++)
			{
				ptrpcm_config->txfifo_rd_idx[i] = 0;
				ptrpcm_config->txfifo_wt_idx[i] = 0;
				ptrpcm_config->rxfifo_rd_idx[i] = 0;
				ptrpcm_config->rxfifo_wt_idx[i] = 0;
				ptrpcm_config->bsfifo_rd_idx[i] = 0;
				ptrpcm_config->bsfifo_wt_idx[i] = 0;
			}
			ptrpcm_config->rx_isr_cnt = 0;
			ptrpcm_config->tx_isr_cnt = 0;
			
			ptrpcm_config->bStartRecord = 0;
			pcm_dump_reg();			
			for ( i = 0 ; i < ptrpcm_config->pcm_ch_num ; i ++ )
				pcm_enable(i, ptrpcm_config);	
			/* enable system interrupt for PCM */
			data = pcm_inw(RALINK_REG_INTENA);
			data |=0x010;
	    		pcm_outw(RALINK_REG_INTENA, data);
			break;
		case PCM_STOP:
			MSG("iocmd=PCM_STOP\n");
			spin_lock_irqsave(&ptrpcm_config->lock, flags);	
			
			/* disable system interrupt for PCM */
			data = pcm_inw(RALINK_REG_INTENA);
			data &=~0x010;
			pcm_outw(RALINK_REG_INTENA, data);
		
			synchronize_irq(SURFBOARDINT_PCM);
			free_irq(SURFBOARDINT_PCM, NULL);
		
			for ( i = 0 ; i < ptrpcm_config->pcm_ch_num ; i ++ )
				pcm_disable(i, ptrpcm_config);
#ifdef PCM_TASKLET
			tasklet_kill(&pcm_rx_tasklet);
			tasklet_kill(&pcm_tx_tasklet);
#endif
			MSG("pcm tasklet deinitialization\n");
			
			spin_unlock_irqrestore(&ptrpcm_config->lock, flags);
			break;
		default:
			break;
	}
	
	return 0;
}

void pcm_dump_reg (void)
{
	int i;
	MSG("[0x%08X]RALINK_REG_GPIOMODE=0x%08X\n", RALINK_REG_GPIOMODE, pcm_inw(RALINK_REG_GPIOMODE));
	MSG("[0x%08X]PCM_GLBCFG=0x%08X\n", PCM_GLBCFG, pcm_inw(PCM_GLBCFG));
	MSG("[0x%08X]PCM_PCMCFG=0x%08X\n", PCM_PCMCFG, pcm_inw(PCM_PCMCFG));
	MSG("[0x%08X]PCM_INT_STATUS=0x%08X\n", PCM_INT_STATUS, pcm_inw(PCM_INT_STATUS));
	MSG("[0x%08X]PCM_INT_EN=0x%08X\n", PCM_INT_EN, pcm_inw(PCM_INT_EN));
	MSG("[0x%08X]PCM_FF_STATUS=0x%08X\n", PCM_FF_STATUS, pcm_inw(PCM_FF_STATUS));
#if defined (CONFIG_RALINK_MT7620)
	for (i = 0; i < CONFIG_PCM_CH; i++) {
		MSG("[0x%08X]PCM_CH_CFG(%d)=0x%08X\n", PCM_CH_CFG(i), i,  pcm_inw(PCM_CH_CFG(i)));
		MSG("[0x%08X]PCM_CH_FIFO(%d)=0x%08X\n", PCM_CH_FIFO(i), i, pcm_inw(PCM_CH_FIFO(i)));
	}
#else	
	MSG("[0x%08X]PCM_CH0_CFG=0x%08X\n", PCM_CH0_CFG, pcm_inw(PCM_CH0_CFG));
	MSG("[0x%08X]PCM_CH1_CFG=0x%08X\n", PCM_CH1_CFG, pcm_inw(PCM_CH1_CFG));
	MSG("[0x%08X]PCM_CH0_FIFO=0x%08X\n", PCM_CH0_FIFO,pcm_inw(PCM_CH0_FIFO));
	MSG("[0x%08X]PCM_CH1_FIFO=0x%08X\n", PCM_CH1_FIFO,pcm_inw(PCM_CH1_FIFO));
#endif
#if defined(CONFIG_RALINK_RT3883)||defined(CONFIG_RALINK_RT3352)||defined(CONFIG_RALINK_RT5350) \
	|| defined (CONFIG_RALINK_RT6855) || defined(CONFIG_RALINK_MT7620)
	MSG("[0x%08X]PCM_FSYNC_CFG=0x%08X\n", PCM_FSYNC_CFG, pcm_inw(PCM_FSYNC_CFG));
	MSG("[0x%08X]PCM_CH_CFG2=0x%08X\n", PCM_CH_CFG2, pcm_inw(PCM_CH_CFG2));
	MSG("[0x%08X]PCM_DIVCOMP_CFG=0x%08X\n", PCM_DIVCOMP_CFG, pcm_inw(PCM_DIVCOMP_CFG));
	MSG("[0x%08X]PCM_DIVINT_CFG=0x%08X\n", PCM_DIVINT_CFG, pcm_inw(PCM_DIVINT_CFG));
#endif	
}	

#endif

int pcm_loopback_test(unsigned int chip_id)
{

#if defined (CONFIG_RALINK_RT6855A)

	if (chip_id == RT6855A_CHIP) {
		inloopback = 0;
		slt_pcm_tx_count = 0;
		slt_pcm_rx_count = 0;

		pcmDriverInit();
		msleep(SLT_PCM_TEST_TIME);
		pcmDriverExit();

		printk("SLT PCM Test: error count=%d tx_count=%u rx_count=%u\n", inloopback, slt_pcm_tx_count, slt_pcm_rx_count);

		if ((inloopback == 0) && (slt_pcm_tx_count == slt_pcm_rx_count))
			return 1;
		else
			return 0;
	}

	return 0;

#elif defined (CONFIG_RALINK_MT7620)

	if (chip_id == MT7620_CHIP) {
		pcm_init();
		do_pcm(PCM_START);
		msleep(SLT_PCM_TEST_TIME);
		do_pcm(PCM_STOP);

		printk("tx_isr_cnt=%d rx_isr_cnt=%d bPassed=%d\n", ppcm_config->tx_isr_cnt, ppcm_config->rx_isr_cnt, bPassed);
		if ((ppcm_config->tx_isr_cnt > 10) && (ppcm_config->tx_isr_cnt == ppcm_config->rx_isr_cnt) && (bPassed == CONFIG_PCM_CH * MAX_PCM_PROC_UNIT))
			return 1;
		else
			return 0;

	}

	return 0;
#endif

}
