
#include "mtk_baseDefs.h"
#include "mtk_hwAccess.h"
#include "mtk_AdapterInternal.h"
#include "mtk_hwDmaAccess.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/mach-ralink/surfboardint.h>
#include "mtk_pecApi.h"
#include <net/mtk_esp.h>
#include <linux/proc_fs.h>

#include <linux/platform_device.h>
#include "mtk_hwInterface.h"

static struct proc_dir_entry *entry;

#if defined(CONFIG_RALINK_HWCRYPTO_2)
extern bool _ipsec_accel_on_;
#endif

extern void 
mtk_ipsec_init(
	void
);

static bool Adapter_IsInitialized = false;


static bool
Adapter_Init(
	int irq
)
{
    if (Adapter_IsInitialized != false)
    {
        printk("Adapter_Init: Already initialized\n");
        return true;
    }


    if (!HWPAL_DMAResource_Init(1024))
    {
		printk("HWPAL_DMAResource_Init failed\n");
       return false;
    }

    if (!Adapter_EIP93_Init())
    {
        printk("Adapter_EIP93_Init failed\n");
		return false;
    }

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    Adapter_Interrupts_Init(irq); //(SURFBOARDINT_CRYPTO);
#endif

    Adapter_IsInitialized = true;

    return true;
}


static void
Adapter_UnInit(
	void
)
{
    if (!Adapter_IsInitialized)
    {
        printk("Adapter_UnInit: Adapter is not initialized\n");
        return;
    }

    Adapter_IsInitialized = false;



    Adapter_EIP93_UnInit();

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    Adapter_Interrupts_UnInit();
#endif

    HWPAL_DMAResource_UnInit();
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
static int mcrypto_proc_read(char *buf, char **start, off_t off, int count, int *eof, void *data)
{
    int len, i;
    if (off > 0)
    {
        return 0;
    }

    len = sprintf(buf, "expand : %d\n", mcrypto_proc.copy_expand_count);
    len += sprintf(buf + len, "nolinear packet : %d\n", mcrypto_proc.nolinear_count);
    len += sprintf(buf + len, "oom putpacket : %d\n", mcrypto_proc.oom_in_put);
    for (i = 0; i < 4; i++)
    	len += sprintf(buf + len, "skbq[%d] : %d\n", i, mcrypto_proc.qlen[i]);
    for (i = 0; i < 10; i++)
    	len += sprintf(buf + len, "dbgpt[%d] : %d\n", i, mcrypto_proc.dbg_pt[i]);	
    return len;
}
#endif

int
VDriver_Init(
	void
)
{
    int i;
	int irq = 20;

    if (!Adapter_Init(irq))
    {
		printk("\n !Adapter_Init failed! \n");
        return -1;
    }

	if (PEC_Init(NULL) == PEC_ERROR_BAD_USE_ORDER)
	{
		printk("\n !PEC is initialized already! \n");
		return -1;
	}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
	entry = create_proc_entry(PROCNAME, 0666, NULL);
	if (entry == NULL)
	{
		printk("HW Crypto : unable to create /proc entry\n");
		return -1;
	}
	entry->read_proc = mcrypto_proc_read;
	entry->write_proc = NULL;
#endif	
	memset(&mcrypto_proc, 0, sizeof(mcrypto_proc_type));
    
	mtk_ipsec_init();

#if defined(CONFIG_RALINK_HWCRYPTO_2)
	_ipsec_accel_on_ = true;
	printk("HW Crypto : Enable\n");
#endif

    return 0;   // success
}



void
VDriver_Exit(
	void
)
{
#if defined(CONFIG_RALINK_HWCRYPTO_2)
	_ipsec_accel_on_ = false;
	printk("HW Crypto : Disable\n");
#endif
    Adapter_UnInit();
	
	PEC_UnInit();
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
	remove_proc_entry(PROCNAME, entry);
#endif	
}

#if 0
/**
 * struct mtk_device - crypto engine device structure
 */
struct mtk_device {
	void __iomem		*base;
	struct device		*dev;
	struct clk		*clk;
	int			irq;

	struct mtk_ring		*ring;
	struct saRecord_s	*saRecord;
	struct saState_s	*saState;
	dma_addr_t		saState_base;
	dma_addr_t		saRecord_base;
	unsigned int		seed[8];
};

static int mtk_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_device *mtk;
	struct resource *res;
	
	mtk = devm_kzalloc(dev, sizeof(*mtk), GFP_KERNEL);
	if (!mtk)
		return -ENOMEM;

	mtk->dev = dev;
	platform_set_drvdata(pdev, mtk);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mtk->base = devm_ioremap_resource(&pdev->dev, res);

	if (IS_ERR(mtk->base))
		return PTR_ERR(mtk->base);

	mtk->irq = platform_get_irq(pdev, 0);

	if (mtk->irq < 0) {
		dev_err(mtk->dev, "Cannot get IRQ resource\n");
		return mtk->irq;
	}
	dev_info(mtk->dev, "Assigning IRQ: %d", mtk->irq);

	//Adapter_Interrupts_Init(mtk->irq);

	VDriver_Init(mtk->irq);
	
	dev_info(mtk->dev, "Init succesfull\n");

	return 0;
}

static int mtk_crypto_remove(struct platform_device *pdev)
{
	struct mtk_device *mtk = platform_get_drvdata(pdev);

	/* Clear/ack all interrupts before disable all */
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);

	VDriver_Exit();
	
	dev_info(mtk->dev, "EIP93 removed.\n");

	return 0;
}

static const struct of_device_id mtk_crypto_of_match[] = {
	{ .compatible = "mediatek,mtk-eip93", },
	{}
};
MODULE_DEVICE_TABLE(of, mtk_crypto_of_match);

static struct platform_driver mtk_crypto_driver = {
	.probe = mtk_crypto_probe,
	.remove = mtk_crypto_remove,
	.driver = {
		.name = "mtk-eip93",
		.of_match_table = mtk_crypto_of_match,
	},
};
module_platform_driver(mtk_crypto_driver);

MODULE_ALIAS("platform:" KBUILD_MODNAME);
MODULE_DESCRIPTION("Mediatek EIP-93 crypto engine driver");
MODULE_LICENSE("Proprietary");
#else
MODULE_LICENSE("Proprietary");

module_init(VDriver_Init);
module_exit(VDriver_Exit);
#endif
