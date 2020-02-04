#include <linux/autoconf.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>

#if defined (CONFIG_RALINK_RT6855A)
#include <asm/tc3162/tc3162.h>
#else
#include <asm/mach-ralink/serial_rt2880.h>
#endif

#include <asm/mach-ralink/eureka_ep430.h>
#include <asm/pci.h>

#include "slt.h"
#include "gpio.h"
#if defined (CONFIG_RALINK_RT6855A)
#include "../../../../../linux-2.6.36MT.x/drivers/char/ralink_gpio.h"
#else
#include "../../../../drivers/char/ralink_gpio.h"
#endif


/*
 * 0: not test yet
 * 1: success
 * 2: fail
 */
int slt_bin_result = 0;
int slt_eot_f = 0;
int slt_nand_result = 0;
int slt_spi_result = 0;
int slt_usb_host_result = 0;
int slt_dram_result = 0;
int slt_uart_lite_result = 0;
int slt_pcie_result = 0;
int slt_sd_result = 0;
int slt_pcm_result = 0;
int slt_i2s_result = 0;
int slt_rgmii_result = 0;
int slt_ephy_result = 0;
int slt_wifi_result = 0;
int slt_wifi_throughput = 0;
int slt_wifi_pass_th = 0;

bool test_all_f = false;
unsigned int test_item = TEST_ALL;
int wifi_pass_th = -1;
int wifi_throughput = -1;

int slt_spi_test(unsigned int chip_id)
{
	/* just return 1 when the platform uses SPI Flash */
	return 1;
}

int test_file_read(char *filename)
{
	struct file *srcf;
	char *src;
	mm_segment_t orgfs;
	unsigned char *buffer;
	const int bufSize = 32;
	int i;
	char *test_pattern = "0123456789";

	buffer = kmalloc(bufSize, GFP_ATOMIC);
	if(buffer == NULL)
	      return 1;

   	src = filename;
	orgfs = get_fs();
	set_fs(KERNEL_DS);
	if (src && *src) {
		srcf = filp_open(src, O_RDONLY, 0);
		if (IS_ERR(srcf))
		{
			kfree(buffer);
			return 1;
		}
		else
		{
			memset(buffer, 0x00, bufSize);
			srcf->f_op->read(srcf, buffer, bufSize, &srcf->f_pos);
			filp_close(srcf,NULL);
		}
	}
	for (i = 0; i  < strlen(test_pattern); i++ ) {
		if((char)buffer[i] != test_pattern[i]) {
			set_fs(orgfs);
			kfree(buffer);
			return 2;
		}
	}
	set_fs(orgfs);
	kfree(buffer);

	return 0;
}

int slt_sd_host_test(unsigned int chip_id, unsigned int chip_id2)
{
#if defined (CONFIG_RALINK_MT7620) 
	char *filename="/media/mmc/slt_test1";

	if (chip_id2 == MT7620A_CHIP) {	
		int result = test_file_read(filename);

		if (result == 0)
			return 1;
		else if (result == 1) {
			printk("SLT SD Host Test: Fail to open %s\n", filename);
			printk("SLT SD Host Test: read test failed\n");
			return 0;
		}
		else if (result == 2) {
			printk("SLT SD Host Test: %s data checking failed.\n", filename);
			printk("SLT SD Host Test: read test failed\n");
			return 0;
		}
		else
			return 0;
	}
#endif

	return 0;
}

int slt_usb_host_test(unsigned int chip_id, unsigned int chip_id2)
{
	char *filename1="/media/sda/slt_test1";
	char *filename2="/media/sdb/slt_test2";

#if defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_RT6855A)
	if ((chip_id == RT6855A_CHIP) || (chip_id == MT7620_CHIP)) {	
		int result;

		/* USB Port 1 test */
		result = test_file_read(filename1);
		if (result == 0)
			printk("SLT USB Host Test: Port 1 read test passed\n");
		else if (result == 1) {
			printk("SLT USB Host Test: Fail to open %s\n", filename1);
			printk("SLT USB Host Test: Port 1 read test failed\n");
			return 0;
		}
		else if (result == 2) {
			printk("SLT USB Host Test: %s data checking failed\n", filename1);
			printk("SLT USB Host Test: Port 1 read test failed\n");
			return 0;
		}
		else {
			printk("SLT USB Host Test: Port 1 read test failed\n");
			return 0;
		}

		/* USB Port 2 test */
		if (chip_id2 == RT6856_CHIP) {
			result = test_file_read(filename2);
			if (result == 0) {
				printk("SLT USB Host Test: Port 2 read test passed\n");
				return 1;
			}
			else if (result == 1) {
				printk("SLT USB Host Test: Fail to open %s\n", filename2);
				printk("SLT USB Host Test: Port 2 read test failed\n");
				return 0;
			}
			else if (result == 2) {
				printk("SLT USB Host Test: %s data checking failed.\n", filename2);
				printk("SLT USB Host Test: Port 2 read test failed\n");
				return 0;
			}
			else {
				printk("SLT USB Host Test: Port 2 read test failed\n");
				return 0;
			}
		}		
		else 
			return 1;
	}
#endif

	return 0;
}

int slt_dram_test(unsigned int chip_id)
{
	int i;
	unsigned char buf[DRAM_TEST_SIZE];
	volatile unsigned char *ptr;

#if defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_RT6855A)
	if ((chip_id == RT6855A_CHIP) || (chip_id == MT7620_CHIP)) {
		memcpy(buf, (void *)DRAM_TEST_ADDR, DRAM_TEST_SIZE);
		for (i = 0; i < DRAM_TEST_SIZE; i++) {
			ptr = (unsigned char *)DRAM_TEST_ADDR + i;
			if (buf[i] != *ptr)
				return 0;
		}	

		return 1;
	}
#endif

	return 0;
}

int put_uart_char(char c)
{
#if defined (CONFIG_RALINK_RT6855A)
	//while (!(LSR_INDICATOR & LSR_THRE))
	while (!(HS_LSR_INDICATOR & HS_LSR_THRE))
		;
	//VPchar(CR_UART_THR) = c;
	VPchar(CR_HSUART_THR) = c;
#elif defined (CONFIG_RALINK_MT7620)
	//while ((sysRegRead(UART_LSR + RALINK_UART_LITE_BASE) & UART_LSR_THRE) == 0)
	while ((sysRegRead(UART_LSR + RALINK_UART_BASE) & UART_LSR_THRE) == 0)
		;
	//sysRegWrite(UART_TX + RALINK_UART_LITE_BASE, c);
	sysRegWrite(UART_TX + RALINK_UART_BASE, c);
#endif

	return 1;
}

char get_uart_char(void)
{
#if defined (CONFIG_RALINK_RT6855A)
	//while (!(LSR_INDICATOR & LSR_RECEIVED_DATA_READY))
	while (!(HS_LSR_INDICATOR & HS_LSR_RECEIVED_DATA_READY))
		;
	//return VPchar(CR_HSUART_RBR);
	return VPchar(CR_HSUART_RBR);
#elif defined (CONFIG_RALINK_MT7620)
	//while (!(sysRegRead(UART_LSR + RALINK_UART_LITE_BASE) & 1))
	while (!(sysRegRead(UART_LSR + RALINK_UART_BASE) & 1))
		;
	//return sysRegRead(UART_RX + RALINK_UART_LITE_BASE);
	return sysRegRead(UART_RX + RALINK_UART_BASE);
#endif
}

int slt_uartlite_test(unsigned int chip_id, unsigned int chip_id2)
{
#if defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_RT6855A)
	if ((chip_id == RT6855A_CHIP) || (chip_id == MT7620_CHIP)) {
		int i;
		unsigned char tmp[100];

		if (chip_id2 == RT6856_CHIP) {
			unsigned int data;

			data = sysRegRead(RALINK_REG_GPIOMODE);
			data |= (1L << 6);
			sysRegWrite(RALINK_REG_GPIOMODE, data);
		}

		sysRegWrite(0xb0000c08, 0);
		//get_uart_char();
		for (i = 0; i < UARTLITE_TEST_SIZE; i++) {
			put_uart_char(i);
			tmp[i] = get_uart_char();
		}
		sysRegWrite(0xb0000c08, 5);
		for (i = 0; i < UARTLITE_TEST_SIZE; i++) {
			if (tmp[i] != i)
				return 0;
		}
		if (i == UARTLITE_TEST_SIZE)
			return 1;
	}
#endif

        return 0;
}

int slt_pcie_test(unsigned int chip_id, unsigned int chip_id2)
{
#if defined (CONFIG_RALINK_RT6855A) || defined (CONFIG_RALINK_MT7620)
	if ((chip_id == RT6855A_CHIP) || (chip_id2 == MT7620A_CHIP)) {
		if ((RALINK_PCI0_STATUS & 0x1) != 1) {
			printk("SLT PCIe Test: slot1 link failed\n");
			return 0;
		}

		if (RALINK_PCI0_DERR != 0) {
			printk("SLT PCIe Test: slot1 data failed\n");
			return 0;
		}

		if (RALINK_PCI0_ECRC != 0) {
			printk("SLT PCIe Test: slot1 crc failed\n");
			return 0;
		}
	
		if (chip_id2 == RT6856_CHIP) {
			if ((RALINK_PCI1_STATUS & 0x1) != 1) {
				printk("SLT PCIe Test: slot2 link failed\n");
				return 0;
			}

			if (RALINK_PCI1_DERR != 0) {
				printk("SLT PCIe Test: slot2 data failed\n");
				return 0;
			}

			if (RALINK_PCI1_ECRC != 0) {
				printk("SLT PCIe Test: slot2 crc failed\n");
				return 0;
			}
		}
	
#if defined (CONFIG_RALINK_MT7620)
		if (chip_id2 == MT7620A_CHIP) {
			int i;
			struct pci_dev *dev = NULL;
			unsigned int target_dev[][4] = {
				{0x1814, 0x3092},					
				{0x1814, 0x5392},					
				{0x1814, 0x5592},					
				{0, 0}};					

			for (i = 0;; i++) {
				if (target_dev[i][0] == 0) {
					printk("SLT PCIe Test: PID/VID checking failed\n");
					return 0;
				}

				dev = pci_get_device(target_dev[i][0], target_dev[i][1], NULL);
				if (dev  != NULL)
					break;
			}
		}
#endif

		return 1;
	}
#endif

	return 0;
}

int slt_pcm_test(unsigned int chip_id)
{
#if defined (CONFIG_RALINK_RT6855A)
	if (chip_id == RT6855A_CHIP) {
		unsigned int tmp;

		tmp = sysRegRead(RALINK_REG_GPIOMODE);
		tmp |= (1L << 0);
		sysRegWrite(RALINK_REG_GPIOMODE, tmp);

		return pcm_loopback_test(chip_id);
	}
#elif defined (CONFIG_RALINK_MT7620)
	if (chip_id == MT7620_CHIP)
		return pcm_loopback_test(chip_id);
#endif
	
	return 0;
}

int slt_i2s_test(unsigned int chip_id)
{
#if defined (CONFIG_RALINK_MT7620)
	if (chip_id == MT7620_CHIP) {
		int i, j;
		int write_count = 0, error_count = 0;
		unsigned long value;
	
		value = sysRegRead(RALINK_SYSCTL_BASE + 0x34);
		sysRegWrite(RALINK_SYSCTL_BASE + 0x34, value | 0x00020000);
		value = sysRegRead(RALINK_SYSCTL_BASE + 0x34);
		sysRegWrite(RALINK_SYSCTL_BASE + 0x34, value & 0xFFFDFFFF);
		value = sysRegRead(RALINK_SYSCTL_BASE + 0x60);
		sysRegWrite(RALINK_SYSCTL_BASE + 0x60, (value & ~(0x1C)) | 0x8);
		value = sysRegRead(RALINK_I2S_BASE);
		sysRegWrite(RALINK_I2S_BASE, value & 0x7FFFFFFF);		
		sysRegWrite(RALINK_I2S_BASE + 0x18, 0x00000000);
		sysRegWrite(RALINK_I2S_BASE + 0x0, 0xC1104040);
		sysRegWrite(RALINK_I2S_BASE + 0x24, 0x00000006);
		sysRegWrite(RALINK_I2S_BASE + 0x20, 0x80000105);

		for (i = 0; i < 32; i++) {
			for (j = 0; j < I2S_TEST_SIZE; j++) {
				register unsigned long ff_status;
				unsigned long data;

				ff_status = sysRegRead(RALINK_I2S_BASE + 0x0C);
				if ((ff_status & 0x0F) > 0) {
					sysRegWrite(RALINK_I2S_BASE + 0x10, (1 << i));
					write_count++;
					mdelay(1);
					data = sysRegRead(RALINK_I2S_BASE + 0x14);
				}
		 		else {
					data = sysRegRead(RALINK_I2S_BASE + 0x14);
					continue;	
				}
					
				ff_status = sysRegRead(RALINK_I2S_BASE + 0x0C);	
				if (((ff_status >> 4) & 0x0F) > 0) {
					data = sysRegRead(RALINK_I2S_BASE + 0x14);
					if (j >= I2S_PRE_TEST_SIZE) {
						if (data != (1 << i))
							error_count++;
					}
				}
				else
					continue;

			}
		}	

		if (write_count > ((I2S_TEST_SIZE - I2S_PRE_TEST_SIZE) * 32) &&
			(error_count == 0))
			return 1;
		else {
			printk("SLT I2S Test: error count=%d\n", error_count);
			return 0;
		}
	}	
#endif
	
	return 0;
}


int slt_rgmii_test(unsigned int chip_id)
{
	return 0;
}

int slt_wifi_test(unsigned int chip_id, unsigned int chip_id2)
{
#if defined (CONFIG_RALINK_MT7620) 
	if (chip_id == MT7620_CHIP) {	
		if (wifi_pass_th == -1)
			wifi_pass_th = slt_wifi_pass_th;
		if (wifi_throughput == -1)
			wifi_throughput = slt_wifi_throughput;

		printk("SLT WiFi Test: pass threshold=%d\n", wifi_pass_th);
		printk("SLT WiFi Test: throughput result=%d\n", wifi_throughput);
		if (wifi_throughput >= wifi_pass_th)
			return 1;
		else
			return 0;				
	}
#endif
	return 0;
}


void bin_classify(unsigned int chip_id, unsigned int bin)
{
	if ((chip_id == RT6855_CHIP) || (chip_id == RT6856_CHIP)) {
		switch (bin) {
		case BIN1:
			GPIO_HIGH(SLT_BIN_IND0_GPIO);
			GPIO_HIGH(SLT_BIN_IND1_GPIO);
			break;
		case BIN2:
			GPIO_LOW(SLT_BIN_IND0_GPIO);
			GPIO_HIGH(SLT_BIN_IND1_GPIO);
			break;
		case BIN3:
			GPIO_HIGH(SLT_BIN_IND0_GPIO);
			GPIO_LOW(SLT_BIN_IND1_GPIO);
			break;
		case BIN4:
			GPIO_LOW(SLT_BIN_IND0_GPIO);
			GPIO_LOW(SLT_BIN_IND1_GPIO);
			break;
		default:
			/* BIN3 */
			GPIO_HIGH(SLT_BIN_IND0_GPIO);
			GPIO_LOW(SLT_BIN_IND1_GPIO);
			break;
		}
	}

	/* EOT is not necessary for RT6856, RT6855, and MT7620,
	 * since these CHIPs use RS232 to communicate with handler, not GPIO
	 */
	/* EOT */
	//GPIO_HIGH(SLT_EOT_GPIO);

	slt_bin_result = bin;
	printk("\n\n========================================\n");
	printk("End of SLT tset. BIN=%u\n", bin);
	printk("\n\n########################################\n");
}

static int check_chip_id(unsigned int *chip_id, unsigned int *chip_id2)
{
#if defined (CONFIG_RALINK_RT6855A)
	*chip_id = RT6855A_CHIP;	
#elif defined (CONFIG_RALINK_MT7620)
	*chip_id = MT7620_CHIP;	
#else 
#error "Chip ID is not configured for SLT program"
#endif

#if defined (CONFIG_RALINK_RT6855A)
	if (*chip_id == RT6855A_CHIP) {
		if (isRT6855) {
			*chip_id2 = RT6855_CHIP;
			return 1;
		}
		else if (isRT6856) {
			*chip_id2 = RT6856_CHIP;
			return 1;
		}
		else {
			*chip_id2 = *chip_id;
			return 0;
		}
	}
#elif defined (CONFIG_RALINK_MT7620)
	if (*chip_id == MT7620_CHIP) {
		unsigned int id, id2, id3;

		id = *(volatile u32 *)KSEG1ADDR((RALINK_SYSCTL_BASE + 0));
		id2 = *(volatile u32 *)KSEG1ADDR((RALINK_SYSCTL_BASE + 4));
		id3 = *(volatile u32 *)KSEG1ADDR((RALINK_SYSCTL_BASE + 0xc));
		//if ((id == 0x33365452) && (id2 == 0x20203235)) {
		if (1) {
			*chip_id = MT7620_CHIP;
			id3 &= (1 << 16);
			if (id3)
				*chip_id2 = MT7620A_CHIP;
			else
				*chip_id2 = MT7620N_CHIP;

			return 1;
		}
		else
			return 0;
	}
#else
	*chip_id2 = *chip_id;
#endif

	return 0;
}

static int print_ver(unsigned int chip_id, unsigned int chip_id2)
{
	char *slt_version, *slt_chip_id;

	if (chip_id2 == RT6855_CHIP) {
		slt_version = RT6855_SLT_VERSION;
		slt_chip_id = "RT6855";
	}
	else if (chip_id2 == RT6856_CHIP) {
		slt_version = RT6856_SLT_VERSION;
		slt_chip_id = "RT6856";
	}
	else if (chip_id == MT7620_CHIP) {
		slt_version = MT7620_SLT_VERSION;
		if (chip_id2 == MT7620A_CHIP)
			slt_chip_id = "MT7620A";
		else if (chip_id2 == MT7620N_CHIP)
			slt_chip_id = "MT7620N";
		else
			slt_chip_id = "MT7620";
	}
	else {
		slt_version = "";
		slt_chip_id = "";
	}
	printk("\n\n######### %s SLT Program (V%s) ############\n", slt_chip_id, slt_version);

	return 0;
}



static int config_slt_gpio(unsigned int chip_id, unsigned chip_id2)
{
	unsigned int ephy_relay_gpio0, ephy_relay_gpio1;

#if defined(CONFIG_RALINK_RT6855A)
	if (chip_id == RT6855A_CHIP) {
		unsigned int data;

		data = sysRegRead(RALINK_REG_GPIOMODE);
		data &= ~(1L << 1);
		data &= ~(1L << 12);
		sysRegWrite(RALINK_REG_GPIOMODE, data);

		if (isRT6855) {
			ephy_relay_gpio0 = 1;
			ephy_relay_gpio1 = 10;
			set_gpio_idx_dir(ephy_relay_gpio0, GPIO_OUTPUT);
			set_gpio_idx_dir(ephy_relay_gpio1, GPIO_OUTPUT);
		}
		else if (isRT6856) {
			ephy_relay_gpio0 = 2;
			ephy_relay_gpio1 = 10;
			set_gpio_idx_dir(ephy_relay_gpio0, GPIO_OUTPUT);
			set_gpio_idx_dir(ephy_relay_gpio1, GPIO_OUTPUT);
		}
		else {
		}

		set_gpio_idx_dir(SLT_DUT_REBOOT_GPIO, GPIO_INPUT);
		set_gpio_idx_dir(SLT_EOT_GPIO, GPIO_OUTPUT);
		set_gpio_idx_dir(SLT_BIN_IND0_GPIO, GPIO_OUTPUT);
		set_gpio_idx_dir(SLT_BIN_IND1_GPIO, GPIO_OUTPUT);

	}
#elif defined (CONFIG_RALINK_MT7620)
	if (chip_id == MT7620_CHIP) {
		unsigned int data;

		data = sysRegRead(RALINK_REG_GPIOMODE);
		data |= (1L << 11);
		sysRegWrite(RALINK_REG_GPIOMODE, data);

		ephy_relay_gpio0 = 0;
		ephy_relay_gpio1 = 37;
		set_gpio_idx_dir(ephy_relay_gpio0, GPIO_OUTPUT);
		set_gpio_idx_dir(ephy_relay_gpio1, GPIO_OUTPUT);
	}
#endif


	return 0;
}

int __init slt_init(void)
{
	unsigned int chip_id, chip_id2;
	unsigned int port5_test = 0, check_payload = 1;
	unsigned int test_item_result = 0;

	if (check_chip_id(&chip_id, &chip_id2) != 1) {
		printk("\nSLT: Chip ID is not matched! chip_id=RT%x chip_id2=RT%x\n", 
			chip_id, chip_id2);
		bin_classify(chip_id, CHIP_ID_FAIL_BIN);
		if (test_all_f == false)
			return 0;
	}

	print_ver(chip_id, chip_id2);
	slt_proc_init();
	config_slt_gpio(chip_id, chip_id2);

	if ((chip_id2 == MT7620A_CHIP) || (chip_id2 == RT6856_CHIP)) {
		port5_test = 1;
		/* port5 reset */
		if (chip_id2 == RT6856_CHIP) {
			set_gpio_idx_dir(30, GPIO_OUTPUT);
			set_gpio_idx(30, 1);
		}
	}

	/* do this early to save time (two relay switch time) */
	set_eth_relay(chip_id, RELAY_OPEN, 0);	

	if (test_item & TEST_DRAM) {
		printk("\n\n===Start DRAM Test======================\n");
		if (slt_dram_test(chip_id) == 1) {
			test_item_result |= TEST_SPI;
			slt_dram_result = 1;
			printk("SLT: DRAM test passed.\n");
		}
		else {
			slt_dram_result = 2;
			printk("SLT: DRAM test failed.\n");
			bin_classify(chip_id, DRAM_FAIL_BIN);
			if (test_all_f == false)
				return 0;
		}
	}

	if (test_item & TEST_SPI) {
		printk("\n\n===Start SPI Test=======================\n");
		if (slt_spi_test(chip_id) == 1) {
			test_item_result |= TEST_SPI;
			slt_spi_result = 1;
			printk("SLT: SPI test passed.\n");
		}
		else {
			slt_spi_result = 2;
			printk("SLT: SPI test failed.\n");
			bin_classify(chip_id, SPI_FAIL_BIN);
			if (test_all_f == false)
				return 0;
		}
	}

	if (test_item & TEST_NAND) {
		if (chip_id2 == RT6856_CHIP) {
			printk("\n\n===Start NAND Test======================\n");
			if (slt_nand_test(chip_id) == 1) {
				test_item_result |= TEST_NAND;
				slt_nand_result = 1;
				printk("SLT: NAND test passed.\n");
			}
			else {
				slt_nand_result = 2;
				printk("SLT: NAND test failed.\n");
				bin_classify(chip_id, NAND_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}
		}
	}

	if (test_item & TEST_USB_HOST) {
		printk("\n\n===Start USB Host Test==================\n");
		if (slt_usb_host_test(chip_id, chip_id2) == 1) {
			test_item_result |= TEST_USB_HOST;
			slt_usb_host_result = 1;
			printk("SLT: USB Host test passed.\n");
		}
		else {
			slt_usb_host_result = 2;
			printk("SLT: USB Host test failed.\n");
			bin_classify(chip_id, USB_HOST_FAIL_BIN);
			if (test_all_f == false)
				return 0;
		}
	}

	if (test_item & TEST_UARTLITE) {
		/* RT6856 and MT7620 use UART-Lite to communicate with handler,
		 * so UART-Lite test is not necessary 
		 */
		//if ((chip_id == RT6855A_CHIP) || (chip_id2 == MT7620A_CHIP)) {
		if (0) {
			printk("\n\n===Start UART-Lite Test=================\n");
			if (slt_uartlite_test(chip_id, chip_id2) == 1) {
				test_item_result |= TEST_UARTLITE;
				slt_uart_lite_result = 1;
				printk("SLT: UART-Lite test passed.\n");
			}
			else {
				slt_uart_lite_result = 2;
				printk("SLT: UART-Lite test failed.\n");
				bin_classify(chip_id, UART_LITE_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}
		}
	}

	if (test_item & TEST_PCIE) {
		if ((chip_id == RT6855A_CHIP) || (chip_id2 == MT7620A_CHIP)) {
			printk("\n\n===Start PCIe Test======================\n");
			if (slt_pcie_test(chip_id, chip_id2) == 1) {
				test_item_result |= TEST_PCIE;
				slt_pcie_result = 1;
				printk("SLT: PCIe test passed.\n");
			}
			else {
				slt_pcie_result = 2;
				printk("SLT: PCIe test failed.\n");
				bin_classify(chip_id, PCIE_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}
		}
	}

	if (test_item & TEST_SD) {
		if (chip_id2 == MT7620A_CHIP) {	
			printk("\n\n===Start SD Test========================\n");
			if (slt_sd_host_test(chip_id, chip_id2) == 1) {
				test_item_result |= TEST_SD;
				slt_sd_result = 1;
				printk("SLT: SD test passed.\n");
			}
			else {
				slt_sd_result = 2;
				printk("SLT: SD test failed.\n");
				bin_classify(chip_id, SD_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}
		}
	}

	if (test_item & TEST_PCM) {
		if ((chip_id2 == MT7620A_CHIP) || (chip_id2 == RT6856_CHIP)) {
			printk("\n\n===Start PCM Test=======================\n");
			if (slt_pcm_test(chip_id) == 1) {
				test_item_result |= TEST_PCM;
				slt_pcm_result = 1;
				printk("SLT: PCM test passed.\n");
			}
			else {
				slt_pcm_result = 2;
				printk("SLT: PCM test failed.\n");
				bin_classify(chip_id, PCM_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}
		}
	}

	if (test_item & TEST_I2S) {
		if (chip_id2 == MT7620A_CHIP) {
			printk("\n\n===Start I2S Test=======================\n");
			if (slt_i2s_test(chip_id) == 1) {
				test_item_result |= TEST_I2S;
				slt_i2s_result = 1;
				printk("SLT: I2S test passed.\n");
			}
			else {
				slt_i2s_result = 2;
				printk("SLT: I2S test failed.\n");
				bin_classify(chip_id, I2S_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}
		}
	}

	if (test_item & TEST_EPHY) {
		int ret;

		printk("\n\n===Start EPHY&RGMII Test================\n");
		ret = slt_ephy_test(chip_id, port5_test, check_payload);
		if (ret == 1) {
			test_item_result |= TEST_EPHY;
			test_item_result |= TEST_RGMII;
			slt_ephy_result = 1;
			slt_rgmii_result = 1;
			printk("SLT: EPHY test passed.\n");
			printk("SLT: RGMII test passed.\n");
		}
		else if (ret == -1) {
			slt_ephy_result = 2;
			printk("SLT: EPHY 100M 100Meter test failed.\n");
			bin_classify(chip_id, EPHY_100M_FAIL_BIN);
			if (test_all_f == false)
				return 0;
		}
		else {
			slt_ephy_result = 2;
			slt_rgmii_result = 2;
			printk("SLT: EPHY test failed.\n");
			printk("SLT: RGMII test failed.\n");
			bin_classify(chip_id, EPHY_FAIL_BIN);
			if (test_all_f == false)
				return 0;
		}
	}

#if 0
	if (test_item & TEST_WIFI) {
		if ((chip_id == MT7620_CHIP)) {
			printk("\n\n===Start WiFi Test========================\n");
			if (slt_wifi_test(chip_id, chip_id2) == 1) {
				test_item_result |= TEST_WIFI;
				slt_wifi_result = 1;
				printk("SLT: WiFi test passed.\n");
			}
			else {
				slt_wifi_result = 2;
				printk("SLT: WiFi test failed.\n");
				bin_classify(chip_id, WIFI_FAIL_BIN);
				if (test_all_f == false)
					return 0;
			}	
		}
	}
#endif

	slt_eot_f = 1;
	printk("\n\n------------------------------------------\n");
	printk("\n\nTest Result=%x\n", test_item_result);
	bin_classify(chip_id, PASS_BIN);

	return 0;
}

void __exit slt_exit(void)
{
	slt_proc_exit();
}

module_init(slt_init);
module_exit(slt_exit);
module_param(test_all_f, bool, 0644);
module_param(test_item, uint, 0644);
module_param(wifi_pass_th, int, 0644);
module_param(wifi_throughput, int, 0644);
