#ifndef SLT_H
#define SLT_H

#define RT6855_SLT_VERSION	RT6856_SLT_VERSION
#define RT6856_SLT_VERSION	"1.4"
#define MT7620_SLT_VERSION	"1.4"

#define PHYS_TO_K1(physaddr) KSEG1ADDR(physaddr)
#define sysRegRead(phys) (*(volatile unsigned int *)PHYS_TO_K1(phys))
#define sysRegWrite(phys, val) ((*(volatile unsigned int *)PHYS_TO_K1(phys)) = (val))


/* GPIO BIN definition */
#if defined (CONFIG_RALINK_RT6855A)
#define SLT_DUT_REBOOT_GPIO	0
#define SLT_EOT_GPIO		1
#define SLT_REBOOT_GPIO		0
#define SLT_BIN_IND0_GPIO	7
#define SLT_BIN_IND1_GPIO	8
#elif defined (CONFIG_RALINK_MT7620)
#define SLT_DUT_REBOOT_GPIO	0
#define SLT_EOT_GPIO		20
#define SLT_REBOOT_GPIO		0
#define SLT_ETH_RELAY0_GPIO	1
#define SLT_ETH_RELAY1_GPIO	2
#define SLT_BIN_IND0_GPIO	18
#define SLT_BIN_IND1_GPIO	19
#endif


#define BIN1	1
#define BIN2	2
#define BIN3	3
#define BIN4	4

#if defined (CONFIG_RALINK_RT6855A)
#define PASS_BIN		BIN1
#define CHIP_ID_FAIL_BIN	BIN3
#define DRAM_FAIL_BIN		BIN3
#define SPI_FAIL_BIN		BIN3
#define UART_LITE_FAIL_BIN	BIN2
#define USB_HOST_FAIL_BIN	BIN4
#define PCIE_FAIL_BIN		BIN3
#define SD_FAIL_BIN		BIN3
#define PCM_FAIL_BIN		BIN3
#define I2S_FAIL_BIN		BIN3
#define EPHY_FAIL_BIN		BIN3
#define EPHY_100M_FAIL_BIN	BIN2
#define RGMII_FAIL_BIN		BIN3
#define NAND_FAIL_BIN		BIN3
#elif defined (CONFIG_RALINK_MT7620)
#define PASS_BIN		BIN1
#define CHIP_ID_FAIL_BIN	BIN2
#define DRAM_FAIL_BIN		BIN2
#define SPI_FAIL_BIN		BIN2
#define USB_HOST_FAIL_BIN	BIN3
#define UART_LITE_FAIL_BIN	BIN2
#define PCIE_FAIL_BIN		BIN2
#define SD_FAIL_BIN		BIN2
#define PCM_FAIL_BIN		BIN2
#define I2S_FAIL_BIN		BIN2
#define EPHY_FAIL_BIN		BIN2
#define EPHY_100M_FAIL_BIN	BIN4
#define RGMII_FAIL_BIN		BIN2
#define NAND_FAIL_BIN		BIN2
#define WIFI_FAIL_BIN		BIN3
#else
#define PASS_BIN		BIN1
#define CHIP_ID_FAIL_BIN	BIN2
#define DRAM_FAIL_BIN		BIN2
#define SPI_FAIL_BIN		BIN2
#define USB_HOST_FAIL_BIN	BIN3
#define UART_LITE_FAIL_BIN	BIN2
#define PCIE_FAIL_BIN		BIN2
#define SD_FAIL_BIN		BIN2
#define PCM_FAIL_BIN		BIN2
#define I2S_FAIL_BIN		BIN2
#define EPHY_FAIL_BIN		BIN2
#define EPHY_100M_FAIL_BIN	BIN4
#define RGMII_FAIL_BIN		BIN2
#define NAND_FAIL_BIN		BIN2
#endif


#define RELAY_100M	0
#define RELAY_LPBK	1
#define RELAY_OPEN	2

#define GPIO_LOW(x)	set_gpio_idx(x, 0)
#define GPIO_HIGH(x)	set_gpio_idx(x, 1)

#define RT6855A_CHIP	0x6855A
/* DRQFN */
#define RT6855_CHIP	0x6855
/* TFBGA */
#define RT6856_CHIP	0x6856

#define MT7620_CHIP	0x7620
/* TFBGA */
#define MT7620A_CHIP	0x7620A
/* DRQFN */
#define MT7620N_CHIP	0x7620B


#define TEST_ALL	0xFFFF
#define TEST_SPI	0x0001
#define TEST_DRAM	0x0002
#define TEST_USB_HOST	0x0004
#define TEST_UARTLITE	0x0008
#define TEST_PCIE	0x0010
#define TEST_SD		0x0020
#define TEST_PCM_I2S	0x0040
#define TEST_PCM	0x0080
#define TEST_I2S	0x0100
#define TEST_EPHY	0x0200
#define TEST_RGMII	0x0400
#define TEST_NAND	0x0800
#define TEST_WIFI	0x1000

#define BIN_FAIL	0x0000

#define DRAM_TEST_SIZE		4096
#define DRAM_TEST_ADDR		0xBFC00000

#define UARTLITE_TEST_SIZE	100

#define I2S_TEST_SIZE		50
#define I2S_PRE_TEST_SIZE	25

#define PCIE_TEST_VENDOR_ID	0x1814
#define PCIE_TEST_DEVICE_ID	0x0802

int slt_proc_init(void);
int slt_proc_exit(void);
int pcm_loopback_test(unsigned int chip_id);
int slt_nand_test(unsigned int chip_id);
int slt_ephy_test(unsigned int chip_id, int port_test, int check_payload);
int slt_spi_test(unsigned int chip_id);
int slt_sdram_test(unsigned int chip_id);
int slt_uartlite_test(unsigned int chip_id, unsigned int chip_id2);
int slt_pcie_test(unsigned int chip_id, unsigned int chip_id2);
int slt_sd_test(unsigned int chip_id);
int slt_pcm_i2s_test(unsigned int chip_id);
int slt_rgmii_test(unsigned int chip_id);
int set_eth_relay(unsigned int chip_id, int type, int sleep);
int wait_link_up(int esw, int port5);
#endif /* SLT_H */
