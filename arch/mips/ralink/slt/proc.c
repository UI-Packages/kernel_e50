#include <linux/kernel.h>
#include <linux/proc_fs.h>

#include <asm/uaccess.h>

struct proc_dir_entry *proc_slt_dir;
struct proc_dir_entry *proc_bin;
struct proc_dir_entry *proc_eot;
struct proc_dir_entry *proc_spi;
struct proc_dir_entry *proc_usb_host;
struct proc_dir_entry *proc_dram;
struct proc_dir_entry *proc_uart_lite;
struct proc_dir_entry *proc_pcie;
struct proc_dir_entry *proc_sd;
struct proc_dir_entry *proc_pcm;
struct proc_dir_entry *proc_i2s;
struct proc_dir_entry *proc_rgmii;
struct proc_dir_entry *proc_ephy;
struct proc_dir_entry *proc_nand;
struct proc_dir_entry *proc_wifi;
struct proc_dir_entry *proc_wifi_pass_th;
struct proc_dir_entry *proc_wifi_throughput;

extern int slt_bin_result;
extern int slt_eot_f;
extern int slt_spi_result;
extern int slt_usb_host_result;
extern int slt_dram_result;
extern int slt_uart_lite_result;
extern int slt_pcie_result;
extern int slt_sd_result;
extern int slt_pcm_result;
extern int slt_i2s_result;
extern int slt_rgmii_result;
extern int slt_ephy_result;
extern int slt_nand_result;
extern int slt_wifi_result;
extern int slt_wifi_pass_th;
extern int slt_wifi_throughput;

static int get_bin(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_bin_result);

	*eof = 1;

	return (p - page);
}

static int set_bin(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_bin_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set EOT to %d\n", slt_bin_result);

	return count;
}

static int get_eot(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_eot_f);

	*eof = 1;

	return (p - page);
}

static int set_eot(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_eot_f = simple_strtoul(buf, NULL, 10);
	printk("SLT: set EOT to %d\n", slt_eot_f);

	return count;
}

static int get_spi(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_spi_result);

	*eof = 1;

	return (p - page);
}

static int set_spi(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_spi_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set SPI to %d\n", slt_spi_result);

	return count;
}


static int get_usb_host(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_usb_host_result);

	*eof = 1;

	return (p - page);
}

static int set_usb_host(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_usb_host_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set USB Host to %d\n", slt_usb_host_result);

	return count;
}

static int get_dram(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_dram_result);

	*eof = 1;

	return (p - page);
}

static int set_dram(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_dram_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set SDRAM to %d\n", slt_dram_result);

	return count;
}

static int get_uart_lite(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_uart_lite_result);

	*eof = 1;

	return (p - page);
}

static int set_uart_lite(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_uart_lite_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set UART Lite to %d\n", slt_uart_lite_result);

	return count;
}

static int get_pcie(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_pcie_result);

	*eof = 1;

	return (p - page);
}

static int set_pcie(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_pcie_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set PCIe to %d\n", slt_pcie_result);

	return count;
}

static int get_sd(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_sd_result);

	*eof = 1;

	return (p - page);
}

static int set_sd(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_sd_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set SD to %d\n", slt_sd_result);

	return count;
}

static int get_pcm(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_pcm_result);

	*eof = 1;

	return (p - page);
}

static int set_pcm(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_pcm_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set PCM to %d\n", slt_pcm_result);

	return count;
}

static int get_i2s(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_i2s_result);

	*eof = 1;

	return (p - page);
}

static int set_i2s(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_i2s_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set I2S to %d\n", slt_i2s_result);

	return count;
}

static int get_rgmii(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_rgmii_result);

	*eof = 1;

	return (p - page);
}

static int set_rgmii(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_rgmii_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set RGMII to %d\n", slt_rgmii_result);

	return count;
}

static int get_ephy(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d\n", slt_ephy_result);

	*eof = 1;

	return (p - page);
}

static int set_ephy(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_ephy_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set EPHY to %d\n", slt_ephy_result);

	return count;
}

static int get_nand(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d", slt_nand_result);

	*eof = 1;

	return (p - page);
}

static int set_nand(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_nand_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set NAND to %d\n", slt_nand_result);

	return count;
}

static int get_wifi(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d", slt_wifi_result);

	*eof = 1;

	return (p - page);
}

static int set_wifi(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_wifi_result = simple_strtoul(buf, NULL, 10);
	printk("SLT: set wifi to %d\n", slt_wifi_result);

	return count;
}

static int get_wifi_pass_th(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d", slt_wifi_pass_th);

	*eof = 1;

	return (p - page);
}

static int set_wifi_pass_th(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_wifi_pass_th = simple_strtoul(buf, NULL, 10);
	printk("SLT: set WiFi pass threshold to %d\n", slt_wifi_pass_th);

	return count;
}

static int get_wifi_throughput(char *page, char **start, off_t off, int count,
			  int *eof, void *data_unused)
{
	char *p = page;

	p += sprintf(p, "%d", slt_wifi_throughput);

	*eof = 1;

	return (p - page);
}

static int set_wifi_throughput(struct file *file, const char *buffer, unsigned long count, void *data)
{
        char buf[32];

        if (count > 32)
                count = 32;

        memset(buf, 0, 32);
        if (copy_from_user(buf, buffer, count))
                return -EFAULT;

	slt_wifi_throughput = simple_strtoul(buf, NULL, 10);
	printk("SLT: set WiFi throughput to %d\n", slt_wifi_throughput);

	return count;
}


int slt_proc_init(void)
{
	if (proc_slt_dir == NULL)
		proc_slt_dir = proc_mkdir("slt", NULL);

	if ((proc_bin = create_proc_entry("bin", 0, proc_slt_dir))) {
		proc_bin->read_proc = (read_proc_t*)&get_bin;
		proc_bin->write_proc = (write_proc_t*)&set_bin;
	}

	if ((proc_eot = create_proc_entry("eot", 0, proc_slt_dir))) {
		proc_eot->read_proc = (read_proc_t*)&get_eot;
		proc_eot->write_proc = (write_proc_t*)&set_eot;
	}
    
	if ((proc_spi = create_proc_entry("spi", 0, proc_slt_dir))) {
		proc_spi->read_proc = (read_proc_t*)&get_spi;
		proc_spi->write_proc = (write_proc_t*)&set_spi;
	}
    
	if ((proc_usb_host = create_proc_entry("usb_host", 0, proc_slt_dir))) {
		proc_usb_host->read_proc = (read_proc_t*)&get_usb_host;
		proc_usb_host->write_proc = (write_proc_t*)&set_usb_host;
	}

	if ((proc_dram = create_proc_entry("dram", 0, proc_slt_dir))) {
		proc_dram->read_proc = (read_proc_t*)&get_dram;
		proc_dram->write_proc = (write_proc_t*)&set_dram;
	}

	if ((proc_uart_lite = create_proc_entry("uart_lite", 0, proc_slt_dir))) {
		proc_uart_lite->read_proc = (read_proc_t*)&get_uart_lite;
		proc_uart_lite->write_proc = (write_proc_t*)&set_uart_lite;
	}
    
	if ((proc_pcie = create_proc_entry("pcie", 0, proc_slt_dir))){
		proc_pcie->read_proc = (read_proc_t*)&get_pcie;
		proc_pcie->write_proc = (write_proc_t*)&set_pcie;
	}

    	if ((proc_sd = create_proc_entry("sd", 0, proc_slt_dir))){
		proc_sd->read_proc = (read_proc_t*)&get_sd;
		proc_sd->write_proc = (write_proc_t*)&set_sd;
	}

    	if ((proc_pcm = create_proc_entry("pcm", 0, proc_slt_dir))){
		proc_pcm->read_proc = (read_proc_t*)&get_pcm;
		proc_pcm->write_proc = (write_proc_t*)&set_pcm;
	}
    	if ((proc_i2s = create_proc_entry("i2s", 0, proc_slt_dir))){
		proc_i2s->read_proc = (read_proc_t*)&get_i2s;
		proc_i2s->write_proc = (write_proc_t*)&set_i2s;
	}

	if ((proc_rgmii = create_proc_entry("rgmii", 0, proc_slt_dir))){
		proc_rgmii->read_proc = (read_proc_t*)&get_rgmii;
		proc_rgmii->write_proc = (write_proc_t*)&set_rgmii;
	}

	if ((proc_ephy = create_proc_entry("ephy", 0, proc_slt_dir))){
		proc_ephy->read_proc = (read_proc_t*)&get_ephy;
		proc_ephy->write_proc = (write_proc_t*)&set_ephy;
	}

	if ((proc_nand = create_proc_entry("nand", 0, proc_slt_dir))){
		proc_nand->read_proc = (read_proc_t*)&get_nand;
		proc_nand->write_proc = (write_proc_t*)&set_nand;
	}

	if ((proc_wifi = create_proc_entry("wifi", 0, proc_slt_dir))){
		proc_wifi->read_proc = (read_proc_t*)&get_wifi;
		proc_wifi->write_proc = (write_proc_t*)&set_wifi;
	}

	if ((proc_wifi_pass_th = create_proc_entry("wifi_pass_th", 0, proc_slt_dir))){
		proc_wifi_pass_th->read_proc = (read_proc_t*)&get_wifi_pass_th;
		proc_wifi_pass_th->write_proc = (write_proc_t*)&set_wifi_pass_th;
	}

	if ((proc_wifi_throughput = create_proc_entry("wifi_throughput", 0, proc_slt_dir))){
		proc_wifi_throughput->read_proc = (read_proc_t*)&get_wifi_throughput;
		proc_wifi_throughput->write_proc = (write_proc_t*)&set_wifi_throughput;
	}



	return 1;   
}

int slt_proc_exit(void)
{
	if (proc_bin != NULL)
		remove_proc_entry("bin", proc_slt_dir);

	if (proc_eot != NULL)
		remove_proc_entry("eot", proc_slt_dir);

	if (proc_spi != NULL)
		remove_proc_entry("spi", proc_slt_dir);

	if (proc_usb_host != NULL)
		remove_proc_entry("usb_host", proc_slt_dir);

	if (proc_dram != NULL)
		remove_proc_entry("dram", proc_slt_dir);

	if (proc_uart_lite != NULL)
		remove_proc_entry("uart_lite", proc_slt_dir);

	if (proc_pcie != NULL)
		remove_proc_entry("pcie", proc_slt_dir);

	if (proc_sd != NULL)
		remove_proc_entry("sd", proc_slt_dir);

	if (proc_pcm != NULL)
		remove_proc_entry("pcm", proc_slt_dir);

	if (proc_i2s != NULL)
		remove_proc_entry("i2s", proc_slt_dir);

	if (proc_rgmii != NULL)
		remove_proc_entry("rgmii", proc_slt_dir);


	if (proc_ephy != NULL)
		remove_proc_entry("ephy", proc_slt_dir);

	if (proc_nand != NULL)
		remove_proc_entry("nand", proc_slt_dir);
	
	if (proc_wifi != NULL)
		remove_proc_entry("wifi", proc_slt_dir);

	if (proc_wifi != NULL)
		remove_proc_entry("wifi_pass_th", proc_slt_dir);
	
	if (proc_wifi != NULL)
		remove_proc_entry("wifi_throughput", proc_slt_dir);

	if (proc_slt_dir != NULL)
		remove_proc_entry("slt", NULL);

	return 0;  
}

