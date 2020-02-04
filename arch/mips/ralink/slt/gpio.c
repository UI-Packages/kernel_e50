#include <linux/types.h>
#include <linux/kernel.h>

#if defined (CONFIG_RALINK_RT6855A)
#include "../../../../../linux-2.6.36MT.x/drivers/char/ralink_gpio.h"
#else
#include "../../../../drivers/char/ralink_gpio.h"
#endif
#include "gpio.h"

unsigned long get_gpio(int index)
{
	unsigned long tmp = 0;

#if defined (CONFIG_RALINK_RT6855A)
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));

	return tmp;
#elif defined (CONFIG_RALINK_MT7620)
	if (index == 0)
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));
	else if (index == 24)
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3924DATA));
	else if (index == 40)
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO7140DATA));
	else
		return -1;

	return tmp;
#endif

	return -1;
}

int set_gpio(int index, unsigned int value)
{
#if defined (CONFIG_RALINK_RT6855A)
	*(volatile u32 *)(RALINK_REG_PIODATA)= cpu_to_le32(value);
#elif defined (CONFIG_RALINK_MT7620)
	if (index == 0)
		*(volatile u32 *)(RALINK_REG_PIODATA)= cpu_to_le32(value);
	else if (index == 24)
		*(volatile u32 *)(RALINK_REG_PIO3924DATA)= cpu_to_le32(value);
	else if (index == 40)
		*(volatile u32 *)(RALINK_REG_PIO7140DATA)= cpu_to_le32(value);
	else
		return -1;

#endif

	return get_gpio(index);
}

int get_gpio_idx(unsigned int idx)
{
	unsigned long tmp;

#if defined (CONFIG_RALINK_RT6855A)
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));
	if ((0L <= idx) && (idx < RALINK_GPIO_DATA_LEN)) {
		tmp = (tmp >> idx) & 1L;
		return tmp;
	}
	else 
		return -1;
#elif defined (CONFIG_RALINK_MT7620)
	if ((0L <= idx) && (idx < 24)) {
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));
		tmp = (tmp >> idx) & 1L;
		return tmp;
	}
	else if (idx < 40) {
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3924DATA));
		tmp = (tmp >> (idx - 24)) & 1L;
		return tmp;
	}
	else if (idx < 72) {
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO7140DATA));
		tmp = (tmp >> (idx - 40)) & 1L;
		return tmp;
	}
	else 
		return -1;
#endif

	return -1;
}

int set_gpio_idx(unsigned int idx, unsigned int value)
{
	unsigned long tmp;

#if defined (CONFIG_RALINK_RT6855A)
	if ((0L <= idx) && (idx < RALINK_GPIO_DATA_LEN)) {
		tmp =le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));
		if (value & 1L)
			tmp |= (1L << idx);
		else
			tmp &= ~(1L << idx);
		*(volatile u32 *)(RALINK_REG_PIODATA) = cpu_to_le32(tmp);

		return get_gpio_idx(idx);
	}
	else
		return -1;

#elif defined (CONFIG_RALINK_MT7620)
	if ((0L <= idx) && (idx < 24)) {
		tmp =le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));
		if (value & 1L)
			tmp |= (1L << idx);
		else
			tmp &= ~(1L << idx);
		*(volatile u32 *)(RALINK_REG_PIODATA) = cpu_to_le32(tmp);

		return get_gpio_idx(idx);
	}
	else if (idx < 40) {
		tmp =le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3924DATA));
		if (value & 1L)
			tmp |= (1L << (idx - 24));
		else
			tmp &= ~(1L << (idx - 24));
		*(volatile u32 *)(RALINK_REG_PIO3924DATA) = cpu_to_le32(tmp);

		return get_gpio_idx(idx);
	}
	else if (idx < 72) {
		tmp =le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO7140DATA));
		if (value & 1L)
			tmp |= (1L << (idx - 40));
		else
			tmp &= ~(1L << (idx - 40));
		*(volatile u32 *)(RALINK_REG_PIO7140DATA) = cpu_to_le32(tmp);

		return get_gpio_idx(idx);
	}
	else
		return -1;
#endif

	return -1;

}

int get_gpio_idx_dir(unsigned int idx)
{
	unsigned long tmp;

#if defined (CONFIG_RALINK_RT6855A)
	if ((0L <= idx) && (idx <= 15)) 
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
	else
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3116DIR));
	if ((0L <= idx) && (idx < RALINK_GPIO_DATA_LEN)) {
		tmp = (tmp >> idx) & 1L;
		return tmp;
	}
	else 
		return -1;

#elif defined (CONFIG_RALINK_MT7620)
	if ((0L <= idx) && (idx < 24)) {
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
		tmp = (tmp >> idx) & 1L;
		return tmp;
	}
	else if (idx < 40) {
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3924DIR));
		tmp = (tmp >> idx) & 1L;
		return tmp;
	}
	else if (idx < 72) {
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO7140DIR));
		tmp = (tmp >> idx) & 1L;
		return tmp;
	}
	else 
		return -1;
#endif

	return -1;
}

int set_gpio_idx_dir(unsigned int idx, unsigned int value)
{
	unsigned long tmp = 0;

	if (value == GPIO_INPUT) {
#if defined (CONFIG_RALINK_RT6855A)
		if ((0L <= idx) && (idx <= 15)) {
			tmp =le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
			tmp &= ~(0x3 << (idx * 2));
			*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(tmp);
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
			tmp &= ~(0x1 << idx);
			*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		}
		else if ((16 <= idx) && (idx <= 31)) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3116DIR));
			tmp &= ~(0x3 << ((idx - 16)* 2));
			*(volatile u32 *)(RALINK_REG_PIO3116DIR) = cpu_to_le32(tmp);
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
			tmp &= ~(0x1 << idx);
			*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		}
		else {
			printk("set_gpio_idx_dir: index(%d) out of range\n", idx);
			return -1;
		}
#elif defined (CONFIG_RALINK_MT7620)
		if ((0L <= idx) && (idx < 24)) {
			tmp &= ~(0x1 << idx);
			*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(tmp);
		}
		else if (idx < 40) {
			tmp &= ~(0x1 << (idx - 24));
			*(volatile u32 *)(RALINK_REG_PIO3924DIR) = cpu_to_le32(tmp);
		}
		else if (idx < 72) {
			tmp &= ~(0x1 << (idx - 40));
			*(volatile u32 *)(RALINK_REG_PIO7140DIR) = cpu_to_le32(tmp);
		}
		else {
			printk("set_gpio_idx_dir: index(%d) out of range\n", idx);
			return -1;
		}
#endif
	}
	else {
#if defined (CONFIG_RALINK_RT6855A)
		if ((0L <= idx) && (idx <= 15)) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
			tmp &= ~(0x3 << (idx * 2));
			tmp |= 0x1 << (idx * 2);
			*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(tmp);
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
			tmp |= 0x1 << idx;
			*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		}
		else if ((16 <= idx) && (idx <= 31)) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3116DIR));
			tmp &= ~(0x3 << ((idx - 16)* 2));
			tmp |= 0x1 << ((idx - 16)* 2);
			*(volatile u32 *)(RALINK_REG_PIO3116DIR) = cpu_to_le32(tmp);
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
			tmp |= 0x1 << idx;
			*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		}
		else {
			printk("set_gpio_idx_dir: index(%d) out of range\n", idx);
			return -1;
		}
#elif defined (CONFIG_RALINK_MT7620)
		if ((0L <= idx) && (idx < 24)) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
			tmp |= 0x1 << idx;
			*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(tmp);
		}
		else if (idx < 40) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3924DIR));
			tmp |= 0x1 << (idx - 24);
			*(volatile u32 *)(RALINK_REG_PIO3924DIR) = cpu_to_le32(tmp);
		}
		else if (idx < 72) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO7140DIR));
			tmp |= 0x1 << (idx - 40);
			*(volatile u32 *)(RALINK_REG_PIO7140DIR) = cpu_to_le32(tmp);
		}
		else {
			printk("set_gpio_idx_dir: index(%d) out of range\n", idx);
			return -1;
		}
#endif
	}

	return get_gpio_idx_dir(idx);
}

unsigned long get_gpio_dir(int index)
{
	unsigned long tmp = 0;

#if defined (CONFIG_RALINK_RT6855A)
	tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
#elif defined (CONFIG_RALINK_MT7620)
	if (index == 0)
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
	else if (index == 24)
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3924DIR));
	else if (index == 40)
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO7140DIR));
	else {
		printk("get_gpio_dir: index(%d) out of range\n", index);
		return -1;
	}
#endif

	return tmp;
}

int set_gpio_dir(int index, unsigned int value)
{
#if defined (CONFIG_RALINK_RT6855A)
	*(volatile u32 *)(RALINK_REG_PIODIR)= cpu_to_le32(value);
#elif defined (CONFIG_RALINK_MT7620)
	if (index == 0)
		*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(value);
	else if (index == 24)
		*(volatile u32 *)(RALINK_REG_PIO3924DIR) = cpu_to_le32(value);
	else if (index == 40)
		*(volatile u32 *)(RALINK_REG_PIO7140DIR) = cpu_to_le32(value);
	else {
		printk("set_gpio_dir: index(%d) out of range\n", index);
		return -1;
	}
#endif

	return get_gpio_dir(index);
}


