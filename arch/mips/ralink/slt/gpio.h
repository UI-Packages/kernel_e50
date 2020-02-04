
#define GPIO_INPUT	0
#define GPIO_OUTPUT	1

unsigned long get_gpio(int index);
int set_gpio(int index, unsigned int value);
int get_gpio_idx(unsigned int idx);
int set_gpio_idx(unsigned int idx, unsigned int value);
unsigned long get_gpio_dir(int index);
int set_gpio_dir(int index, unsigned int value);
int get_gpio_idx_dir(unsigned int idx);
int set_gpio_idx_dir(unsigned int idx, unsigned int value);
