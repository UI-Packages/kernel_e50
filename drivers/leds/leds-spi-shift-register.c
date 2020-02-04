#include <linux/leds.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/of_device.h>

struct spi_leds_priv;

struct spi_led_data {
	struct spi_device *spi;
	struct led_classdev	ldev;
	struct spi_leds_priv *priv;
};

struct spi_leds_priv {
	int num_leds;
	u8 *buf;
	struct spi_led_data *leds[];
};

static const struct of_device_id spi_led_data_of_ids[] = {
	{
		.compatible = "leds-spi-shift-register",
	},
	{},
};
MODULE_DEVICE_TABLE(of, spi_led_data_of_ids);

static void leds_spi_shift_register_set_brightness(struct led_classdev *ldev, enum led_brightness brightness)
{
	struct spi_led_data *led = container_of(ldev, struct spi_led_data, ldev);
	u8 *buf = led->priv->buf;
	size_t buf_len = led->priv->num_leds/8;
	int i;

	memset(buf, 0, buf_len);
	for (i=0; i<led->priv->num_leds; i++) {
		int byte = i / 8;
		int bit = 7 - (i % 8);
		if (led->priv->leds[i]) {
			if (led->priv->leds[i]->ldev.brightness) {
				buf[byte] |= 1 << bit;
			}
		}
	}
	spi_write(led->spi, buf, buf_len);
}

static inline int sizeof_spi_leds_priv(int num_leds)
{
	return sizeof(struct spi_leds_priv) +
		(sizeof(struct spi_led_data *) * num_leds);
}

static void leds_spi_shift_register_remove_all(struct spi_leds_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_leds; i++)
		if (priv->leds[i])
			led_classdev_unregister(&priv->leds[i]->ldev);

}
static int leds_spi_shift_register_probe(struct spi_device *spi)
{
	struct spi_leds_priv *priv;
	int ret;
	struct device_node *node_child;
	struct device_node *np = spi->dev.of_node;
	u32 prop;
	int num_leds;

	if (of_property_read_u32(np, "words", &prop) != 0) {
		dev_err(&spi->dev, "Missing DT property words\n");
		return -EINVAL;
	}

	num_leds = prop * 8;

	priv = devm_kzalloc(&spi->dev, sizeof_spi_leds_priv(num_leds), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->buf = devm_kzalloc(&spi->dev, num_leds, GFP_KERNEL);
	if (!priv->buf)
		return -ENOMEM;

	priv->num_leds = num_leds;

	for_each_child_of_node(np, node_child) {
		u32 reg;
		if (of_property_read_u32(node_child, "reg", &reg) != 0) {
			dev_err(&spi->dev, "LED is missing DT property reg\n");
			continue;
		}
		if (reg >= num_leds) {
			dev_err(&spi->dev, "invalid LED (%u >= %d)\n", reg, num_leds);
			continue;
		}
		priv->leds[reg] = devm_kzalloc(&spi->dev, sizeof(struct spi_led_data), GFP_KERNEL);
		if ( ! priv->leds[reg])
			return -ENOMEM;

		priv->leds[reg]->priv = priv;
		priv->leds[reg]->spi = spi;
		priv->leds[reg]->ldev.name = node_child->name;
		priv->leds[reg]->ldev.brightness = LED_OFF;
		priv->leds[reg]->ldev.brightness_set = leds_spi_shift_register_set_brightness;
		ret = led_classdev_register(&spi->dev, &priv->leds[reg]->ldev);
		if (ret < 0) {
			dev_err(&spi->dev, "Failed to register led\n");
			of_node_put(node_child);
			goto error;
		}
	};

	spi_set_drvdata(spi, priv);
	return 0;
error:
	leds_spi_shift_register_remove_all(priv);

	return ret;

}

static int leds_spi_shift_register_remove(struct spi_device *spi)
{
	struct spi_leds_priv *priv = spi_get_drvdata(spi);

	leds_spi_shift_register_remove_all(priv);

	return 0;
}

static struct spi_driver leds_spi_shift_register_driver = {
	.probe		= leds_spi_shift_register_probe,
	.remove		= leds_spi_shift_register_remove,
	.driver = {
		.name	= "leds_spi_shift_register",
		.of_match_table	= spi_led_data_of_ids,
	},
};

module_spi_driver(leds_spi_shift_register_driver);

MODULE_AUTHOR("Jan Kraval <jan.kraval@ubnt.com>");
MODULE_DESCRIPTION("Driver for leds connected to SPI bus via shift register");
MODULE_LICENSE("GPL v2");
