#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/i2c.h>
#include <linux/module.h>

struct isl28022_data {
	struct i2c_client *client;
};

static s32 read_reg(struct device *dev, int reg)
{
	struct isl28022_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;

	u16 val = i2c_smbus_read_word_data(client, reg);
	return (val >= 0 ) ? be16_to_cpu(val) : -1;
}

static ssize_t isl28022_read_curr(struct device *dev, struct device_attribute *devattr, char *buf)
{
	u16 reg = read_reg(dev, 1);
	int val = 0;
	if (reg > 0) {
		if(reg & 0x8000)
		val += -32768;
		val += reg & ~(0x8000);
		val *= 10;
		val = DIV_ROUND_CLOSEST(val, 8);
	}
	return sprintf(buf, "%d\n", val);
}

static ssize_t isl28022_read_in(struct device *dev, struct device_attribute *devattr, char *buf)
{
	u16 reg = read_reg(dev, 2);
	int val = 0;
	if (reg > 0) {
		val = (reg >> 2) * 4;
	}
	return sprintf(buf, "%d\n", val);
}

static SENSOR_DEVICE_ATTR(in1_input, S_IRUGO, isl28022_read_in, NULL, 0);
static SENSOR_DEVICE_ATTR(curr1_input, S_IRUGO, isl28022_read_curr, NULL, 0);

static struct attribute *isl28022_attrs[] = {
	&sensor_dev_attr_in1_input.dev_attr.attr,
	&sensor_dev_attr_curr1_input.dev_attr.attr,
	NULL
};

ATTRIBUTE_GROUPS(isl28022);

static const struct i2c_device_id isl28022_id[] = {
	{ "isl28022", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, isl28022_id);

static const struct of_device_id isl28022_of_ids[] = {
	{
		.compatible = "renesas,isl28022",
	},
	{},
};
MODULE_DEVICE_TABLE(of, isl28022_of_ids);

static int isl28022_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct device *dev = &client->dev;
	struct isl28022_data *data;
	struct device *hwmon_dev;

	data = devm_kzalloc(dev, sizeof(struct isl28022_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->client = client;

	hwmon_dev = devm_hwmon_device_register_with_groups(dev, client->name, data, isl28022_groups);
	return PTR_ERR_OR_ZERO(hwmon_dev);
}

static struct i2c_driver isl28022_driver = {
	.driver = {
		.name = "isl28022",
		.of_match_table	= isl28022_of_ids,
	},
	.probe = isl28022_probe,
	.id_table = isl28022_id,
};

module_i2c_driver(isl28022_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jan Kraval <jan.kraval@ubnt.com>");
MODULE_DESCRIPTION("Driver for Renesas ISL28022 Precision Digital Power Monitor");
