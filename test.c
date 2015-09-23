/* MPI sgl_read and sgl_write tests
 *
 * Copyright Tadeusz Struk <tstruk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/mpi.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <crypto/scatterwalk.h>

static u8 buf[] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
		    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                   10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                   20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                   30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                   40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
                   50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
                   60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
                   70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                   80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
                   90, 91, 92, 93, 94, 95, 96, 97, 98, 99 };

static void dump(char *mem, unsigned int len)
{
        unsigned int i;

	printk("addr: %p, len %d \n", mem, len);
        for (i = 0; i < len ; i++)
        {
                if (!(i % 0x10))
                        printk("0x%04x: ", i);

                if (i < len)
                        printk("%02x ", 0xff & *(mem + i));

		if (i && !((i + 1) % 0x10))
			printk("\n");
        }
	printk("\n");
}

static void dump_mpi(MPI m)
{
	unsigned int size = mpi_get_size(m), len;
	char *buff = kmalloc(size, GFP_KERNEL);

	if (!buff)
		return;

	mpi_read_buffer(m, buff, size, &len, NULL);
	dump(buff, size);
	pr_info("Got %d bytes\n", len);
	kfree(buff);
}

static void dump_sg(struct scatterlist *sg)
{
	unsigned int size = sg_len(sg);
	char *buff = kmalloc(size, GFP_KERNEL);

	if (!buff)
		return;

	scatterwalk_map_and_copy(buff, sg, 0, size, 0);
	dump(buff, size);
	pr_info("Got %d bytes\n", size);
	kfree(buff);
}

int test_read(void)
{
	MPI n1, n2, n3;
	struct scatterlist sg;
	struct scatterlist sg_tab[7];
	int ret = -ENOMEM;
	u8 *ptr = kmalloc(sizeof(buf), GFP_KERNEL);

	pr_info("test_read\n");
	if (!ptr)
		return ret;

	memcpy(ptr, buf, sizeof(buf));

	n1 = mpi_read_raw_data(buf, sizeof(buf));
	if (!n1) {
		pr_err("mpi_read_raw_data failed\n");
		return ret;
	}
	pr_info("n1:\n");
	dump_mpi(n1);
	mpi_free(n1);

	sg_init_one(&sg, ptr, sizeof(buf));

	n2 = mpi_read_raw_from_sgl(&sg);
	if (!n2) {
		pr_err("mpi_read_raw_from_sgl single failed\n");
		goto free;
	}
	pr_info("n2:\n");
	dump_mpi(n2);
	mpi_free(n2);

	sg_init_table(sg_tab, 7);
	sg_set_buf(sg_tab, ptr, 5);
	sg_set_buf(sg_tab + 1, ptr + 5, 9);
	sg_set_buf(sg_tab + 2, ptr + 14, 2);
	sg_set_buf(sg_tab + 3, ptr + 16, 5);
	sg_set_buf(sg_tab + 4, ptr + 21, 15);
	sg_set_buf(sg_tab + 5, ptr + 36, 69);
	sg_set_buf(sg_tab + 6, ptr + 105, 5);

	n3 = mpi_read_raw_from_sgl(sg_tab);
	if (!n3) {
		pr_err("mpi_read_raw_from_sgl tab failed\n");
		goto free;
	}
	pr_info("n3:\n");
	dump_mpi(n3);
	mpi_free(n3);
	kfree(ptr);
	return 0;

free:
	kfree(ptr);
	return ret;
}

int test_write(void)
{
	MPI n;
	struct scatterlist sg_tab[7];
	int ret = -ENOMEM, nbytes;
	u8 *ptr = kzalloc(sizeof(buf), GFP_KERNEL);

	pr_info("test_write\n");
	if (!ptr)
		return ret;

	n = mpi_read_raw_data(buf, sizeof(buf));
	if (!n) {
		pr_err("mpi_read_raw_data failed\n");
		return ret;
	}

	sg_init_table(sg_tab, 7);
	sg_set_buf(sg_tab, ptr, 5);
	sg_set_buf(sg_tab + 1, ptr + 5, 9);
	sg_set_buf(sg_tab + 2, ptr + 14, 2);
	sg_set_buf(sg_tab + 3, ptr + 16, 5);
	sg_set_buf(sg_tab + 4, ptr + 21, 15);
	sg_set_buf(sg_tab + 5, ptr + 36, 69);
	sg_set_buf(sg_tab + 6, ptr + 105, 5);

	ret = mpi_write_to_sgl(n, sg_tab, &nbytes, NULL);
	if (ret) {
		pr_err("mpi_write_to_sgl failed\n");
		goto free;
	}

	dump_sg(sg_tab);
	ret = 0;
free:
	mpi_free(n);
	kfree(ptr);
	return ret;

}

int test_init(void)
{
	pr_info("init\n");
	if (test_read())
		pr_info("mpi read test failed\n");

	if (test_write())
		pr_info("mpi write test failed\n");

	return 0;
}

void test_exit(void)
{
	pr_info("exit\n");
}

MODULE_LICENSE("GPL");
module_init(test_init);
module_exit(test_exit);
