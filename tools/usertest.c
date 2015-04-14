

#include <jtrace.h>
#include <jtrace_common.h>

#include <stdio.h>
#include <assert.h>

int main(int argc, char **argv)
{
	int i;
	jtrace_instance_t *jtri;
	jtrace_instance_t *jtri0;
	jtrace_instance_t *jtri1;
	jtrace_instance_t *jtri2;
	char *id = 0;
	int value1 = 1;
	char hex_dump_data[512];

	for (i = 0; i < 512; i++) {
		hex_dump_data[i] = (char) (i & 0xff);
	}

	INIT_LIST_HEAD(&jtrc_instance_list);

	jtri0 = jtrace_init("test", 0x100000);
	printf("test: %p\n", jtri0);
	assert(jtri0);
	jtri1 = jtrace_init("frog", 0x100000);
	printf("frog: %p\n", jtri1);
	assert(jtri1);
	jtri2 = jtrace_init("bunny", 0x100000);
	printf("bunny: %p\n", jtri2);
	assert(jtri2);
	jtri = jtrc_find_instance_by_name(&jtrc_instance_list, "frog");
	printf("jtrc_find_instance_by_name(frog): %p\n", jtri);
	assert(jtri == jtri1);
	list_del(&jtri->jtrc_list);
	jtri = jtrc_find_instance_by_name(&jtrc_instance_list, "frog");
	assert(jtri == NULL);

	jtrace_put_instance(jtri1);
	jtrace_put_instance(jtri2);

	/* Put some stuff in the trace buffer "test" */
	jtrc_setprint(jtri0, 1);

	jtrc(jtri0, JTR_CONF, id, "First Entry");

	jtrc(jtri0, JTR_CONF, id, "sizeof(jtrc_element_t)=%d",
	     sizeof(jtrc_element_t));
	jtrc(jtri0, JTR_CONF, id, "sizeof(jtrc_regular_element_t)=%d",
	     sizeof(jtrc_regular_element_t));
	jtrc(jtri0, JTR_CONF, id, "sizeof(jtrc_hex_begin_element_t)=%d",
	     sizeof(jtrc_hex_begin_element_t));
	jtrc(jtri0, JTR_CONF, id, "sizeof(jtrc_hex_element_t)=%d",
	     sizeof(jtrc_hex_element_t));
	jtrc(jtri0, JTR_CONF, id, "sizeof(jtrc_element_fmt_t)=%d",
	     sizeof(jtrc_element_fmt_t));
	jtrc(jtri0, JTR_CONF, id, "offsetof(jtrc_element_t, elem_fmt)=%d",
	     offsetof(jtrc_element_t, elem_fmt));
	jtrc(jtri0, JTR_CONF, id, "offsetof(jtrc_element_t, hex.length)=%d",
	     offsetof(jtrc_element_t, hex.length));
	jtrc(jtri0, JTR_CONF, id, "offsetof(jtrc_element_t, hex.data_start)=%d",
	     offsetof(jtrc_element_t, hex.data_start));
	jtrc(jtri0, JTR_CONF, id,
	     "offsetof(jtrc_element_t, hex_begin.total_length)=%d",
	     offsetof(jtrc_element_t, hex_begin.total_length));
	jtrc(jtri0, JTR_CONF, id,
	     "offsetof(jtrc_element_t, hex_begin.data_start)=%d",
	     offsetof(jtrc_element_t, hex_begin.data_start));
	jtrc(jtri0, JTR_CONF, id, "JTRC_MAX_HEX_DATA_FOR_BEG_ELEM=%d",
	     JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);
	jtrc(jtri0, JTR_CONF, id, "JTRC_MAX_HEX_DATA_PER_ELEM=%d",
	     JTRC_MAX_HEX_DATA_PER_ELEM);

	jtrc_pfs(jtri0, JTR_CONF, id, "preformatted_data, value1=%d", value1);

	jtrc_pfs(jtri0, JTR_CONF, id,
		"preformatted_data, lots of args %d %d %d %d %d %d %d", value1,
		value1, value1, value1, value1, value1, value1);

	jtrc(jtri0, JTR_CONF, id, "value1=%d", value1);

	jtrc_hexdump(jtri0, JTR_CONF, id, "hex_dump_data", hex_dump_data, 27);

	jtrc_hexdump(jtri0, JTR_CONF, id, "hex_dump_data",
		    hex_dump_data, JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);

	jtrc(jtri0, JTR_CONF, id, "value1=%d", value1);

	jtrc_hexdump(jtri0, JTR_CONF, id, "hex_dump_data", hex_dump_data, 256);

	jtrc(jtri0, JTR_CONF, id, "Last Entry");

	jtrc_setprint(jtri0, 0);


	return 0;
}
