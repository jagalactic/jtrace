
#define JTRC_ENABLE
#include <jtrace.h>

#include <stdio.h>
#include <assert.h>

void jtrace_stats(struct jtrace_instance *jtri)
{
	printf("jtrace %s: context %d mask %x num_insert %d index %d\n",
	       jtri->jtrc_cb.jtrc_name,
	       jtri->jtrc_cb.jtrc_context,
	       jtri->jtrc_cb.jtrc_flags,
	       jtri->jtrc_cb.jtrc_num_insert,
	       jtri->jtrc_cb.jtrc_buf_index);
}

int main(int argc, char **argv)
{
	int i;
	struct jtrace_instance *jtrix;
	struct jtrace_instance *jtri0;
	struct jtrace_instance *jtri1;
	struct jtrace_instance *jtri2;
	char *id = 0;
	int value1 = 1;
	char hex_dump_data[512];

	jtrace_config();

	for (i = 0; i < 512; i++)
		hex_dump_data[i] = (char) (i & 0xff);

	INIT_LIST_HEAD(&jtrc_instance_list);

	jtri0 = jtrace_init("test", 64);
	assert(jtri0);
	jtri1 = jtrace_init("frog", 0x100000);
	assert(jtri1);
	jtri2 = jtrace_init("bunny", 0x100000);
	assert(jtri2);

	jtrace_stats(jtri0);
	jtrc_setmask(jtri0, 0xfffffff);
	jtrace_stats(jtri0);

	jtrix = jtrc_find_get_instance("frog");
	assert(jtrix == jtri1);
	list_del(&jtrix->jtrc_list);
	jtrix = jtrc_find_get_instance("frog");
	assert(jtrix == NULL);

	jtrace_put_instance(jtri1); /* frog */
	jtrace_put_instance(jtri2); /* bunny */

	/* Put some stuff in the trace buffer "test" */

	jtrace_stats(jtri0);
	jtrc(jtri0, JTR_CONF, id, "First Entry");
	jtrace_stats(jtri0);

	jtrc(jtri0, JTR_CONF, id, "sizeof(struct jtrc_entry)=%d",
	     sizeof(struct jtrc_entry));
	jtrc(jtri0, JTR_CONF, id, "sizeof(struct jtrc_reg_entry)=%d",
	     sizeof(struct jtrc_reg_entry));
	jtrc(jtri0, JTR_CONF, id, "sizeof(struct jtrc_hex_entry)=%d",
	     sizeof(struct jtrc_hex_entry));
	jtrc(jtri0, JTR_CONF, id, "sizeof(struct jtrc_hex_continue)=%d",
	     sizeof(struct jtrc_hex_continue));
	jtrc(jtri0, JTR_CONF, id, "sizeof(enum jtrc_entry_fmt)=%d",
	     sizeof(enum jtrc_entry_fmt));
	jtrc(jtri0, JTR_CONF, id, "offsetof(struct jtrc_entry, elem_fmt)=%d",
	     offsetof(struct jtrc_entry, elem_fmt));
	jtrc(jtri0, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex_continue.length)=%d",
	     offsetof(struct jtrc_entry, hex_continue.length));
	jtrc(jtri0, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex_continue.data_start)=%d",
	     offsetof(struct jtrc_entry, hex_continue.data_start));
	jtrc(jtri0, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex_begin.total_length)=%d",
	     offsetof(struct jtrc_entry, hex_begin.total_length));
	jtrc(jtri0, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex_begin.data_start)=%d",
	     offsetof(struct jtrc_entry, hex_begin.data_start));
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

	print_trace(&jtri0->jtrc_cb, 0xfffffff);

	jtrace_stats(jtri0);

	jtrace_put_instance(jtri0);

	return 0;
}
