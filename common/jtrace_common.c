

/**
 * jtrc_find_instance_by_addr()
 *
 * Find instance in jtrc_instance_list list by address.
 */
static jtrace_instance_t *
jtrc_find_instance_by_addr(struct list_head *jtri_list,
			   jtrace_instance_t * jt)
{
	jtrace_instance_t *tmp_jtri = NULL;
	int found = 0;

	list_for_each_entry(tmp_jtri,
			    jtri_list, jtrc_list) {
		if (tmp_jtri == jt) {
			found = 1;
			break;
		}
	}

	if (!found) {
		return (NULL);
	}
	return (tmp_jtri);
}

/**
 * jtrc_find_instance_by_name()
 *
 * Find trace info by name.
 */
static jtrace_instance_t *
jtrc_find_instance_by_name(struct list_head *jtri_list, char *trc_name)
{
	int found = 0;
	jtrace_instance_t *jt = NULL;

	list_for_each_entry(jt, jtri_list, jtrc_list) {
		if (strncmp(jt->jtrc_cb.jtrc_name, trc_name,
			    sizeof(jt->jtrc_cb.jtrc_name)) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		return (NULL);
	}
	return (jt);
}

static jtrace_instance_t *
jtrc_default_instance(struct list_head *jtri_list)
{
	return jtrc_find_instance_by_name(jtri_list, JTRC_DEFAULT_NAME);
}
