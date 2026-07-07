/*
 * rss.c - netlink implementation of RSS context commands
 *
 * Implementation of "ethtool -x <dev>"
 */

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "parser.h"

struct cb_args {
	struct nl_context	*nlctx;
	u32			num_rings;
};

void dump_json_rss_info(struct cmd_context *ctx, u32 *indir_table,
			u32 indir_size, u8 *hkey, u32 hkey_size,
			const struct stringset *hash_funcs, u8 hfunc,
			u32 input_xfrm)
{
	unsigned int i;

	open_json_object(NULL);
	print_string(PRINT_JSON, "ifname", NULL, ctx->devname);
	if (indir_size) {
		open_json_array("rss-indirection-table", NULL);
		for (i = 0; i < indir_size; i++)
			print_uint(PRINT_JSON, NULL, NULL, indir_table[i]);
		close_json_array("\n");
	}

	if (hkey_size) {
		open_json_array("rss-hash-key", NULL);
		for (i = 0; i < hkey_size; i++)
			print_uint(PRINT_JSON, NULL, NULL, (u8)hkey[i]);
		close_json_array("\n");
	}

	if (hfunc) {
		for (i = 0; i < get_count(hash_funcs); i++) {
			if (hfunc & (1 << i)) {
				print_string(PRINT_JSON, "rss-hash-function",
					     NULL, get_string(hash_funcs, i));
				break;
			}
		}

		if (i == get_count(hash_funcs))
			print_uint(PRINT_JSON, "rss-hash-function-raw", NULL, hfunc);
	}

	open_json_object("rss-input-transformation");
	print_bool(PRINT_JSON, "symmetric-xor", NULL,
		   (input_xfrm & RXH_XFRM_SYM_XOR) ? true : false);
	print_bool(PRINT_JSON, "symmetric-or-xor", NULL,
		   (input_xfrm & RXH_XFRM_SYM_OR_XOR) ? true : false);
	if (input_xfrm & ~(RXH_XFRM_SYM_XOR | RXH_XFRM_SYM_OR_XOR))
		print_uint(PRINT_JSON, "raw", NULL, input_xfrm);

	close_json_object();

	close_json_object();
}

/* There is no netlink equivalent for ETHTOOL_GRXRINGS. */
static int get_num_rings(struct cb_args *args)
{
	struct nl_context *nlctx = args->nlctx;
	struct cmd_context *ctx = nlctx->ctx;
	struct ethtool_rxnfc ring_count = {
		.cmd = ETHTOOL_GRXRINGS,
	};
	int ret;

	ret = ioctl_init(ctx, false);
	if (ret)
		return ret;

	ret = send_ioctl(ctx, &ring_count);
	if (ret) {
		perror("Cannot get RX ring count");
		return ret;
	}

	args->num_rings = (u32)ring_count.data;

	return 0;
}

int rss_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_RSS_MAX + 1] = {};
	unsigned int indir_bytes = 0, hkey_bytes = 0;
	DECLARE_ATTR_TB_INFO(tb);
	struct cb_args *args = data;
	struct nl_context *nlctx = args->nlctx;
	const struct stringset *hash_funcs;
	u32 rss_hfunc = 0, indir_size;
	u32 *indir_table = NULL;
	u32 input_xfrm = 0;
	u8 *hkey = NULL;
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_RSS_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	show_cr();

	if (tb[ETHTOOL_A_RSS_HFUNC])
		rss_hfunc = mnl_attr_get_u32(tb[ETHTOOL_A_RSS_HFUNC]);

	if (tb[ETHTOOL_A_RSS_INDIR]) {
		indir_bytes = mnl_attr_get_payload_len(tb[ETHTOOL_A_RSS_INDIR]);
		indir_table = mnl_attr_get_payload(tb[ETHTOOL_A_RSS_INDIR]);
	}

	if (tb[ETHTOOL_A_RSS_HKEY]) {
		hkey_bytes = mnl_attr_get_payload_len(tb[ETHTOOL_A_RSS_HKEY]);
		hkey = mnl_attr_get_payload(tb[ETHTOOL_A_RSS_HKEY]);
	}

	if (tb[ETHTOOL_A_RSS_INPUT_XFRM])
		input_xfrm = mnl_attr_get_u32(tb[ETHTOOL_A_RSS_INPUT_XFRM]);

	/* Fetch RSS hash functions and their status and print */
	if (!nlctx->is_monitor) {
		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			return MNL_CB_ERROR;
	}
	hash_funcs = global_stringset(ETH_SS_RSS_HASH_FUNCS,
				      nlctx->ethnl2_socket);

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return silent ? MNL_CB_OK : MNL_CB_ERROR;

	ret = get_num_rings(args);
	if (ret < 0)
		return MNL_CB_ERROR;

	indir_size = indir_bytes / sizeof(u32);
	if (is_json_context()) {
		dump_json_rss_info(nlctx->ctx, (u32 *)indir_table, indir_size,
				   hkey, hkey_bytes, hash_funcs, rss_hfunc,
				   input_xfrm);
	} else {
		print_indir_table(nlctx->ctx, args->num_rings,
				  indir_size, (u32 *)indir_table);
		print_rss_hkey(hkey, hkey_bytes);
		printf("RSS hash function:\n");
		if (!rss_hfunc) {
			printf("    Operation not supported\n");
			return 0;
		}
		for (unsigned int i = 0; i < get_count(hash_funcs); i++) {
			printf("    %s: %s\n", get_string(hash_funcs, i),
			       (rss_hfunc & (1 << i)) ? "on" : "off");
			rss_hfunc &= ~(1 << i);
		}
		if (rss_hfunc)
			printf("    Unknown hash function: 0x%x\n", rss_hfunc);

		printf("RSS input transformation:\n");
		printf("    symmetric-xor: %s\n",
		       (input_xfrm & RXH_XFRM_SYM_XOR) ? "on" : "off");
		input_xfrm &= ~RXH_XFRM_SYM_XOR;
		printf("    symmetric-or-xor: %s\n",
		       (input_xfrm & RXH_XFRM_SYM_OR_XOR) ? "on" : "off");
		input_xfrm &= ~RXH_XFRM_SYM_OR_XOR;

		if (input_xfrm)
			printf("    Unknown bits in RSS input transformation: 0x%x\n", input_xfrm);
	}

	return MNL_CB_OK;
}

/* RSS_GET */
static const struct param_parser grss_params[] = {
	{
		.arg		= "context",
		.type		= ETHTOOL_A_RSS_CONTEXT,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{}
};

int nl_grss(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	struct nl_msg_buff *msgbuff;
	struct cb_args args = {};
	int ret;

	nlctx->cmd = "-x";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_RSS_GET, true))
		return -EOPNOTSUPP;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_RSS_GET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 1;

	if (ethnla_fill_header(msgbuff, ETHTOOL_A_RSS_HEADER,
			       ctx->devname, 0))
		return -EMSGSIZE;

	ret = nl_parser(nlctx, grss_params, NULL, PARSER_GROUP_NONE, NULL);
	if (ret < 0)
		goto err;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		goto err;

	args.nlctx = nlctx;
	new_json_obj(ctx->json);
	ret = nlsock_process_reply(nlsk, rss_reply_cb, &args);
	delete_json_obj();

	if (ret == 0)
		return 0;
err:
	return nlctx->exit_code ?: 1;
}

/* RSS_SET */
enum {
	SRSS_PARAM_EQUAL,
	SRSS_PARAM_WEIGHT,
	SRSS_PARAM_START,
	SRSS_PARAM_DEFAULT,
	SRSS_PARAM_HKEY,
	SRSS_PARAM_HFUNC,
	SRSS_PARAM_XFRM,
	SRSS_PARAM_CONTEXT,
	SRSS_PARAM_DELETE,
};

struct srss_cmd {
	unsigned long	present;
	u32		equal;
	u32		start;
	char		**weight;
	u32		num_weights;
	char		*hkey;
	char		*hfunc;
	u32		input_xfrm;
	u32		context;
};

#define SRSS_HAS(cmd, p)	((cmd)->present & (1UL << (p)))

struct rss_sizes {
	u32	indir_size;
	u32	key_size;
};

static int rss_sizes_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_RSS_MAX + 1] = {};
	struct rss_sizes *sizes = data;
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return MNL_CB_ERROR;

	if (tb[ETHTOOL_A_RSS_INDIR])
		sizes->indir_size =
			mnl_attr_get_payload_len(tb[ETHTOOL_A_RSS_INDIR]) /
			sizeof(u32);

	if (tb[ETHTOOL_A_RSS_HKEY])
		sizes->key_size =
			mnl_attr_get_payload_len(tb[ETHTOOL_A_RSS_HKEY]);

	return MNL_CB_OK;
}

static int rss_get_sizes(struct nl_context *nlctx, u32 *indir_size,
			 u32 *key_size)
{
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	struct nl_msg_buff *msgbuff = &nlsk->msgbuff;
	struct rss_sizes sizes = {};
	int ret;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_RSS_GET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return ret;

	if (ethnla_fill_header(msgbuff, ETHTOOL_A_RSS_HEADER,
			       nlctx->devname, 0))
		return -EMSGSIZE;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		return ret;

	ret = nlsock_process_reply(nlsk, rss_sizes_reply_cb, &sizes);
	if (ret < 0)
		return ret;

	*indir_size = sizes.indir_size;
	*key_size = sizes.key_size;
	return 0;
}

static int rss_resolve_hfunc(struct nl_context *nlctx, const char *name,
			     u32 *hfunc)
{
	const struct stringset *hash_funcs;
	unsigned int i, count;
	int ret;

	ret = netlink_init_ethnl2_socket(nlctx);
	if (ret < 0) {
		fprintf(stderr, "Cannot get hash function names\n");
		return ret;
	}

	hash_funcs = global_stringset(ETH_SS_RSS_HASH_FUNCS,
				      nlctx->ethnl2_socket);
	if (!hash_funcs) {
		fprintf(stderr, "Cannot get hash function names\n");
		return -ENOENT;
	}

	count = get_count(hash_funcs);
	for (i = 0; i < count; i++) {
		if (!strcmp(get_string(hash_funcs, i), name)) {
			*hfunc = (u32)1 << i;
			return 0;
		}
	}

	fprintf(stderr, "Unknown hash function: %s\n", name);
	return -EINVAL;
}

static int rss_create_reply_cb(const struct nlmsghdr *nlhdr,
			       void *data __maybe_unused)
{
	const struct nlattr *tb[ETHTOOL_A_RSS_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return MNL_CB_ERROR;

	if (tb[ETHTOOL_A_RSS_CONTEXT])
		printf("New RSS context is %u\n",
		       mnl_attr_get_u32(tb[ETHTOOL_A_RSS_CONTEXT]));

	return MNL_CB_OK;
}

static int srss_parse_weight(struct nl_context *nlctx,
			     uint16_t type __maybe_unused,
			     const void *data __maybe_unused,
			     struct nl_msg_buff *msgbuff __maybe_unused,
			     void *dest)
{
	struct srss_cmd *cmd = dest;

	cmd->weight = nlctx->argp;
	while (nlctx->argc > 0 &&
	       isdigit((unsigned char)(*nlctx->argp)[0])) {
		nlctx->argp++;
		nlctx->argc--;
		cmd->num_weights++;
	}

	if (cmd->num_weights == 0) {
		fprintf(stderr, "'weight' requires at least one value\n");
		return -EINVAL;
	}

	return 0;
}

static const struct lookup_entry_u32 srss_xfrm_values[] = {
	{ .arg = "none",             .val = 0 },
	{ .arg = "symmetric-xor",    .val = RXH_XFRM_SYM_XOR },
	{ .arg = "symmetric-or-xor", .val = RXH_XFRM_SYM_OR_XOR },
	{}
};

static int srss_parse_context(struct nl_context *nlctx,
			      uint16_t type __maybe_unused,
			      const void *data __maybe_unused,
			      struct nl_msg_buff *msgbuff __maybe_unused,
			      void *dest)
{
	struct srss_cmd *cmd = dest;
	const char *arg = *nlctx->argp;

	nlctx->argp++;
	nlctx->argc--;

	if (!strcmp(arg, "new")) {
		cmd->context = ETH_RXFH_CONTEXT_ALLOC;
	} else {
		u32 v;

		if (parse_u32(arg, &v) ||
		    v < 1 || v > ETH_RXFH_CONTEXT_ALLOC - 1) {
			fprintf(stderr, "Invalid 'context' value\n");
			return -EINVAL;
		}
		cmd->context = v;
	}

	return 0;
}

/* "default" and "delete" are flags with no extra arg, just being seen
 * (recorded in cmd->present) is enough.
 */
static int srss_parse_flag(struct nl_context *nlctx __maybe_unused,
			   uint16_t type __maybe_unused,
			   const void *data __maybe_unused,
			   struct nl_msg_buff *msgbuff __maybe_unused,
			   void *dest __maybe_unused)
{
	return 0;
}

static const struct param_parser srss_params[] = {
	[SRSS_PARAM_EQUAL] = {
		.arg		= "equal",
		.handler	= nl_parse_direct_u32,
		.dest_offset	= offsetof(struct srss_cmd, equal),
		.min_argc	= 1,
		.alt_group	= 1,
	},
	[SRSS_PARAM_WEIGHT] = {
		.arg		= "weight",
		.handler	= srss_parse_weight,
		.min_argc	= 1,
		.alt_group	= 1,
	},
	[SRSS_PARAM_START] = {
		.arg		= "start",
		.handler	= nl_parse_direct_u32,
		.dest_offset	= offsetof(struct srss_cmd, start),
		.min_argc	= 1,
	},
	[SRSS_PARAM_DEFAULT] = {
		.arg		= "default",
		.handler	= srss_parse_flag,
		.alt_group	= 1,
	},
	[SRSS_PARAM_HKEY] = {
		.arg		= "hkey",
		.handler	= nl_parse_string,
		.dest_offset	= offsetof(struct srss_cmd, hkey),
		.min_argc	= 1,
	},
	[SRSS_PARAM_HFUNC] = {
		.arg		= "hfunc",
		.handler	= nl_parse_string,
		.dest_offset	= offsetof(struct srss_cmd, hfunc),
		.min_argc	= 1,
	},
	[SRSS_PARAM_XFRM] = {
		.arg		= "xfrm",
		.handler	= nl_parse_lookup_u32,
		.handler_data	= srss_xfrm_values,
		.dest_offset	= offsetof(struct srss_cmd, input_xfrm),
		.min_argc	= 1,
	},
	[SRSS_PARAM_CONTEXT] = {
		.arg		= "context",
		.handler	= srss_parse_context,
		.min_argc	= 1,
	},
	[SRSS_PARAM_DELETE] = {
		.arg		= "delete",
		.handler	= srss_parse_flag,
		.alt_group	= 1,
	},
	{}
};

static int srss_validate_cmd(const struct srss_cmd *cmd)
{
	if (SRSS_HAS(cmd, SRSS_PARAM_EQUAL) &&
	    (cmd->equal < 1 || cmd->equal > INT_MAX)) {
		fprintf(stderr, "Invalid 'equal' value\n");
		return -EINVAL;
	}

	if (SRSS_HAS(cmd, SRSS_PARAM_START) && cmd->start > INT_MAX) {
		fprintf(stderr, "Invalid 'start' value\n");
		return -EINVAL;
	}

	if (SRSS_HAS(cmd, SRSS_PARAM_DELETE)) {
		static const struct {
			unsigned int	param;
			const char	*name;
		} delete_forbidden[] = {
			{ SRSS_PARAM_HKEY,  "hkey"  },
			{ SRSS_PARAM_HFUNC, "hfunc" },
			{ SRSS_PARAM_XFRM,  "xfrm"  },
			{ SRSS_PARAM_START, "start" },
		};
		unsigned int i;

		if (!SRSS_HAS(cmd, SRSS_PARAM_CONTEXT)) {
			fprintf(stderr,
				"Delete option requires context option\n");
			return -EINVAL;
		}
		if (cmd->context == ETH_RXFH_CONTEXT_ALLOC) {
			fprintf(stderr,
				"Delete and 'context new' are mutually exclusive\n");
			return -EINVAL;
		}
		for (i = 0; i < ARRAY_SIZE(delete_forbidden); i++) {
			if (SRSS_HAS(cmd, delete_forbidden[i].param)) {
				fprintf(stderr,
					"Delete and %s options are mutually exclusive\n",
					delete_forbidden[i].name);
				return -EINVAL;
			}
		}
	}

	if (SRSS_HAS(cmd, SRSS_PARAM_START) &&
	    SRSS_HAS(cmd, SRSS_PARAM_DEFAULT)) {
		fprintf(stderr,
			"Start and default options are mutually exclusive\n");
		return -EINVAL;
	}

	if (SRSS_HAS(cmd, SRSS_PARAM_START) &&
	    !(SRSS_HAS(cmd, SRSS_PARAM_EQUAL) ||
	      SRSS_HAS(cmd, SRSS_PARAM_WEIGHT))) {
		fprintf(stderr,
			"Start must be used with equal or weight options\n");
		return -EINVAL;
	}

	if (SRSS_HAS(cmd, SRSS_PARAM_DEFAULT) &&
	    SRSS_HAS(cmd, SRSS_PARAM_CONTEXT)) {
		fprintf(stderr,
			"Default and context options are mutually exclusive\n");
		return -EINVAL;
	}

	return 0;
}

int nl_srss(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	u32 indir_size = 0, key_size = 0;
	struct nl_msg_buff *msgbuff;
	struct srss_cmd cmd = {};
	struct nl_socket *nlsk;
	unsigned int msg_type;
	char *hkey = NULL;
	u32 *indir = NULL;
	u32 hfunc_val = 0;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_RSS_SET, false))
		return -EOPNOTSUPP;

	if (!ctx->argc) {
		fprintf(stderr, "ethtool (-X): parameters missing\n");
		ret = 1;
		goto out;
	}

	nlctx->cmd = "-X";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = nl_parser(nlctx, srss_params, &cmd, PARSER_GROUP_NONE, NULL);
	if (ret < 0)
		goto out;

	ret = srss_validate_cmd(&cmd);
	if (ret)
		goto out;

	if (SRSS_HAS(&cmd, SRSS_PARAM_DELETE))
		msg_type = ETHTOOL_MSG_RSS_DELETE_ACT;
	else if (cmd.context == ETH_RXFH_CONTEXT_ALLOC)
		msg_type = ETHTOOL_MSG_RSS_CREATE_ACT;
	else
		msg_type = ETHTOOL_MSG_RSS_SET;

	if (msg_type != ETHTOOL_MSG_RSS_SET &&
	    netlink_cmd_check(ctx, msg_type, false))
		return -EOPNOTSUPP;

	if (SRSS_HAS(&cmd, SRSS_PARAM_HKEY) ||
	    SRSS_HAS(&cmd, SRSS_PARAM_EQUAL) ||
	    SRSS_HAS(&cmd, SRSS_PARAM_WEIGHT) ||
	    SRSS_HAS(&cmd, SRSS_PARAM_DEFAULT)) {
		ret = rss_get_sizes(nlctx, &indir_size, &key_size);
		if (ret < 0)
			goto out;
	}

	if (indir_size == 0 && (SRSS_HAS(&cmd, SRSS_PARAM_EQUAL) ||
				SRSS_HAS(&cmd, SRSS_PARAM_WEIGHT) ||
				SRSS_HAS(&cmd, SRSS_PARAM_DEFAULT))) {
		fprintf(stderr,
			"Device does not support RX indirection table\n");
		ret = -EINVAL;
		goto out;
	}

	ret = msg_init(nlctx, msgbuff, msg_type, NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		goto out;

	if (ethnla_fill_header(msgbuff, ETHTOOL_A_RSS_HEADER,
			       ctx->devname, 0)) {
		ret = -EMSGSIZE;
		goto out;
	}

	if (msg_type == ETHTOOL_MSG_RSS_DELETE_ACT) {
		if (ethnla_put_u32(msgbuff, ETHTOOL_A_RSS_CONTEXT,
				   cmd.context)) {
			ret = -EMSGSIZE;
			goto out;
		}
		goto send;
	}

	/* For SET: include context id if targeting a non-default context.
	 * For CREATE: omit context (kernel auto-allocates).
	 */
	if (msg_type == ETHTOOL_MSG_RSS_SET &&
	    SRSS_HAS(&cmd, SRSS_PARAM_CONTEXT)) {
		if (ethnla_put_u32(msgbuff, ETHTOOL_A_RSS_CONTEXT,
				   cmd.context)) {
			ret = -EMSGSIZE;
			goto out;
		}
	}

	if (SRSS_HAS(&cmd, SRSS_PARAM_HKEY)) {
		ret = parse_hkey(&hkey, key_size, cmd.hkey);
		if (ret)
			goto out;

		if (ethnla_put(msgbuff, ETHTOOL_A_RSS_HKEY, key_size, hkey)) {
			ret = -EMSGSIZE;
			goto out;
		}
	}

	if (SRSS_HAS(&cmd, SRSS_PARAM_HFUNC)) {
		ret = rss_resolve_hfunc(nlctx, cmd.hfunc, &hfunc_val);
		if (ret < 0)
			goto out;

		if (ethnla_put_u32(msgbuff, ETHTOOL_A_RSS_HFUNC, hfunc_val)) {
			ret = -EMSGSIZE;
			goto out;
		}
	}

	if (SRSS_HAS(&cmd, SRSS_PARAM_XFRM)) {
		if (ethnla_put_u32(msgbuff, ETHTOOL_A_RSS_INPUT_XFRM,
				   cmd.input_xfrm)) {
			ret = -EMSGSIZE;
			goto out;
		}
	}

	if (SRSS_HAS(&cmd, SRSS_PARAM_EQUAL) ||
	    SRSS_HAS(&cmd, SRSS_PARAM_WEIGHT) ||
	    SRSS_HAS(&cmd, SRSS_PARAM_DEFAULT)) {
		u32 table_size = indir_size;

		indir = calloc(indir_size, sizeof(*indir));
		if (!indir) {
			ret = -ENOMEM;
			goto out;
		}

		ret = fill_indir_table(
			&table_size, indir, SRSS_HAS(&cmd, SRSS_PARAM_DEFAULT),
			SRSS_HAS(&cmd, SRSS_PARAM_START) ? cmd.start : 0,
			SRSS_HAS(&cmd, SRSS_PARAM_EQUAL) ? cmd.equal : 0,
			SRSS_HAS(&cmd, SRSS_PARAM_WEIGHT) ? cmd.weight : NULL,
			cmd.num_weights);
		if (ret)
			goto out;

		/* fill_indir_table() sets table_size to 0 to signal "reset to
		 * default" (sent as a zero-length INDIR attribute, which the
		 * kernel only accepts on the default context).
		 */
		if (ethnla_put(msgbuff, ETHTOOL_A_RSS_INDIR,
			       table_size * sizeof(*indir), indir)) {
			ret = -EMSGSIZE;
			goto out;
		}
	}

send:
	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		goto out;

	if (msg_type == ETHTOOL_MSG_RSS_CREATE_ACT)
		ret = nlsock_process_reply(nlsk, rss_create_reply_cb, nlctx);
	else
		ret = nlsock_process_reply(nlsk, nomsg_reply_cb, nlctx);

out:
	free(indir);
	free(hkey);
	return ret < 0 ? 1 : ret;
}
