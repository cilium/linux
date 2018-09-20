// SPDX-License-Identifier: GPL-2.0+
// Copyright (C) 2017 Facebook
// Author: Roman Gushchin <guro@fb.com>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf.h>

#include "main.h"

#define HELP_SPEC_ATTACH_TYPES						\
	"ATTACH_TYPE := { stream_verdict | stream_parser | msg_verdict }"

static const char * const attach_type_strings[] = {
	[BPF_CGROUP_INET_INGRESS] = "ingress",
	[BPF_CGROUP_INET_EGRESS] = "egress",
	[BPF_CGROUP_INET_SOCK_CREATE] = "sock_create",
	[BPF_CGROUP_SOCK_OPS] = "sock_ops",
	[BPF_SK_SKB_STREAM_PARSER] = "stream_parser",
	[BPF_SK_SKB_STREAM_VERDICT] = "stream_verdict",
	[BPF_CGROUP_DEVICE] = "device",
	[BPF_SK_MSG_VERDICT] = "msg_verdict",
	[__MAX_BPF_ATTACH_TYPE] = NULL,
};

static enum bpf_attach_type parse_attach_type(const char *str)
{
	enum bpf_attach_type type;

	for (type = 0; type < __MAX_BPF_ATTACH_TYPE; type++) {
		if (attach_type_strings[type] &&
		    is_prefix(str, attach_type_strings[type]))
			return type;
	}

	return __MAX_BPF_ATTACH_TYPE;
}

static int do_show(int argc, char **argv)
{
	p_err("Not yet supported\n");
	return 0;
#if 0
	enum bpf_attach_type type;
	int map_fd;
	int ret = -1;

	if (argc < 1) {
		p_err("too few parameters for cgroup show");
		goto exit;
#if 0
	} else if (argc > 1) {
		p_err("too many parameters for cgroup show");
		goto exit;
#endif
	}

	map_fd = map_parse_fd(&argc, &argv); 
	if (map_fd < 0) {
		p_err("can't open cgroup %s", argv[1]);
		goto exit;
	}

	if (json_output)
		jsonw_start_array(json_wtr);
	else
		printf("%-8s %-15s %-15s %-15s\n", "ID", "AttachType",
		       "AttachFlags", "Name");

	for (type = 0; type < __MAX_BPF_ATTACH_TYPE; type++) {
		/*
		 * Not all attach types may be supported, so it's expected,
		 * that some requests will fail.
		 * If we were able to get the show for at least one
		 * attach type, let's return 0.
		 */
		if (show_attached_bpf_progs(map_fd, type) == 0)
			ret = 0;
	}

	if (json_output)
		jsonw_end_array(json_wtr);

	close(map_fd);
exit:
	return ret;
#endif
}

static int do_add(int argc, char **argv)
{
	enum bpf_attach_type attach_type;
	char **map_id, **prog_id;
	int map_fd, prog_fd;
	int attach_flags = 0;
	int ret = -1;

	if (argc < 4) {
		p_err("too few parameters for attach");
		goto exit;
	}

       	map_id = &argv[1];
	prog_id = &argv[3];

	printf("%s: %s:\n", __func__, argv[1]);
	map_fd = map_parse_fd(&argc, &map_id); 
	if (map_fd < 0) {
		p_err("can't open cgroup %s", argv[1]);
		goto exit;
	}

	attach_type = parse_attach_type(argv[0]);
	printf("%s: type %i\n", __func__, attach_type);
	if (attach_type == __MAX_BPF_ATTACH_TYPE) {
		p_err("invalid attach type");
		goto exit_cgroup;
	}

	prog_fd = prog_parse_fd(&argc, &prog_id);
	if (prog_fd < 0)
		goto exit_cgroup;

	printf("%s: prof_fd %i\n", __func__, prog_fd);
	if (bpf_prog_attach(prog_fd, map_fd, attach_type, attach_flags)) {
		p_err("failed to attach program");
		goto exit_prog;
	}

	if (json_output)
		jsonw_null(json_wtr);

	ret = 0;

exit_prog:
	close(prog_fd);
exit_cgroup:
	close(map_fd);
exit:
	return ret;
}

static int do_remove(int argc, char **argv)
{
	enum bpf_attach_type attach_type;
	char **map_id, **prog_id;
	int prog_fd, map_fd;
	int ret = -1;

	if (argc < 4) {
		p_err("too few parameters for cgroup detach");
		goto exit;
	}

       	map_id = &argv[1];
	prog_id = &argv[3];

	map_fd = map_parse_fd(&argc, &map_id);
	if (map_fd < 0) {
		p_err("can't open cgroup %s", argv[1]);
		goto exit;
	}

	attach_type = parse_attach_type(argv[1]);
	if (attach_type == __MAX_BPF_ATTACH_TYPE) {
		p_err("invalid attach type");
		goto exit_cgroup;
	}

	argc -= 2;
	argv = &argv[2];
	prog_fd = prog_parse_fd(&argc, &prog_id);
	if (prog_fd < 0)
		goto exit_cgroup;

	if (bpf_prog_detach2(prog_fd, map_fd, attach_type)) {
		p_err("failed to detach program");
		goto exit_prog;
	}

	if (json_output)
		jsonw_null(json_wtr);

	ret = 0;

exit_prog:
	close(prog_fd);
exit_cgroup:
	close(map_fd);
exit:
	return ret;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %s %s { show | list } [MAP] \n"
		"       %s %s add ATTACH_TYPE PROG MAP\n"
		"       %s %s remove ATTACH_TYPE MAP\n"
		"       %s %s help\n"
		"\n"
		"	MAP := { id MAP_ID | pinned FILE }\n"
		"	PROG := { id PROG_ID | pinned FILE }\n"
		"       " HELP_SPEC_ATTACH_TYPES "\n"
		"",
		bin_name, argv[-2], bin_name, argv[-2],
		bin_name, argv[-2], bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "add",	do_add },
	{ "remove",	do_remove },
	{ "help",	do_help },
	{ 0 }
};

int do_attach_cmd(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
