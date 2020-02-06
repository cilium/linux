// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include <linux/filter.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <zlib.h>

#include "main.h"

#ifndef PROC_SUPER_MAGIC
# define PROC_SUPER_MAGIC	0x9fa0
#endif

enum probe_component {
	COMPONENT_UNSPEC,
	COMPONENT_KERNEL,
	COMPONENT_DEVICE,
};

#define BPF_HELPER_MAKE_ENTRY(name)	[BPF_FUNC_ ## name] = "bpf_" # name
static const char * const helper_name[] = {
	__BPF_FUNC_MAPPER(BPF_HELPER_MAKE_ENTRY)
};

#undef BPF_HELPER_MAKE_ENTRY

/* Miscellaneous utility functions */

static bool check_procfs(void)
{
	struct statfs st_fs;

	if (statfs("/proc", &st_fs) < 0)
		return false;
	if ((unsigned long)st_fs.f_type != PROC_SUPER_MAGIC)
		return false;

	return true;
}

static void uppercase(char *str, size_t len)
{
	size_t i;

	for (i = 0; i < len && str[i] != '\0'; i++)
		str[i] = toupper(str[i]);
}

/* Filtering utility functions */

static bool
check_filters(const char *name, regex_t *filter_in, regex_t *filter_out)
{
	char err_buf[100];
	int ret;

	/* Do not probe if filter_in was defined and string does not match
	 * against the pattern.
	 */
	if (filter_in) {
		ret = regexec(filter_in, name, 0, NULL, 0);
		switch (ret) {
		case 0:
			break;
		case REG_NOMATCH:
			return false;
		default:
			regerror(ret, filter_in, err_buf, ARRAY_SIZE(err_buf));
			p_err("could not match regex: %s", err_buf);
			free(filter_in);
			free(filter_out);
			exit(1);
		}
	}

	/* Do not probe if filter_out was defined and string matches against the
	 * pattern.
	 */
	if (filter_out) {
		ret = regexec(filter_out, name, 0, NULL, 0);
		switch (ret) {
		case 0:
			return false;
		case REG_NOMATCH:
			break;
		default:
			regerror(ret, filter_out, err_buf, ARRAY_SIZE(err_buf));
			p_err("could not match regex: %s", err_buf);
			free(filter_in);
			free(filter_out);
			exit(1);
		}
	}

	return true;
}

/* Printing utility functions */

static void
print_bool_feature(const char *feat_name, const char *plain_name,
		   const char *define_name, bool res, const char *define_prefix)
{
	if (json_output)
		jsonw_bool_field(json_wtr, feat_name, res);
	else if (define_prefix)
		printf("#define %s%sHAVE_%s\n", define_prefix,
		       res ? "" : "NO_", define_name);
	else
		printf("%s is %savailable\n", plain_name, res ? "" : "NOT ");
}

static void
print_kernel_option(const char *name, const char *value, regex_t *filter_in,
		    regex_t *filter_out)
{
	char *endptr;
	int res;

	if (!check_filters(name, filter_in, filter_out))
		return;

	/* No support for C-style ouptut */

	if (json_output) {
		if (!value) {
			jsonw_null_field(json_wtr, name);
			return;
		}
		errno = 0;
		res = strtol(value, &endptr, 0);
		if (!errno && *endptr == '\n')
			jsonw_int_field(json_wtr, name, res);
		else
			jsonw_string_field(json_wtr, name, value);
	} else {
		if (value)
			printf("%s is set to %s\n", name, value);
		else
			printf("%s is not set\n", name);
	}
}

static void
print_start_section(const char *json_title, const char *plain_title,
		    const char *define_comment, const char *define_prefix)
{
	if (json_output) {
		jsonw_name(json_wtr, json_title);
		jsonw_start_object(json_wtr);
	} else if (define_prefix) {
		printf("%s\n", define_comment);
	} else {
		printf("%s\n", plain_title);
	}
}

static void print_end_section(void)
{
	if (json_output)
		jsonw_end_object(json_wtr);
	else
		printf("\n");
}

/* Probing functions */

static int read_procfs(const char *path)
{
	char *endptr, *line = NULL;
	size_t len = 0;
	FILE *fd;
	int res;

	fd = fopen(path, "r");
	if (!fd)
		return -1;

	res = getline(&line, &len, fd);
	fclose(fd);
	if (res < 0)
		return -1;

	errno = 0;
	res = strtol(line, &endptr, 10);
	if (errno || *line == '\0' || *endptr != '\n')
		res = -1;
	free(line);

	return res;
}

static void probe_unprivileged_disabled(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/kernel/unprivileged_bpf_disabled");
	if (json_output) {
		jsonw_int_field(json_wtr, "unprivileged_bpf_disabled", res);
	} else {
		switch (res) {
		case 0:
			printf("bpf() syscall for unprivileged users is enabled\n");
			break;
		case 1:
			printf("bpf() syscall restricted to privileged users\n");
			break;
		case -1:
			printf("Unable to retrieve required privileges for bpf() syscall\n");
			break;
		default:
			printf("bpf() syscall restriction has unknown value %d\n", res);
		}
	}
}

static void probe_jit_enable(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/net/core/bpf_jit_enable");
	if (json_output) {
		jsonw_int_field(json_wtr, "bpf_jit_enable", res);
	} else {
		switch (res) {
		case 0:
			printf("JIT compiler is disabled\n");
			break;
		case 1:
			printf("JIT compiler is enabled\n");
			break;
		case 2:
			printf("JIT compiler is enabled with debugging traces in kernel logs\n");
			break;
		case -1:
			printf("Unable to retrieve JIT-compiler status\n");
			break;
		default:
			printf("JIT-compiler status has unknown value %d\n",
			       res);
		}
	}
}

static void probe_jit_harden(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/net/core/bpf_jit_harden");
	if (json_output) {
		jsonw_int_field(json_wtr, "bpf_jit_harden", res);
	} else {
		switch (res) {
		case 0:
			printf("JIT compiler hardening is disabled\n");
			break;
		case 1:
			printf("JIT compiler hardening is enabled for unprivileged users\n");
			break;
		case 2:
			printf("JIT compiler hardening is enabled for all users\n");
			break;
		case -1:
			printf("Unable to retrieve JIT hardening status\n");
			break;
		default:
			printf("JIT hardening status has unknown value %d\n",
			       res);
		}
	}
}

static void probe_jit_kallsyms(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/net/core/bpf_jit_kallsyms");
	if (json_output) {
		jsonw_int_field(json_wtr, "bpf_jit_kallsyms", res);
	} else {
		switch (res) {
		case 0:
			printf("JIT compiler kallsyms exports are disabled\n");
			break;
		case 1:
			printf("JIT compiler kallsyms exports are enabled for root\n");
			break;
		case -1:
			printf("Unable to retrieve JIT kallsyms export status\n");
			break;
		default:
			printf("JIT kallsyms exports status has unknown value %d\n", res);
		}
	}
}

static void probe_jit_limit(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/net/core/bpf_jit_limit");
	if (json_output) {
		jsonw_int_field(json_wtr, "bpf_jit_limit", res);
	} else {
		switch (res) {
		case -1:
			printf("Unable to retrieve global memory limit for JIT compiler for unprivileged users\n");
			break;
		default:
			printf("Global memory limit for JIT compiler for unprivileged users is %d bytes\n", res);
		}
	}
}

static bool read_next_kernel_config_option(gzFile file, char *buf, size_t n,
					   char **value)
{
	char *sep;

	while (gzgets(file, buf, n)) {
		if (strncmp(buf, "CONFIG_", 7))
			continue;

		sep = strchr(buf, '=');
		if (!sep)
			continue;

		/* Trim ending '\n' */
		buf[strlen(buf) - 1] = '\0';

		/* Split on '=' and ensure that a value is present. */
		*sep = '\0';
		if (!sep[1])
			continue;

		*value = sep + 1;
		return true;
	}

	return false;
}

static void
probe_kernel_image_config(regex_t *filter_in, regex_t *filter_out)
{
	static const char * const options[] = {
		/* Enable BPF */
		"CONFIG_BPF",
		/* Enable bpf() syscall */
		"CONFIG_BPF_SYSCALL",
		/* Does selected architecture support eBPF JIT compiler */
		"CONFIG_HAVE_EBPF_JIT",
		/* Compile eBPF JIT compiler */
		"CONFIG_BPF_JIT",
		/* Avoid compiling eBPF interpreter (use JIT only) */
		"CONFIG_BPF_JIT_ALWAYS_ON",

		/* cgroups */
		"CONFIG_CGROUPS",
		/* BPF programs attached to cgroups */
		"CONFIG_CGROUP_BPF",
		/* bpf_get_cgroup_classid() helper */
		"CONFIG_CGROUP_NET_CLASSID",
		/* bpf_skb_{,ancestor_}cgroup_id() helpers */
		"CONFIG_SOCK_CGROUP_DATA",

		/* Tracing: attach BPF to kprobes, tracepoints, etc. */
		"CONFIG_BPF_EVENTS",
		/* Kprobes */
		"CONFIG_KPROBE_EVENTS",
		/* Uprobes */
		"CONFIG_UPROBE_EVENTS",
		/* Tracepoints */
		"CONFIG_TRACING",
		/* Syscall tracepoints */
		"CONFIG_FTRACE_SYSCALLS",
		/* bpf_override_return() helper support for selected arch */
		"CONFIG_FUNCTION_ERROR_INJECTION",
		/* bpf_override_return() helper */
		"CONFIG_BPF_KPROBE_OVERRIDE",

		/* Network */
		"CONFIG_NET",
		/* AF_XDP sockets */
		"CONFIG_XDP_SOCKETS",
		/* BPF_PROG_TYPE_LWT_* and related helpers */
		"CONFIG_LWTUNNEL_BPF",
		/* BPF_PROG_TYPE_SCHED_ACT, TC (traffic control) actions */
		"CONFIG_NET_ACT_BPF",
		/* BPF_PROG_TYPE_SCHED_CLS, TC filters */
		"CONFIG_NET_CLS_BPF",
		/* TC clsact qdisc */
		"CONFIG_NET_CLS_ACT",
		/* Ingress filtering with TC */
		"CONFIG_NET_SCH_INGRESS",
		/* bpf_skb_get_xfrm_state() helper */
		"CONFIG_XFRM",
		/* bpf_get_route_realm() helper */
		"CONFIG_IP_ROUTE_CLASSID",
		/* BPF_PROG_TYPE_LWT_SEG6_LOCAL and related helpers */
		"CONFIG_IPV6_SEG6_BPF",
		/* BPF_PROG_TYPE_LIRC_MODE2 and related helpers */
		"CONFIG_BPF_LIRC_MODE2",
		/* BPF stream parser and BPF socket maps */
		"CONFIG_BPF_STREAM_PARSER",
		/* xt_bpf module for passing BPF programs to netfilter  */
		"CONFIG_NETFILTER_XT_MATCH_BPF",
		/* bpfilter back-end for iptables */
		"CONFIG_BPFILTER",
		/* bpftilter module with "user mode helper" */
		"CONFIG_BPFILTER_UMH",

		/* test_bpf module for BPF tests */
		"CONFIG_TEST_BPF",
	};
	char *values[ARRAY_SIZE(options)] = { };
	struct utsname utsn;
	char path[PATH_MAX];
	gzFile file = NULL;
	char buf[4096];
	char *value;
	size_t i;

	if (!uname(&utsn)) {
		snprintf(path, sizeof(path), "/boot/config-%s", utsn.release);

		/* gzopen also accepts uncompressed files. */
		file = gzopen(path, "r");
	}

	if (!file) {
		/* Some distributions build with CONFIG_IKCONFIG=y and put the
		 * config file at /proc/config.gz.
		 */
		file = gzopen("/proc/config.gz", "r");
	}
	if (!file) {
		p_info("skipping kernel config, can't open file: %s",
		       strerror(errno));
		goto end_parse;
	}
	/* Sanity checks */
	if (!gzgets(file, buf, sizeof(buf)) ||
	    !gzgets(file, buf, sizeof(buf))) {
		p_info("skipping kernel config, can't read from file: %s",
		       strerror(errno));
		goto end_parse;
	}
	if (strcmp(buf, "# Automatically generated file; DO NOT EDIT.\n")) {
		p_info("skipping kernel config, can't find correct file");
		goto end_parse;
	}

	while (read_next_kernel_config_option(file, buf, sizeof(buf), &value)) {
		for (i = 0; i < ARRAY_SIZE(options); i++) {
			if (values[i] || strcmp(buf, options[i]))
				continue;

			values[i] = strdup(value);
		}
	}

end_parse:
	if (file)
		gzclose(file);

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		print_kernel_option(options[i], values[i], filter_in,
				    filter_out);
		free(values[i]);
	}
}

static bool
probe_bpf_syscall(bool print_syscall_config, const char *define_prefix,
		  regex_t *filter_in, regex_t *filter_out)
{
	const char *feat_name = "have_bpf_syscall";
	const char *plain_desc = "bpf() syscall";
	const char *define_name = "BPF_SYSCALL";
	bool res;

	bpf_load_program(BPF_PROG_TYPE_UNSPEC, NULL, 0, NULL, 0, NULL, 0);
	res = (errno != ENOSYS);

	if (!check_filters(feat_name, filter_in, filter_out))
		print_syscall_config = false;

	if (print_syscall_config)
		print_bool_feature(feat_name,
				   plain_desc,
				   define_name,
				   res, define_prefix);

	return res;
}

static void
probe_prog_type(bool print_program_types, enum bpf_prog_type prog_type,
		bool *supported_types, const char *define_prefix,
		regex_t *filter_in, regex_t *filter_out, __u32 ifindex)
{
	char feat_name[128], plain_desc[128], define_name[128];
	const char *plain_comment = "eBPF program_type ";
	size_t maxlen;
	bool res;

	sprintf(feat_name, "have_%s_prog_type", prog_type_name[prog_type]);
	sprintf(define_name, "%s_prog_type", prog_type_name[prog_type]);
	uppercase(define_name, sizeof(define_name));
	sprintf(plain_desc, "%s%s", plain_comment, prog_type_name[prog_type]);

	if (ifindex)
		/* Only test offload-able program types */
		switch (prog_type) {
		case BPF_PROG_TYPE_SCHED_CLS:
		case BPF_PROG_TYPE_XDP:
			break;
		default:
			return;
		}

	res = bpf_probe_prog_type(prog_type, ifindex);

	supported_types[prog_type] |= res;

	maxlen = sizeof(plain_desc) - strlen(plain_comment) - 1;
	if (strlen(prog_type_name[prog_type]) > maxlen) {
		p_info("program type name too long");
		return;
	}

	if (!check_filters(feat_name, filter_in, filter_out))
		return;

	if (print_program_types)
		print_bool_feature(feat_name, plain_desc, define_name, res,
				   define_prefix);
}

static void
probe_map_type(enum bpf_map_type map_type, const char *define_prefix,
	       regex_t *filter_in, regex_t *filter_out, __u32 ifindex)
{
	char feat_name[128], plain_desc[128], define_name[128];
	const char *plain_comment = "eBPF map_type ";
	size_t maxlen;
	bool res;

	sprintf(feat_name, "have_%s_map_type", map_type_name[map_type]);
	sprintf(define_name, "%s_map_type", map_type_name[map_type]);
	uppercase(define_name, sizeof(define_name));
	sprintf(plain_desc, "%s%s", plain_comment, map_type_name[map_type]);

	if (!check_filters(feat_name, filter_in, filter_out))
		return;

	res = bpf_probe_map_type(map_type, ifindex);

	maxlen = sizeof(plain_desc) - strlen(plain_comment) - 1;
	if (strlen(map_type_name[map_type]) > maxlen) {
		p_info("map type name too long");
		return;
	}

	print_bool_feature(feat_name, plain_desc, define_name, res,
			   define_prefix);
}

static void
probe_helpers_for_progtype(enum bpf_prog_type prog_type, bool supported_type,
			   const char *define_prefix, regex_t *filter_in,
			   regex_t *filter_out, __u32 ifindex)
{
	const char *ptype_name = prog_type_name[prog_type];
	char feat_name[128];
	unsigned int id;
	bool res;

	if (!check_filters(ptype_name, filter_in, filter_out))
		return;

	if (ifindex)
		/* Only test helpers for offload-able program types */
		switch (prog_type) {
		case BPF_PROG_TYPE_SCHED_CLS:
		case BPF_PROG_TYPE_XDP:
			break;
		default:
			return;
		}

	if (json_output) {
		sprintf(feat_name, "%s_available_helpers", ptype_name);
		jsonw_name(json_wtr, feat_name);
		jsonw_start_array(json_wtr);
	} else if (!define_prefix) {
		printf("eBPF helpers supported for program type %s:",
		       ptype_name);
	}

	for (id = 1; id < ARRAY_SIZE(helper_name); id++) {
		if (!check_filters(helper_name[id], filter_in, filter_out))
			continue;

		if (!supported_type)
			res = false;
		else
			res = bpf_probe_helper(id, prog_type, ifindex);

		if (json_output) {
			if (res)
				jsonw_string(json_wtr, helper_name[id]);
		} else if (define_prefix) {
			printf("#define %sBPF__PROG_TYPE_%s__HELPER_%s %s\n",
			       define_prefix, ptype_name, helper_name[id],
			       res ? "1" : "0");
		} else {
			if (res)
				printf("\n\t- %s", helper_name[id]);
		}
	}

	if (json_output)
		jsonw_end_array(json_wtr);
	else if (!define_prefix)
		printf("\n");
}

static void
probe_large_insn_limit(const char *define_prefix, regex_t *filter_in,
		       regex_t *filter_out, __u32 ifindex)
{
	const char *plain_desc = "Large program size limit";
	const char *define_name = "LARGE_INSN_LIMIT";
	const char *feat_name = "have_large_insn_limit";
	bool res;

	if (!check_filters(feat_name, filter_in, filter_out))
		return;

	res = bpf_probe_large_insn_limit(ifindex);
	print_bool_feature(feat_name,
			   plain_desc,
			   define_name,
			   res, define_prefix);
}

static void
section_system_config(enum probe_component target, const char *define_prefix,
		      regex_t *filter_in, regex_t *filter_out)
{
	switch (target) {
	case COMPONENT_KERNEL:
	case COMPONENT_UNSPEC:
		if (define_prefix)
			break;

		print_start_section("system_config",
				    "Scanning system configuration...",
				    NULL, /* define_comment never used here */
				    NULL); /* define_prefix always NULL here */
		if (check_procfs()) {
			probe_unprivileged_disabled();
			probe_jit_enable();
			probe_jit_harden();
			probe_jit_kallsyms();
			probe_jit_limit();
		} else {
			p_info("/* procfs not mounted, skipping related probes */");
		}
		probe_kernel_image_config(filter_in, filter_out);
		print_end_section();
		break;
	default:
		break;
	}
}

static bool
section_syscall_config(bool print_syscall_config, const char *define_prefix,
		       regex_t *filter_in, regex_t *filter_out)
{
	bool res;

	if (print_syscall_config)
		print_start_section("syscall_config",
				    "Scanning system call availability...",
				    "/*** System call availability ***/",
				    define_prefix);
	res = probe_bpf_syscall(print_syscall_config, define_prefix,
				filter_in, filter_out);
	if (print_syscall_config)
		print_end_section();

	return res;
}

static void
section_program_types(bool print_program_types, bool *supported_types,
		      const char *define_prefix, regex_t *filter_in,
		      regex_t *filter_out, __u32 ifindex)
{
	unsigned int i;

	if (print_program_types)
		print_start_section("program_types",
				    "Scanning eBPF program types...",
				    "/*** eBPF program types ***/",
				    define_prefix);

	for (i = BPF_PROG_TYPE_UNSPEC + 1; i < ARRAY_SIZE(prog_type_name); i++)
		probe_prog_type(print_program_types, i, supported_types,
				define_prefix, filter_in, filter_out, ifindex);

	if (print_program_types)
		print_end_section();
}

static void section_map_types(const char *define_prefix, regex_t *filter_in,
			      regex_t *filter_out, __u32 ifindex)
{
	unsigned int i;

	print_start_section("map_types",
			    "Scanning eBPF map types...",
			    "/*** eBPF map types ***/",
			    define_prefix);

	for (i = BPF_MAP_TYPE_UNSPEC + 1; i < map_type_name_size; i++)
		probe_map_type(i, define_prefix, filter_in, filter_out,
			       ifindex);

	print_end_section();
}

static void
section_helpers(bool *supported_types, const char *define_prefix,
		regex_t *filter_in, regex_t *filter_out, __u32 ifindex)
{
	unsigned int i;

	print_start_section("helpers",
			    "Scanning eBPF helper functions...",
			    "/*** eBPF helper functions ***/",
			    define_prefix);

	if (define_prefix)
		printf("/*\n"
		       " * Use %sHAVE_PROG_TYPE_HELPER(prog_type_name, helper_name)\n"
		       " * to determine if <helper_name> is available for <prog_type_name>,\n"
		       " * e.g.\n"
		       " *	#if %sHAVE_PROG_TYPE_HELPER(xdp, bpf_redirect)\n"
		       " *		// do stuff with this helper\n"
		       " *	#elif\n"
		       " *		// use a workaround\n"
		       " *	#endif\n"
		       " */\n"
		       "#define %sHAVE_PROG_TYPE_HELPER(prog_type, helper)	\\\n"
		       "	%sBPF__PROG_TYPE_ ## prog_type ## __HELPER_ ## helper\n",
		       define_prefix, define_prefix, define_prefix,
		       define_prefix);
	for (i = BPF_PROG_TYPE_UNSPEC + 1; i < ARRAY_SIZE(prog_type_name); i++)
		probe_helpers_for_progtype(i, supported_types[i],
					   define_prefix, filter_in, filter_out,
					   ifindex);

	print_end_section();
}

static void section_misc(const char *define_prefix, regex_t *filter_in,
			 regex_t *filter_out, __u32 ifindex)
{
	print_start_section("misc",
			    "Scanning miscellaneous eBPF features...",
			    "/*** eBPF misc features ***/",
			    define_prefix);
	probe_large_insn_limit(define_prefix, filter_in, filter_out, ifindex);
	print_end_section();
}

static int do_probe(int argc, char **argv)
{
	enum probe_component target = COMPONENT_UNSPEC;
	/* Syscall probe is always performed, because performing any other
	 * checks without bpf() syscall does not make sense and the program
	 * should exit.
	 */
	bool print_syscall_config = false;
	const char *filter_out_raw = NULL;
	const char *filter_in_raw = NULL;
	const char *define_prefix = NULL;
	bool check_system_config = false;
	/* Program types probes are needed if helper probes are going to be
	 * performed. Therefore we should differentiate between checking and
	 * printing supported program types. If only helper checks were
	 * requested, program types probes will be performed, but not printed.
	 */
	bool check_program_types = false;
	bool print_program_types = false;
	bool supported_types[128] = {};
	bool check_map_types = false;
	bool check_helpers = false;
	bool check_section = false;
	regex_t *filter_out = NULL;
	regex_t *filter_in = NULL;
	bool check_misc = false;
	char regerror_buf[100];
	__u32 ifindex = 0;
	char *ifname;
	int reg_ret;
	int ret = 0;

	/* Detection assumes user has sufficient privileges (CAP_SYS_ADMIN).
	 * Let's approximate, and restrict usage to root user only.
	 */
	if (geteuid()) {
		p_err("please run this command as root user");
		return -1;
	}

	set_max_rlimit();

	while (argc) {
		if (is_prefix(*argv, "kernel")) {
			if (target != COMPONENT_UNSPEC) {
				p_err("component to probe already specified");
				ret = -1;
				goto cleanup;
			}
			target = COMPONENT_KERNEL;
			NEXT_ARG();
		} else if (is_prefix(*argv, "dev")) {
			NEXT_ARG();

			if (target != COMPONENT_UNSPEC || ifindex) {
				p_err("component to probe already specified");
				ret = -1;
				goto cleanup;
			}
			if (!REQ_ARGS(1)) {
				ret = -1;
				goto cleanup;
			}

			target = COMPONENT_DEVICE;
			ifname = GET_ARG();
			ifindex = if_nametoindex(ifname);
			if (!ifindex) {
				p_err("unrecognized netdevice '%s': %s", ifname,
				      strerror(errno));
				ret = -1;
				goto cleanup;
			}
		} else if (is_prefix(*argv, "section")) {
			check_section = true;
			NEXT_ARG();
			if (is_prefix(*argv, "system_config")) {
				check_system_config = true;
			} else if (is_prefix(*argv, "syscall_config")) {
				print_syscall_config = true;
			} else if (is_prefix(*argv, "program_types")) {
				check_program_types = true;
				print_program_types = true;
			} else if (is_prefix(*argv, "map_types")) {
				check_map_types = true;
			} else if (is_prefix(*argv, "helpers")) {
				/* When helpers probes are requested, program
				 * types probes have to be performed, but they
				 * may not be printed.
				 */
				check_program_types = true;
				check_helpers = true;
			} else if (is_prefix(*argv, "misc")) {
				check_misc = true;
			} else {
				p_err("unrecognized section '%s', available sections: system_config, "
				      "syscall_config, program_types, map_types, helpers, misc", *argv);
				ret = -1;
				goto cleanup;
			}
			NEXT_ARG();
		} else if (is_prefix(*argv, "filter_in")) {
			if (filter_in_raw) {
				p_err("filter_in can be used only once");
				ret = -1;
				goto cleanup;
			}
			NEXT_ARG();
			if (!REQ_ARGS(1)) {
				ret = -1;
				goto cleanup;
			}
			filter_in_raw = GET_ARG();

			filter_in = malloc(sizeof(regex_t));
			reg_ret = regcomp(filter_in, filter_in_raw, 0);
			if (reg_ret) {
				regerror(reg_ret, filter_in, regerror_buf,
					 ARRAY_SIZE(regerror_buf));
				p_err("could not compile regex: %s",
				      regerror_buf);
				ret = -1;
				goto cleanup;
			}
		} else if (is_prefix(*argv, "filter_out")) {
			if (filter_out_raw) {
				p_err("filter_out can be used only once");
				ret = -1;
				goto cleanup;
			}
			NEXT_ARG();
			if (!REQ_ARGS(1)) {
				ret = -1;
				goto cleanup;
			}
			filter_out_raw = GET_ARG();

			filter_out = malloc(sizeof(regex_t));
			reg_ret = regcomp(filter_out, filter_out_raw, 0);
			if (reg_ret) {
				regerror(reg_ret, filter_out, regerror_buf,
					 ARRAY_SIZE(regerror_buf));
				p_err("could not compile regex: %s",
				      regerror_buf);
				ret = -1;
				goto cleanup;
			}
		} else if (is_prefix(*argv, "macros") && !define_prefix) {
			define_prefix = "";
			NEXT_ARG();
		} else if (is_prefix(*argv, "prefix")) {
			if (!define_prefix) {
				p_err("'prefix' argument can only be use after 'macros'");
				ret = -1;
				goto cleanup;
			}
			if (strcmp(define_prefix, "")) {
				p_err("'prefix' already defined");
				ret = -1;
				goto cleanup;
			}
			NEXT_ARG();

			if (!REQ_ARGS(1)) {
				ret = -1;
				goto cleanup;
			}
			define_prefix = GET_ARG();
		} else {
			p_err("expected no more arguments, 'kernel', 'dev', 'macros' or 'prefix', got: '%s'?",
			      *argv);
			ret = -1;
			goto cleanup;
		}
	}

	/* Perform all checks if specific section check was not requested. */
	if (!check_section) {
		print_syscall_config = true;
		check_system_config = true;
		check_program_types = true;
		print_program_types = true;
		check_map_types = true;
		check_helpers = true;
		check_misc = true;
	}

	if (json_output) {
		define_prefix = NULL;
		jsonw_start_object(json_wtr);
	}

	if (check_system_config)
		section_system_config(target, define_prefix, filter_in,
				      filter_out);
	if (!section_syscall_config(print_syscall_config, define_prefix,
				    filter_in, filter_out))
		/* bpf() syscall unavailable, don't probe other BPF features */
		goto exit_close_json;
	if (check_program_types)
		section_program_types(print_program_types, supported_types,
				      define_prefix, filter_in, filter_out,
				      ifindex);
	if (check_map_types)
		section_map_types(define_prefix, filter_in, filter_out,
				  ifindex);
	if (check_helpers)
		section_helpers(supported_types, define_prefix, filter_in,
				filter_out, ifindex);
	if (check_misc)
		section_misc(define_prefix, filter_in, filter_out, ifindex);

exit_close_json:
	if (json_output)
		/* End root object */
		jsonw_end_object(json_wtr);

cleanup:
	free(filter_in);
	free(filter_out);

	return ret;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %s %s probe [COMPONENT] [macros [prefix PREFIX]]\n"
		"       %s %s help\n"
		"\n"
		"       COMPONENT := { kernel | dev NAME }\n"
		"",
		bin_name, argv[-2], bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "probe",	do_probe },
	{ "help",	do_help },
	{ 0 }
};

int do_feature(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
