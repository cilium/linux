===============
bpftool-feature
===============
-------------------------------------------------------------------------------
tool for inspection of eBPF-related parameters for Linux kernel or net device
-------------------------------------------------------------------------------

:Manual section: 8

SYNOPSIS
========

	**bpftool** [*OPTIONS*] **feature** *COMMAND*

	*OPTIONS* := { { **-j** | **--json** } [{ **-p** | **--pretty** }] }

	*COMMANDS* := { **probe** | **help** }

FEATURE COMMANDS
================

|	**bpftool** **feature probe** [*COMPONENT*] [**section** [*SECTION*]] [**filter_in** *PATTERN*] [**filter_out** *PATTERN*] [**macros** [**prefix** *PREFIX*]]
|	**bpftool** **feature help**
|
|	*COMPONENT* := { **kernel** | **dev** *NAME* }
|	*SECTION* := { **system_config** | **syscall_config** | **program_types** | **map_types** | **helpers** | **misc** }

DESCRIPTION
===========
	**bpftool feature probe** [**kernel**] [**section** [*SECTION*]] [**filter_in** *PATTERN*] [**filter_out** *PATTERN*] [**macros** [**prefix** *PREFIX*]]
		  Probe the running kernel and dump a number of eBPF-related
		  parameters, such as availability of the **bpf()** system call,
		  JIT status, eBPF program types availability, eBPF helper
		  functions availability, and more.

		  If the **section** keyword is passed, only the specified
		  probes section will be checked and printed. The only section
		  which is always going to be probed is **syscall_config**,
		  but if the other section was provided as an argument,
		  **syscall_config** check will perform silently without
		  printing the result and bpftool will exit if the bpf()
		  syscall is not abailable (because in that case performing
		  other checks relying on the bpf() system call does not make
		  sense).

		  If the **filter_in** keyword is passed, only checks with
		  names matching the given *PATTERN* are going the be printed
		  and performed.

		  If the **filter_out** keyword is passed, checks with names
		  matching the given *PATTERN* are not going to be printed and
		  performed.

		  **filter_in** is executed before **filter_out** which means
		  that **filter_out** is always applied only on probes
		  selected by **filter_in** if both arguments are used together.

		  If the **macros** keyword (but not the **-j** option) is
		  passed, a subset of the output is dumped as a list of
		  **#define** macros that are ready to be included in a C
		  header file, for example. If, additionally, **prefix** is
		  used to define a *PREFIX*, the provided string will be used
		  as a prefix to the names of the macros: this can be used to
		  avoid conflicts on macro names when including the output of
		  this command as a header file.

		  Keyword **kernel** can be omitted. If no probe target is
		  specified, probing the kernel is the default behaviour.

		  Note that when probed, some eBPF helpers (e.g.
		  **bpf_trace_printk**\ () or **bpf_probe_write_user**\ ()) may
		  print warnings to kernel logs.

	**bpftool feature probe dev** *NAME* [**section** [*SECTION*]] [**filter_in** *PATTERN*] [**filter_out** *PATTERN*] [**macros** [**prefix** *PREFIX*]]
		  Probe network device for supported eBPF features and dump
		  results to the console.

		  The keywords **section**, **filter_in**, **filter_out**,
		  **macros** and **prefix** have the same role as when probing
		  the kernel.

	**bpftool feature help**
		  Print short help message.

OPTIONS
=======
	-h, --help
		  Print short generic help message (similar to **bpftool help**).

	-V, --version
		  Print version number (similar to **bpftool version**).

	-j, --json
		  Generate JSON output. For commands that cannot produce JSON, this
		  option has no effect.

	-p, --pretty
		  Generate human-readable JSON output. Implies **-j**.

	-d, --debug
		  Print all logs available from libbpf, including debug-level
		  information.

SEE ALSO
========
	**bpf**\ (2),
	**bpf-helpers**\ (7),
	**bpftool**\ (8),
	**bpftool-prog**\ (8),
	**bpftool-map**\ (8),
	**bpftool-cgroup**\ (8),
	**bpftool-net**\ (8),
	**bpftool-perf**\ (8),
	**bpftool-btf**\ (8)
