#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -e
set -u
set -o pipefail

VERBOSE="${SELFTESTS_VERBOSE:=0}"
LOG_FILE="$(mktemp /tmp/verify_sig_setup.log.XXXXXX)"

x509_genkey_content="\
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
CN = eBPF Signature Verification Testing Key

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
"

usage()
{
	echo "Usage: $0 <setup-rsa|setup-mldsa|cleanup <existing_tmp_dir>"
	exit 1
}

genkey()
{
	local tmp_dir="$1"

	echo "${x509_genkey_content}" > ${tmp_dir}/x509.genkey

	openssl req -new -nodes -utf8 -sha256 -days 36500 \
			-batch -x509 -config ${tmp_dir}/x509.genkey \
			-outform PEM -out ${tmp_dir}/signing_key.pem \
			-keyout ${tmp_dir}/signing_key.pem 2>&1

	openssl x509 -in ${tmp_dir}/signing_key.pem -out \
		${tmp_dir}/signing_key.der -outform der
}

setup_rsa()
{
	local tmp_dir="$1"

	genkey "${tmp_dir}"
	key_id=$(cat ${tmp_dir}/signing_key.der | keyctl padd asymmetric ebpf_testing_key @s)
	keyring_id=$(keyctl newring ebpf_testing_keyring @s)
	keyctl link $key_id $keyring_id
}

# ML-DSA key types were added in openssl-3.5, and the test needs that on two
# sides which are not necessarily the same openssl: the CLI has to generate
# the key here, and sign-file has to sign with it through whatever libcrypto
# it was linked against. Asking the CLI alone, say through "list
# -key-managers", says nothing about the second, and a system where the two
# differ then gets past the probe only to fail at signing.
#
# So probe by doing it: generate the key and sign a scratch file with it. That
# also covers an openssl built without the algorithm and one too old to know
# the ML-DSA-87 key type at all, and it leaves the key behind for the caller,
# as generating it is the first half of the probe.
mldsa_supported()
{
	local tmp_dir="$1"

	genkey_mldsa "${tmp_dir}" || return 1
	: > ${tmp_dir}/probe
	# Same digest as the caller signs with, see sign_buf_digest().
	./sign-file -d sha512 ${tmp_dir}/signing_key.pem \
		${tmp_dir}/signing_key.pem ${tmp_dir}/probe || return 1
	rm -f ${tmp_dir}/probe ${tmp_dir}/probe.p7s
}

genkey_mldsa()
{
	local tmp_dir="$1"

	echo "${x509_genkey_content}" > ${tmp_dir}/x509.genkey

	# No -<digest> here: ML-DSA hashes the message itself, and openssl
	# rejects an explicit digest for it.
	openssl req -new -nodes -utf8 -days 36500 \
			-batch -x509 -newkey ML-DSA-87 \
			-config ${tmp_dir}/x509.genkey \
			-outform PEM -out ${tmp_dir}/signing_key.pem \
			-keyout ${tmp_dir}/signing_key.pem 2>&1

	openssl x509 -in ${tmp_dir}/signing_key.pem -out \
		${tmp_dir}/signing_key.der -outform der
}

# Leaves ${tmp_dir} empty so the caller can rmdir() it, and exits 77, the
# usual "skipped" convention, so the caller can tell an openssl that cannot
# do ML-DSA apart from a genuine failure.
mldsa_skip()
{
	local tmp_dir="$1"

	rm -f ${tmp_dir}/x509.genkey ${tmp_dir}/signing_key.pem \
		${tmp_dir}/signing_key.der ${tmp_dir}/probe \
		${tmp_dir}/probe.p7s
	exit 77
}

# A userspace that cannot do ML-DSA is the only skip here. The kernel side is
# covered by CONFIG_CRYPTO_MLDSA in the selftest config, so a kernel that will
# not take the certificate is a real failure and is reported as one.
setup_mldsa()
{
	local tmp_dir="$1"

	mldsa_supported "${tmp_dir}" || mldsa_skip "${tmp_dir}"
	key_id=$(cat ${tmp_dir}/signing_key.der |
		 keyctl padd asymmetric ebpf_testing_key @s)
	keyring_id=$(keyctl newring ebpf_testing_keyring @s)
	keyctl link $key_id $keyring_id
}

cleanup() {
	local tmp_dir="$1"

	keyctl unlink $(keyctl search @s asymmetric ebpf_testing_key) @s
	keyctl unlink $(keyctl search @s keyring ebpf_testing_keyring) @s
	rm -rf ${tmp_dir}
}

fsverity_create_sign_file() {
	local tmp_dir="$1"

	data_file=${tmp_dir}/data-file
	sig_file=${tmp_dir}/sig-file
	dd if=/dev/urandom of=$data_file bs=1 count=12345 2> /dev/null
	fsverity sign --key ${tmp_dir}/signing_key.pem $data_file $sig_file

	# We do not want to enable fsverity on $data_file yet. Try whether
	# the file system support fsverity on a different file.
	touch ${tmp_dir}/tmp-file
	fsverity enable ${tmp_dir}/tmp-file
}

fsverity_enable_file() {
	local tmp_dir="$1"

	data_file=${tmp_dir}/data-file
	fsverity enable $data_file
}

catch()
{
	local exit_code="$1"
	local log_file="$2"

	# 77 is mldsa_skip(), an expected outcome rather than a failure, and
	# its probe leaves the noise of the openssl or sign-file that could
	# not do ML-DSA behind in the log. Do not report that as an error.
	if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 77 ]]; then
		cat "${log_file}" >&3
	fi

	rm -f "${log_file}"
	exit ${exit_code}
}

main()
{
	[[ $# -ne 2 ]] && usage

	local action="$1"
	local tmp_dir="$2"

	[[ ! -d "${tmp_dir}" ]] && echo "Directory ${tmp_dir} doesn't exist" && exit 1

	if [[ "${action}" == "setup-rsa" ]]; then
		setup_rsa "${tmp_dir}"
	elif [[ "${action}" == "setup-mldsa" ]]; then
		setup_mldsa "${tmp_dir}"
	elif [[ "${action}" == "genkey" ]]; then
		genkey "${tmp_dir}"
	elif [[ "${action}" == "cleanup" ]]; then
		cleanup "${tmp_dir}"
	elif [[ "${action}" == "fsverity-create-sign" ]]; then
		fsverity_create_sign_file "${tmp_dir}"
	elif [[ "${action}" == "fsverity-enable" ]]; then
		fsverity_enable_file "${tmp_dir}"
	else
		echo "Unknown action: ${action}"
		exit 1
	fi
}

trap 'catch "$?" "${LOG_FILE}"' EXIT

if [[ "${VERBOSE}" -eq 0 ]]; then
	# Save the stderr to 3 so that we can output back to
	# it incase of an error.
	exec 3>&2 1>"${LOG_FILE}" 2>&1
fi

main "$@"
rm -f "${LOG_FILE}"
