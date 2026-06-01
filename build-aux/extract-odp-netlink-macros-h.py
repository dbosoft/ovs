#!/usr/bin/env python3
# Portable, pure-Python reimplementation of the POSIX shell script
# build-aux/extract-odp-netlink-macros-h.
#
# It reads include/odp-netlink.h and emits, for a fixed list of "ovs_key_*"
# structs, an X_OFFSETOF_SIZEOF_ARR macro listing the {offsetof, sizeof} of
# each member, terminated by {0, 0}.
#
# Usage (matches the original invocation):
#   python3 build-aux/extract-odp-netlink-macros-h.py include/odp-netlink.h \
#       > include/odp-netlink-macros.h
#
# Only the Python standard library is used.

import re
import sys

# Order matters: it determines the order of the emitted macros and must match
# the original shell script exactly.
STRUCTS = [
    "ovs_key_ethernet",
    "ovs_key_ipv4",
    "ovs_key_ipv6",
    "ovs_key_tcp",
    "ovs_key_udp",
    "ovs_key_sctp",
    "ovs_key_icmp",
    "ovs_key_icmpv6",
    "ovs_key_arp",
    "ovs_key_nd",
    "ovs_key_nd_extensions",
]


def find_line_start(lines, struct_name):
    """Replicate: grep -nw $struct_name $hfile | grep { | cut -d ":" -f1

    Returns the 1-based line number of the (single expected) line that
    contains struct_name as a whole word and also contains a '{'.
    """
    # grep -w word boundaries: a "word" character is [A-Za-z0-9_]; the match
    # must not be adjacent to another word character.
    word_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(struct_name) +
                         r"(?![A-Za-z0-9_])")
    matches = []
    for idx, line in enumerate(lines, start=1):
        if word_re.search(line) and "{" in line:
            matches.append(idx)
    # The shell pipeline's `cut -d ":" -f1` on multiple grep matches would
    # yield several line numbers on separate lines; the surrounding arithmetic
    # only uses the first.  In practice each struct matches exactly one line.
    return matches[0] if matches else None


def find_line_end(lines, line_start):
    """Replicate:
        num_lines=`tail -n +${line_start} $hfile | grep -n -m1 } | cut -d ":" -f1`
        line_end=$((line_start+num_lines-1))

    tail -n +N starts at line N (1-based); grep -n -m1 } finds the first line
    (1-based within that tail) containing '}'.
    """
    tail = lines[line_start - 1:]
    for offset, line in enumerate(tail, start=1):
        if "}" in line:
            num_lines = offset
            return line_start + num_lines - 1
    return None


def field_line_to_macro(struct_name, field_line):
    """Replicate the dynamically built awk program for one input line.

    awk default field splitting is on runs of whitespace, ignoring leading and
    trailing whitespace.  The shell first does `awk -F ";" ... {print $1}`,
    i.e. takes everything before the first ';'.
    """
    before_semi = field_line.split(";", 1)[0]
    fields = before_semi.split()  # whitespace split, drops empties
    nf = len(fields)
    if nf == 3:
        return ('    {offsetof(struct %s, %s), sizeof(%s %s)}, \\'
                % (struct_name, fields[2], fields[0], fields[1]))
    elif nf == 2:
        return ('    {offsetof(struct %s, %s), sizeof(%s)}, \\'
                % (struct_name, fields[1], fields[0]))
    else:
        return '    {0, 0}}'


def generate_fields_macros(out, lines, struct_name):
    line_start = find_line_start(lines, struct_name)
    line_end = find_line_end(lines, line_start)

    struct_upper = struct_name.upper()
    out.append('#define %s_OFFSETOF_SIZEOF_ARR { \\' % struct_upper)

    # awk processed lines with NR > line_start && NR <= line_end (1-based).
    for nr in range(line_start + 1, line_end + 1):
        out.append(field_line_to_macro(struct_name, lines[nr - 1]))

    out.append('')
    out.append('')


def main():
    hfile = sys.argv[1]
    with open(hfile, "r", newline="") as f:
        data = f.read()

    # Split into logical lines (without terminators), tolerating CRLF input so
    # that output is LF-only and byte-identical to the reference.
    body = data[:-1] if data.endswith("\n") else data
    lines = body.split("\n")
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in lines]

    out = []
    out.append('/* Generated automatically from <include/odp-netlink.h>'
               ' -- do not modify! */')
    out.append('#ifndef ODP_NETLINK_MACROS_H')
    out.append('#define ODP_NETLINK_MACROS_H')
    out.append('')
    out.append('')

    for struct_name in STRUCTS:
        generate_fields_macros(out, lines, struct_name)

    out.append('')
    out.append('#endif')

    text = "\n".join(out) + "\n"
    # Raw byte write to avoid newline translation on Windows.
    sys.stdout.buffer.write(text.encode("utf-8"))


if __name__ == "__main__":
    main()
