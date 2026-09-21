#!/bin/bash
# release-notes.sh — print the CHANGELOG.md section for one version.
#
#   scripts/release-notes.sh 0.16.0          # section body to stdout
#   scripts/release-notes.sh v0.16.0         # leading v is accepted
#
# The release workflow runs this twice: in the guard, to refuse a tag that has
# no notes, and before goreleaser, to hand the section over as the release
# header. A release whose body is only the commit list is what this exists to
# prevent — commits say what changed in the code, notes say what changed for
# the person upgrading.
#
# Exit codes: 0 with the section on stdout; 1 when the section is missing or
# empty; 2 on usage error.

set -euo pipefail

version="${1:-}"
if [ -z "$version" ]; then
	echo "usage: $0 <version>" >&2
	exit 2
fi
version="${version#v}"
changelog="$(dirname "$0")/../CHANGELOG.md"

# From the heading of this version up to (not including) the next "## [" one.
# The heading is matched on its literal "## [X.Y.Z]" prefix, never as a regex:
# a "." or a "+" in the version must not match anything but itself. The
# link-reference definitions at the bottom of the file ("[0.16.0]: https://…")
# are not part of any section.
section="$(awk -v heading="## [$version]" '
	/^## \[/ { in_section = (substr($0, 1, length(heading)) == heading); if (in_section) { next } }
	/^\[[^]]+\]: / { next }
	in_section { print }
' "$changelog")"

# Drop leading and trailing blank lines: the emptiness test below has to be
# honest, and the section is pasted verbatim as the top of the release body.
section="$(printf '%s\n' "$section" | sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
	echo "CHANGELOG.md has no section '## [$version]', or it is empty — write the release notes before tagging" >&2
	exit 1
fi
printf '%s\n' "$section"
