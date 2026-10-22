#!/usr/bin/env bash
# Splits the workspace's tests into groups, runs one group, and proves no test was left out.
#
# Usage:
#
#     test-binaries.sh plan                  list every test target, one id per line
#     test-binaries.sh run <group> <record>  build and run one group, appending its ids to <record>
#     test-binaries.sh check <dir>           fail unless the records in <dir> cover the plan once
#
# A test target's id is its package directory, its kind, and its name:
#
#     testing/ef-tests:test:gloas
#     crates/kzg:lib:axiom_kzg
#     crates/kzg:doc:axiom_kzg
#
# The plan holds what a plain workspace test run would run.
# That is every target cargo marks as tested, plus the doc tests of every library.
#
# Each group names its targets by id pattern.
# The rest group takes every target no other group names, so a new target always runs.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cargo_flags=(--all-features --locked --release)

# The group a test target belongs to.
#
# Groups are balanced by build and run time on a hosted runner.
group_of() {
    case "$1" in
        testing/ef-tests:test:gloas) echo gloas ;;
        testing/ef-tests:test:fulu) echo fulu ;;
        testing/ef-tests:test:phase0 | testing/ef-tests:test:altair | \
            testing/ef-tests:test:bellatrix | testing/ef-tests:test:capella)
            echo early-forks
            ;;
        testing/ef-tests:test:deneb | testing/ef-tests:test:electra | \
            testing/ef-tests:test:ssz_generic | testing/ef-tests:test:node)
            echo late-forks
            ;;
        *:test:vectors | *:test:wycheproof | *:test:conformance | *:test:corpus | \
            *:test:multibase_vectors | *:test:wire_vectors)
            echo standards
            ;;
        *) echo rest ;;
    esac
}

# Every test target of the workspace: id, then package name, kind, and target name.
targets() {
    cargo metadata --format-version 1 --no-deps --locked \
        | jq -r '.packages[] | .name as $package
                 | (.manifest_path | rtrimstr("/Cargo.toml")) as $dir
                 | .targets[]
                 | (select(.test and (.kind[0] | IN("lib", "bin", "test")))
                    | [$dir, $package, .kind[0], .name]),
                   (select(.doctest) | [$dir, $package, "doc", .name])
                 | @tsv' \
        | while IFS=$'\t' read -r dir package kind name; do
            printf '%s:%s:%s\t%s\t%s\t%s\n' "${dir#"$root"/}" "$kind" "$name" "$package" "$kind" "$name"
        done \
        | sort
}

# The id of every test target.
plan() {
    targets | cut -f1
}

# Builds and runs one group's test targets.
#
# Each binary runs from its package directory, as cargo runs it.
run() {
    local group=$1 record=$2 failed=0
    local selected executables
    : > "$record"
    selected=$(targets | while IFS=$'\t' read -r id package kind name; do
        [ "$(group_of "$id")" = "$group" ] && printf '%s\t%s\t%s\t%s\n' "$id" "$package" "$kind" "$name"
    done || true)
    if [ -z "$selected" ]; then
        echo "::error::group $group selects no test target"
        exit 1
    fi

    # Phase 1: one build per package, mapping each binary back to its id.
    executables=$(mktemp)
    local package
    for package in $(awk -F'\t' '$3 != "doc" {print $2}' <<< "$selected" | sort -u); do
        local flags=()
        while IFS=$'\t' read -r _ _ kind name; do
            case "$kind" in
                lib) flags+=(--lib) ;;
                bin) flags+=(--bin "$name") ;;
                test) flags+=(--test "$name") ;;
            esac
        done < <(awk -F'\t' -v p="$package" '$2 == p && $3 != "doc"' <<< "$selected")
        cargo test "${cargo_flags[@]}" --no-run -p "$package" "${flags[@]}" \
            --message-format=json-render-diagnostics \
            | jq -r 'select(.reason == "compiler-artifact" and .profile.test and .executable != null)
                     | [(.manifest_path | rtrimstr("/Cargo.toml")), .target.kind[0], .target.name,
                        .executable] | @tsv' \
            | while IFS=$'\t' read -r dir kind name executable; do
                printf '%s:%s:%s\t%s\n' "${dir#"$root"/}" "$kind" "$name" "$executable"
            done >> "$executables"
    done

    # Phase 2: every selected binary, each exactly once.
    while IFS=$'\t' read -r id _ kind _; do
        [ "$kind" = doc ] && continue
        local executable
        executable=$(awk -F'\t' -v id="$id" '$1 == id {print $2}' "$executables")
        if [ "$(wc -l <<< "$executable")" != 1 ] || [ -z "$executable" ]; then
            echo "::error::$id built $(grep -c . <<< "$executable") binaries, not one"
            failed=1
            continue
        fi
        echo "::group::$id"
        if ! (cd "$root/${id%%:*}" && "$executable"); then
            echo "::error::$id failed"
            failed=1
        fi
        echo "::endgroup::"
        echo "$id" >> "$record"
    done <<< "$selected"

    # Phase 3: the doc tests, in one run over every package that has them.
    local doc_packages=()
    for package in $(awk -F'\t' '$3 == "doc" {print $2}' <<< "$selected"); do
        doc_packages+=(-p "$package")
    done
    if [ ${#doc_packages[@]} -gt 0 ]; then
        if ! cargo test "${cargo_flags[@]}" --doc "${doc_packages[@]}"; then
            echo "::error::doc tests failed"
            failed=1
        fi
        awk -F'\t' '$3 == "doc" {print $1}' <<< "$selected" >> "$record"
    fi
    rm -f "$executables"
    return "$failed"
}

# Compares the targets every group ran with the plan.
check() {
    local dir=$1
    local expected ran
    expected=$(plan)
    ran=$(cat "$dir"/* | sort)
    if [ "$expected" != "$ran" ]; then
        echo "::error::the test groups do not run every target exactly once"
        diff <(echo "$expected") <(echo "$ran") || true
        exit 1
    fi
    echo "all $(wc -l <<< "$expected") test targets ran exactly once"
}

case "${1:-}" in
    plan) plan ;;
    run) run "$2" "$3" ;;
    check) check "$2" ;;
    *)
        echo "usage: $0 plan | run <group> <record> | check <dir>" >&2
        exit 2
        ;;
esac
