#!/usr/bin/bash

# Columns of the terminal stdout writes to, for clipping a progress line so
# it does not wrap. A wrapped line breaks the in-place redraw. Measured
# through fd 3, which the caller points at stdout: inside `$(...)` stdout is
# the capture pipe. 80 when the size cannot be read.
__min_term_cols() {
    local size cols
    size=$(stty size <&3 2>/dev/null) || size=""
    cols=${size##* }
    if [[ "$cols" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s' "$cols"
    else
        printf '80'
    fi
}

# A help request in a subcommand slot, where `help` cannot be a verb.
__min_is_help() {
    case "$1" in
        -h|--help|help) return 0 ;;
        *) return 1 ;;
    esac
}

# A help request in an argument slot. A bare `help` there is a package
# name, search term, or task name, so only the flags count.
__min_is_help_flag() {
    case "$1" in
        -h|--help) return 0 ;;
        *) return 1 ;;
    esac
}

# A help flag anywhere in the arguments. Only for commands whose every
# argument is a valueless flag or a package or object name, none of which
# can be `-h` or `--help`; `min run` forwards later arguments to the task,
# and `min materialize` uses __min_materialize_has_help_flag.
__min_has_help_flag() {
    local arg
    for arg in "$@"; do
        if __min_is_help_flag "$arg"; then
            return 0
        fi
    done
    return 1
}

# A help flag in a `min materialize` argument slot. The value that follows
# `-o`/`--output` or `--arch` is a path or an arch, never a help request.
__min_materialize_has_help_flag() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output|--arch) shift ;;
            -h|--help) return 0 ;;
        esac
        shift
    done
    return 1
}

# Usage text for the dispatch level named by $1 (default: top). Help
# requests print it to stdout and exit 0; error paths print it to stderr.
__min_usage() {
    case "${1:-top}" in
        top)
            echo "Usage: min <subcommand>"
            echo ""
            echo "Add packages: min add [--session|--build|--runtime] <packages>"
            echo "Run a task: min task run <task name>"
            echo "Search for packages: min package search <query>"
            echo "Build packages: min package build <packages>"
            echo "Try building a package (with potentially-stale dependencies): min package patched-build <package name>"
            echo "Check minimal configuration (bare, by exception): min check"
            echo "Materialize an output into the workspace (bare, by exception): min materialize --output <path> [--arch <arch>] <output name>"
            echo "Publish a port from inside the box: min net expose <port>"
            ;;
        package)
            echo "Usage: min package <subcommand>"
            echo ""
            echo "Add packages: min package add [--session|--build|--runtime] <packages>"
            echo "Search for packages: min package search <query>"
            echo "Build packages: min package build <packages>"
            echo "Try building a package (with potentially-stale dependencies): min package patched-build <package name>"
            ;;
        build)
            echo "Usage: min package build <packages>"
            ;;
        search)
            echo "Usage: min package search <query>"
            ;;
        patched-build)
            echo "Usage: min package patched-build <package name>"
            ;;
        add)
            echo "Usage: min add [--session|--build|--runtime] <packages>"
            ;;
        task)
            echo "Usage: min task run <task name>"
            ;;
        check)
            echo "Usage: min check"
            ;;
        materialize)
            echo "Usage: min materialize --output <path> [--arch <arch>] <output name>"
            ;;
        net)
            echo "Usage: min net expose <port>"
            ;;
        expose)
            echo "Usage: min net expose <port>"
            ;;
    esac
}

__min_rpc() {
    local method="$1"
    shift
    local data="$@"

    local error="false"
    local env_pairs=()
    local bar_open=0
    # The exec that runs this helper hands the box its TRACEPARENT (the exec
    # span's W3C context). Forward it ahead of the request so the daemon's
    # work for it (StartMaterialize, ExposeDynamic, ...) joins that trace
    # instead of the channel actor's own root (scenarios 717b, 770). Only a
    # value in the 55-character W3C form crosses: anything in the box can
    # set TRACEPARENT, and a `%` in it would shift the daemon's split of the
    # line.
    local prefix=""
    if [[ "${TRACEPARENT:-}" =~ ^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$ ]]; then
        prefix="traceparent%${TRACEPARENT}%"
    fi

    while IFS= read -r line; do
        local tag="${line%%:*}"
        local rest="${line#*:}"
        case "$tag" in
            bar)
                # One live meter. The daemon sends a fresh line per paint;
                # reprint it on the same row, and clear the row on an empty
                # one. A pipe or a log keeps the one-shot `msg:` lines and
                # drops the redraws. The width is re-read per paint so a
                # resize mid-download does not wrap the row.
                if [[ -t 1 ]]; then
                    if [[ -n "$rest" ]]; then
                        local cols
                        { cols=$(__min_term_cols); } 3>&1
                        printf '\r\033[K%.*s' "$((cols - 1))" "$rest"
                        bar_open=1
                    elif [[ "$bar_open" -eq 1 ]]; then
                        printf '\r\033[K'
                        bar_open=0
                    fi
                fi
                ;;
            msg)
                # Clear the meter rather than leave its last frame behind;
                # the daemon repaints it below this line.
                if [[ "$bar_open" -eq 1 ]]; then
                    printf '\r\033[K'
                    bar_open=0
                fi
                echo "$rest"
                ;;
            set_env)
                local varname="${rest%%:*}"
                local varval="${rest#*:}"
                declare -gx "$varname=$varval"
                env_pairs+=("${varname}=${varval}")
                ;;
            done)
                break
                ;;
            error)
                if [[ "$bar_open" -eq 1 ]]; then
                    printf '\r\033[K'
                    bar_open=0
                fi
                echo "error:$rest" >&2
                error="true"
                break
                ;;
        esac
    done < <(echo "${prefix}${method}%${data}" | socat -,ignoreeof UNIX-CONNECT:/run/minenv_sock)

    if [[ "$bar_open" -eq 1 ]]; then
        printf '\r\033[K'
    fi

    if [[ ${#env_pairs[@]} -gt 0 ]]; then
        echo ""
        echo "Run the following to apply environment variables in your current shell:"
        echo "  export ${env_pairs[*]}"
    fi

    if [[ "$error" == "true" ]]; then
        return 1
    fi
}

min_search() {
    local term="$1"
    if __min_is_help_flag "$term"; then
        __min_usage search
        return 0
    fi
    if [[ -z "$term" ]]; then
        __min_usage search >&2
        return 1
    fi

    __min_rpc "search" "$term"
}

min_patched_pkg() {
    local pkg="$1"
    if __min_is_help_flag "$pkg"; then
        __min_usage patched-build
        return 0
    fi
    if [[ -z "$pkg" || "$pkg" == -* ]]; then
        __min_usage patched-build >&2
        return 1
    fi

    __min_rpc "patched-pkg" "$pkg"
}

__min_add() {
    local prefix="$1"
    shift
    local packages="$@"
    if [[ -z "$prefix" || -z "$packages" ]]; then
        __min_usage add >&2
        return 1
    fi

    __min_rpc "$prefix" "$packages"
}

min_add() {
    local flag="$1"

    if __min_has_help_flag "$@"; then
        __min_usage add
        return 0
    fi

    # If no flag provided, or first arg isn't a flag, default to --session
    if [[ -z "$flag" || "$flag" != --* ]]; then
        flag="--session"
    else
        shift
    fi

    if [[ -z "$1" ]]; then
        __min_usage add >&2
        return 1
    fi

    local prefix
    case "$flag" in
        --session)   prefix="add-session"   ;;
        --build)     prefix="add-build"     ;;
        --runtime)   prefix="add-runtime"   ;;
        *)
            echo "error: unknown flag '$flag'. Expected --session, --build, or --runtime" >&2
            return 1
            ;;
    esac

    __min_add "$prefix" "$@"
}

min_run() {
    if __min_is_help_flag "$1"; then
        __min_usage task
        return 0
    fi
    __min_rpc "run" "$@"
}

min_task() {
    local subcmd="$1"
    shift

    if __min_is_help "$subcmd"; then
        __min_usage task
        return 0
    fi

    case "$subcmd" in
        run)
            min_run "$@"
            ;;
        "")
            __min_usage task >&2
            return 1
            ;;
        *)
            echo "error: unknown subcommand '$subcmd'. Expected 'run'" >&2
            __min_usage task >&2
            return 1
            ;;
    esac
}

min_package() {
    local subcmd="$1"
    shift

    if __min_is_help "$subcmd"; then
        __min_usage package
        return 0
    fi

    case "$subcmd" in
        patched-build)
            min_patched_pkg "$@"
            ;;
        build)
            if __min_has_help_flag "$@"; then
                __min_usage build
                return 0
            fi
            __min_rpc "build" "$@"
            ;;
        search)
            min_search "$@"
            ;;
        add)
            min_add "$@"
            ;;
        "")
            __min_usage package >&2
            return 1
            ;;
        *)
            echo "error: unknown subcommand '$subcmd'. Expected 'add', 'build', 'search', or 'patched-build'" >&2
            __min_usage package >&2
            return 1
            ;;
    esac
}

min_check() {
    if __min_has_help_flag "$@"; then
        __min_usage check
        return 0
    fi
    __min_rpc "check" "$@"
}

min_materialize() {
    if __min_materialize_has_help_flag "$@"; then
        __min_usage materialize
        return 0
    fi
    # The working directory leads the arguments so a relative --output
    # can be resolved.
    __min_rpc "materialize" "${PWD}%$*"
}

min_net() {
    local subcmd="$1"
    shift

    if __min_is_help "$subcmd"; then
        __min_usage net
        return 0
    fi

    case "$subcmd" in
        expose)
            local port="$1"
            if __min_is_help_flag "$port"; then
                __min_usage expose
                return 0
            fi
            if [[ -z "$port" ]]; then
                __min_usage expose >&2
                return 1
            fi
            __min_rpc "net-expose" "$port"
            ;;
        "")
            __min_usage net >&2
            return 1
            ;;
        *)
            echo "error: unknown subcommand '$subcmd'. Expected 'expose'" >&2
            __min_usage net >&2
            return 1
            ;;
    esac
}

# If invoked directly as a script (not sourced), handle invocation
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    subcmd="$1"
    shift
    case "$subcmd" in
        add)
            min_add "$@"
            ;;
        search)
            min_search "$@"
            ;;
        run)
            min_run "$@"
            ;;
        task)
            min_task "$@"
            ;;
        package|pkg)
            min_package "$@"
            ;;
        check)
            min_check "$@"
            ;;
        materialize)
            min_materialize "$@"
            ;;
        net)
            min_net "$@"
            ;;
        -h|--help|help)
            __min_usage
            exit 0
            ;;
        *)
            __min_usage >&2
            exit 1
            ;;
    esac
fi
