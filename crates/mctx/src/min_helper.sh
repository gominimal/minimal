#!/usr/bin/bash

__min_rpc() {
    local method="$1"
    shift
    local data="$@"

    local error="false"
    local env_pairs=()

    while IFS= read -r line; do
        local tag="${line%%:*}"
        local rest="${line#*:}"
        case "$tag" in
            msg)
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
                echo "error:$rest" >&2
                error="true"
                break
                ;;
        esac
    done < <(echo "${method}%${data}" | socat -,ignoreeof UNIX-CONNECT:/run/minenv_sock)

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
    if [[ -z "$term" || -z "$term" ]]; then
        echo "Usage: min_search <search term>" >&2
        return 1
    fi

    __min_rpc "search" "$term"
}

__min_add() {
    local prefix="$1"
    shift
    local packages="$@"
    if [[ -z "$prefix" || -z "$packages" ]]; then
        echo "Usage: min_add [--session|--build|--runtime|--task <taskname>] <packages>" >&2
        return 1
    fi

    __min_rpc "$prefix" "$packages"
}

min_add() {
    local flag="$1"

    # If no flag provided, or first arg isn't a flag, default to --session
    if [[ -z "$flag" || "$flag" != --* ]]; then
        echo "No --flag provided, defaulting to adding package(s) for this session only"
        flag="--session"
    else
        shift
    fi

    if [[ -z "$1" ]]; then
        echo "Usage: min add [--session|--build|--runtime|--task] <packages>" >&2
        return 1
    fi

    local prefix
    case "$flag" in
        --session)   prefix="add-session"   ;;
        --build)     prefix="add-build"     ;;
        --runtime)   prefix="add-runtime"   ;;
        --task)      prefix="add-task"      ;;
        *)
            echo "error: unknown flag '$flag'. Expected --session, --build, --runtime, or --task" >&2
            return 1
            ;;
    esac

    __min_add "$prefix" "$@"
}

min_check() {
    __min_rpc "check" "$@"
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
        check)
            min_check "$@"
            ;;
        *)
            echo "Usage: min <subcommand>" >&2
            echo "" >&2
            echo "Add packages: min add [--session|--build|--runtime|--task <taskname>] <packages>" >&2
            echo "Search for packages: min search <query>" >&2
            echo "Check minimal configuration: min check" >&2
            exit 1
            ;;
    esac
fi
