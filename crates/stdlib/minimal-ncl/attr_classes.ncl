# Both fields of an env_state_wiring entry are consumed verbatim by the
# shell helpers that export state wiring into the user's live environment
# (env_min_helper.sh / min_helper.sh), and the variable name also travels
# on the daemon-to-helper `set_env:` line protocol. A name containing shell
# array subscripts is evaluated by bash `declare` — `X[$(cmd)]` runs the
# command — and the prefix is printed unquoted in an `export` command for the
# person to run, so each field is pinned here to a shape no shell reads as
# syntax. std.contract.custom keeps both default-free, matching every other
# contract in this file (a default would let a bad value be silently
# replaced rather than rejected).
let env_var_name = std.contract.custom (fun _ value =>
    if !(std.typeof value == 'String) then
        'Error { message = "env_state_wiring's env_var must be a string" }
    else if !(std.string.is_match m%"^[A-Za-z_][A-Za-z0-9_]*$"% value) then
        'Error { message = "env_state_wiring's env_var must be a bare identifier (letters, digits, underscore, not starting with a digit)" }
    else
        'Ok value
)
in
# A prefix is one directory name under /state: it names a directory, never a
# path (`/`, `.`, `..`). The helpers also print it unquoted in an `export`
# command for the person to run, so it is limited to ASCII letters, digits,
# `.`, `_` and `-`: no shell syntax, no space, no `:` that would forge
# daemon-to-helper framing, and no control character. The daemon applies the
# same set again (mfile::is_state_prefix).
let state_prefix = std.contract.custom (fun _ value =>
    if !(std.typeof value == 'String) then
        'Error { message = "env_state_wiring's prefix must be a string" }
    else if value == "." || value == ".." then
        'Error { message = "env_state_wiring's prefix must be one directory name under /state, not `.` or `..`" }
    else if !(std.string.is_match m%"^[A-Za-z0-9._-]+$"% value) then
        'Error { message = "env_state_wiring's prefix must be one directory name under /state, using only ASCII letters, digits, `.`, `_` and `-`" }
    else
        'Ok value
)
in
# Checks one wiring entry eagerly. A record contract checks lazily, so the
# fields are checked by hand here; a missing or malformed one is reported
# with its own message rather than left for whoever reads it first.
let check_wiring_entry = fun label value =>
    if !(std.is_record value) then
        'Error { message = "an env_state_wiring entry is a record" }
    else if !(std.record.has_field "env_var" value) then
        'Error { message = "an env_state_wiring entry needs `env_var`" }
    else if !(std.record.has_field "prefix" value) then
        'Error { message = "an env_state_wiring entry needs `prefix`" }
    else
        let allowed = ["env_var", "prefix"] in
        let unknown = std.record.fields value |> std.array.filter (fun n => !(std.array.elem n allowed)) in
        if std.array.length unknown > 0 then
            'Error { message = "an env_state_wiring entry does not take `%{std.array.first unknown}`" }
        else
            std.contract.check env_var_name label value.env_var
            |> match {
                'Ok _ =>
                    std.contract.check state_prefix label value.prefix
                    |> match {
                        'Ok _ => 'Ok value,
                        'Error e => 'Error e,
                    },
                'Error e => 'Error e,
            }
in
# One entry, or an array of them, folded eagerly so a bad entry is reported
# at load time — since #2047 a consumer reading attrs as values also applies
# an array's pending element contracts, but the fold runs first and carries
# the per-entry error messages.
let env_state_wiring_contract = std.contract.custom (fun label value =>
    if std.is_array value then
        value
        |> std.array.try_fold_left
            (fun acc entry =>
                check_wiring_entry label entry
                |> match {
                    'Ok checked => 'Ok (acc @ [checked]),
                    'Error e => 'Error e,
                })
            []
    else
        check_wiring_entry label value
)
in
let source_provenance_gnu = {
    category = 'GnuProject,
    name | String,
}
in
let source_provenance_sourceforge = {
    category = 'Sourceforge,
    name | String | doc "The name of the project, typically first component of the URL path.",
}
in
let source_provenance_github = {
    category = 'GithubRepo,
    owner | String,
    repo | String,
    # TODO: releases field does not validate for some reason.
    releases | optional | std.contract.custom (fun label value =>
        match {
        'TagBased {..} => 'Ok (value),
        _ => 'Error {
            message = "source_provenance value had invalid/unknown category",
        },
        }
        value
    ),
}
in
let source_provenance_website = {
    category = 'Website,
    homepage | String | optional | doc "The landing page of the software.",
    downloads_page | String | optional | doc "The web page linking to the latest release or enumerating releases.",
}
in
let source_provenance_gitlab = {
    category = 'Gitlab,
    host | String | doc "GitLab instance host, e.g. \"gitlab.com\" or \"gitlab.inria.fr\". GitLab is federated, so the host disambiguates the project (the same owner/repo on two instances are different projects).",
    owner | String | doc "The group/user that owns the project — the path segment before the repo.",
    repo | String | doc "The project (repository) name.",
}
in
let PURL = std.contract.custom (fun _label value =>
    if std.typeof value != 'String then
        'Error { message = "PURLs must be a string" }
    else if std.string.is_match m%%"^pkg:(alpm|apk|bitbucket|cargo|cpan|docker|deb|gem|generic|github|golang|huggingface|npm|oci|pypi|rpm|vscode|yocto)/[^\s/@]+(?:/[^\s/@]+)*(?:@[^\s?#]+)?(?:\?[^\s#]*)?(?:#[^\s]*)?$"%% value then
        'Ok value
    else
        'Error { message = "expected PURL string" }
)
in
{
    upstream_version = {
        name = "upstream version",
        desc = "The software version as declared by the upstream.",
        validate = String,
    },
    repology_project = {
        name = "repology project name",
        desc = "The name of this software as tracked by https://repology.org/.",
        validate = String,
    },
    closed_source = {
        name = "marker for closed-source software",
        desc = "When set, the source backing this package is not publically available.",
        validate = Bool,
    },
    binary_from = {
        name = "binary from",
        desc = "Indicates binaries in the package were fetched from the given URL instead of built from source.",
        validate = std.contract.custom (fun _label value =>
            if std.typeof value != 'String then
                'Error { message = "URLs must be a string" }
            else if std.string.is_match m%%"^(?:https?|ftp|git)://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[^\s]*)?$"%% value then
                'Ok value
            else
                'Error { message = "expected URL string" }
        ),
    },

    description = {
        name = "description",
        desc = "A short description of the function of the software.",
        validate = String,
    },
    license_spdx = {
        name = "spdx license string",
        desc = "The SPDX name of the license the software is covered by. See: https://spdx.org/licenses",
        validate = std.contract.any_of [String, Array String],
    },
    upstream_purl = {
        name = "PURL(s) of the packaged software",
        desc = "The Package URL describing upstream.",
        validate = std.contract.any_of [PURL, Array PURL],
    },
    peer_purl = {
        name = "PURL(s) of the software in other package managers",
        desc = "Package URL(s) of the software within other package managers.",
        validate = std.contract.any_of [PURL, Array PURL],
    },

    env_dir_mappings = {
        name = "environment directory mappings",
        desc = "Necessary bind mounts to directories outside an environment.",
        validate = Array {
            read_only | Bool,
            path | String,
            class | [| 'Credential, 'State |],
        },
    },
    env_file_mappings = {
        name = "environment file mappings",
        desc = "Necessary bind mounts to files outside an environment.",
        validate = Array {
            read_only | Bool,
            path | String,
            class | [| 'Credential, 'State |],
        },
    },

    env_state_wiring = {
        name = "environment state directory & variable",
        desc = "Indicates the need for a state directory in an environment, and the environment variable through which it is communicated.",
        validate = env_state_wiring_contract,
    },

    needed_for_internet = {
        name = "needed for internet",
        desc = "A marker attribute - indicates this package should be present for any environment that needs internet access.",
        validate = {},
    },
    source_provenance = {
        name = "source provenance",
        desc = "Declares the authorative source of source code for this project.",
        validate =
            std.contract.custom (fun label value =>
                match {
                {category = 'GnuProject, ..} => std.contract.check source_provenance_gnu label value,
                {category = 'GithubRepo, ..} => std.contract.check source_provenance_github label value,
                {category = 'Sourceforge, ..} => std.contract.check source_provenance_sourceforge label value,
                {category = 'Website, ..} => std.contract.check source_provenance_website label value,
                {category = 'Gitlab, ..} => std.contract.check source_provenance_gitlab label value,
                    _ => 'Error {
                        message = "source_provenance value had invalid/unknown category",
                    },
                }
                value
            ),
    },

    build_cost_multiple = {
        name = "build cost multiple",
        desc = "Hint to build infrastructure that this build is much more intensive than the typical, by some factor.",
        validate = Number,
    },

    redistributable = {
        name = "redistributable",
        desc = "Whether built artifacts of this package may be redistributed through a shared binary cache. Absent means true. Set false when the upstream license or terms forbid redistribution: build infrastructure then neither uploads, indexes, nor seals the artifacts, and consumers build the package locally from the upstream source.",
        validate = Bool,
    },

    bootstrap_rung = {
        name = "bootstrap ladder rung",
        desc = "Marks this package as a pinned rung of a bootstrap ladder; the value names the ladder (e.g. \"hex0\", \"ghc\", \"jvm\"). A rung's version is its identity: it is fixed by what the previous rung can compile and by the ladder's byte-identity seals, so automated tooling must never propose a version bump for it (pkgmgr freezes it). The top of a ladder, the version users install, is not a rung.",
        validate = String,
    }
}
