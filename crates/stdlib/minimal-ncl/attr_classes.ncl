let env_state_wiring_entry = {
    env_var | String,
    prefix | String,
}
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
let PURL = std.contract.custom (fun _label value =>
    if std.typeof value != 'String then
        'Error { message = "PURLs must be a string" }
    else if std.string.is_match m%%"^pkg:(alpm|apk|bitbucket|cargo|cpan|docker|deb|gem|generic|github|golang|huggingface|npm|oci|pypi|rpm|vscode|yocto)/([^@]*)@(?:[^\s]*)$"%% value then
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
        validate = std.contract.any_of [env_state_wiring_entry, Array env_state_wiring_entry],
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
    }
}
