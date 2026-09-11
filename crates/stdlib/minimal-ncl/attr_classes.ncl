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
let source_provenance_gitlab = {
    category = 'Gitlab,
    host | String | doc "GitLab instance host, e.g. \"gitlab.com\" or \"gitlab.inria.fr\". GitLab is federated, so the host disambiguates the project (the same owner/repo on two instances are different projects).",
    owner | String | doc "The group/user that owns the project — the path segment before the repo.",
    repo | String | doc "The project (repository) name.",
}
in
# --- security-patch revision ledger (inbox#511) -------------------------
# These contracts fail CLOSED on malformed entries: a blank or misshapen
# `cve` / `origin` / `sha256` / `upstream_commit` refuses to parse rather
# than producing an SBOM row that quietly asserts nothing.
let CveId = std.contract.custom (fun _label value =>
    if std.typeof value == 'String && std.string.is_match m%"^CVE-[0-9]{4}-[0-9]{4,}$"% value then
        'Ok value
    else
        'Error { message = "expected a CVE id of the form CVE-YYYY-NNNN…" }
)
in
let Sha256Hex = std.contract.custom (fun _label value =>
    if std.typeof value == 'String && std.string.is_match m%"^[0-9a-f]{64}$"% value then
        'Ok value
    else
        'Error { message = "expected a lowercase 64-char sha256 hex digest" }
)
in
let CommitHex = std.contract.custom (fun _label value =>
    if std.typeof value == 'String && std.string.is_match m%"^[0-9a-f]{7,40}$"% value then
        'Ok value
    else
        'Error { message = "expected an abbreviated or full lowercase commit hash (7-40 hex chars)" }
)
in
let NonBlankString = std.contract.custom (fun _label value =>
    if std.typeof value == 'String && std.string.length (std.string.trim value) > 0 then
        'Ok value
    else
        'Error { message = "expected a non-blank string" }
)
in
let security_patch_entry = {
    file
        | NonBlankString
        | doc "The patch file name as it appears in this spec's build_deps (a Local input).",
    cve
        | CveId
        | doc "The CVE this patch remediates. One entry per CVE, even when one file fixes several — the ledger is what feeds go by.",
    sha256
        | Sha256Hex
        | doc "sha256 of the patch file contents, pinning what was actually applied.",
    origin
        | NonBlankString
        | doc "Where the fix came from: the upstream advisory, MR, or mailing-list URL a reviewer can follow.",
    upstream_commit
        | CommitHex
        | doc "The upstream commit this patch was cherry-picked from (ancestry-verifiable).",
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
        # INVARIANT (inbox#511): upstream_version is the advisory-matching
        # key and must be upstream's label verbatim — it NEVER carries our
        # `-rN` security-revision suffix. Vulnerability feeds and `pkgmgr
        # check` compare against this field; an `-rN` here would silently
        # break CVE matching for the package. Our revision lives in the
        # `revision` attr and is rendered into published version strings
        # (SBOM/OpenVEX/secdb) at the publish boundary only.
        validate = std.contract.custom (fun _label value =>
            if std.typeof value != 'String then
                'Error { message = "upstream_version must be a string" }
            else if std.string.is_match m%"-r[0-9]+$"% value then
                'Error {
                    message = "upstream_version must be upstream's label verbatim — it never carries our -rN revision suffix (that lives in the `revision` attr; see gominimal/inbox#511)",
                }
            else
                'Ok value
        ),
    },
    revision = {
        name = "security patch revision",
        desc = "Counts security patch-sets applied on top of upstream_version. 0 (or absent) = pristine upstream. Owned by pkgmgr — never hand-edited — and resets to 0 on any upstream version bump. Rendered as `-rN` into published version strings (SBOM, OpenVEX, secdb) by the publish-boundary helper.",
        validate = std.contract.custom (fun _label value =>
            if std.typeof value == 'Number && value >= 0 && value == std.number.floor value then
                'Ok value
            else
                'Error { message = "revision must be a non-negative integer" }
        ),
    },
    patches = {
        name = "security patch ledger",
        desc = "Typed record of every security patch applied beyond upstream_version: which CVE, from which upstream commit, via which advisory, with the patch file's digest. This ledger — not the patch files — is what qualified_version() and the vulnerability feeds consume, so entries are contract-enforced: a blank cve or origin refuses to parse.",
        validate = Array security_patch_entry,
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
    }
}
