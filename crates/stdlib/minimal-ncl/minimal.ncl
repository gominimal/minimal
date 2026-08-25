let Tys = [| 'Builder, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Subset, 'Profile, 'Layer, 'Upstream, 'Test, 'Stack, 'Container |]
in
let attrs_schema = import "attr_classes.ncl" in
let needs_schema = import "need_classes.ncl" in
let CmdSpec = std.contract.any_of [
  String,
  Array String,
] in
# Builds a contract that accepts strings matching `regex`, blaming with `msg`.
let StringMatching = fun regex msg =>
  std.contract.custom (fun label value =>
    if !(std.is_string value) then
      'Error { message = "expected a string" }
    else if std.string.is_match regex value then
      'Ok value
    else
      'Error { message = "%{msg}: got `%{value}`" }
  ) in
# A container image name, following the registry reference grammar: lowercase
# alphanumerics separated by `.`, `_`, or `-`, in `/`-separated path
# components. Registries reject uppercase, so this does too.
let ImageName = StringMatching
  "^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$"
  "not a valid image name: use lowercase alphanumerics separated by `.`, `_`, `-`, or `/`"
in
# A clean absolute path: no relative form, no trailing or repeated `/`, no
# `.`/`..` components. A bare `/` is allowed.
let AbsolutePath =
  std.contract.custom (fun label value =>
    if !(std.is_string value) then
      'Error { message = "expected a string path" }
    else if value == "/" then
      'Ok value
    else if !(std.string.is_match "^(/[^/]+)+$" value) then
      'Error {
        message = "must be an absolute path with no trailing or repeated `/`: got `%{value}`"
      }
    else if std.string.is_match "(^|/)[.][.]?(/|$)" value then
      'Error {
        message = "must not contain `.` or `..` path components: got `%{value}`"
      }
    else
      'Ok value
  ) in
# The user processes run as, in OCI form: `user`, `uid`, `user:group`,
# `uid:gid`, `uid:group`, or `user:gid`.
#
# Prefer numeric ids. A *named* user must resolve through `/etc/passwd` inside
# the image, which a package-assembled rootfs usually lacks, and Kubernetes
# `runAsNonRoot` requires a numeric uid.
let UserSpec = StringMatching
  "^([0-9]+|[A-Za-z_][A-Za-z0-9_.-]*)(:([0-9]+|[A-Za-z_][A-Za-z0-9_.-]*))?$"
  "not a valid user: expected `user`, `uid`, `user:group`, or `uid:gid`"
in
# A signal name, e.g. `SIGTERM` or `SIGRTMIN+3`.
let StopSignal = StringMatching
  "^SIG[A-Z0-9]+([+-][0-9]+)?$"
  "not a valid signal name: expected the `SIGTERM` form"
in
# Environment variables baked into an image. Names must be POSIX portable
# (`[A-Za-z_][A-Za-z0-9_]*`), because runtimes join these into `KEY=VALUE`
# strings and split on the first `=`.
let EnvVars = std.contract.custom (fun label record_value =>
    if !(std.is_record record_value) then
      'Error { message = "not a record" }
    else
      record_value
      |> std.record.to_array
      |> std.array.try_fold_left
        (fun acc { field, value } =>
          if !(std.string.is_match "^[A-Za-z_][A-Za-z0-9_]*$" field) then
            'Error { message = "`%{field}` is not a valid environment variable name" }
          else if !(std.is_string value) then
            'Error { message = "environment variable `%{field}` must be a string" }
          else
            'Ok acc
        )
        null
      |> match {
        'Ok _ => 'Ok record_value,
        'Error e => 'Error e,
      }
  ) in
{
    BuildSpec | doc "A minimal build spec, defining inputs to the build as well as outputs which carry build artifacts downstream" = {
        ty | Tys = 'Builder,
        name
          | String,
        build_deps
          | Array BuildDep,
        runtime_deps
          | Array RuntimeDep | optional,
        needs | Needs | optional,

        attrs | Attrs | optional,

        cmd | CmdSpec | optional,
        cmds | Array CmdSpec | optional,
        build_args | {_: String} | optional,

        # Do NOT set this yourself
        __magic_buildspec_id | optional,
        prebuilt | Bool | optional,

        target | String | optional,

        replace_on_cycle | BuildSpec | optional,

        outputs
          | {_ : Output} | optional = {},

        tests | {_: Test} | optional,
    },
    build | Dyn -> BuildSpec | doc "Constructs a minimal build spec." =
      fun spec => spec | BuildSpec,

    Output | doc "An artifact produced by the execution of a build spec" = fun Contract =>
        std.contract.custom (fun label value =>
            match {
                {ty = 'OutputLib, ..} => std.contract.check OutputLib label value,
                {ty = 'OutputBin, ..}  => std.contract.check OutputBin label value,
                {ty = 'OutputData, ..} => std.contract.check OutputData label value,
                _ => 'Error {
                    message = "Expected Output type",
                },
            }
            value
        ),

    OutputLib | doc "An output of a build spec which represents a shared library." = {
        ty | Tys = 'OutputLib,
        glob
          | String,
        allow_data | Bool | optional,
    },
    OutputBin | doc "An output of a build spec which represents a binary." = {
        ty | Tys = 'OutputBin,
        glob
          | String,
        allow_missing_interpreter | Bool | optional,
    },
    OutputData | doc "An output of a build spec which represents data files that are used during execution." = {
        ty | Tys = 'OutputData,
        glob
          | String,
        allow_executable | Bool | optional,
    },

    RuntimeDep | doc "Possible values for a runtime dependency entry." = fun Contract =>
        std.contract.custom (fun label value =>
            match {
                {ty = 'Builder, ..} => std.contract.check BuildSpec label value,
                {ty = 'Subset, ..} => std.contract.check Subset label value,
                {ty = 'Upstream, ..} => std.contract.check UpstreamPkg label value,
                _ => 'Error {
                    message = "Expected Input type",
                },
            }
            value
        ),

    BuildDep | doc "Possible types in an entry of the build_deps array." = fun Contract =>
        std.contract.custom (fun label value =>
            match {
                {ty = 'Builder, ..} => std.contract.check BuildSpec label value,
                {ty = 'Source, ..} => std.contract.check Source label value,
                {ty = 'Local, ..}  => std.contract.check Local label value,
                {ty = 'Subset, ..} => std.contract.check Subset label value,
                {ty = 'Upstream, ..} => std.contract.check UpstreamPkg label value,
                _ => 'Error {
                    message = "Expected Input type",
                },
            }
            value
        ),

    Source | doc "An input to a build spec which represents source code from some location." = {
        ty | Tys = 'Source,
        file
          | String | optional,

        url
          | String | optional,
        sha256
          | String | optional,

        extract
          | Bool | optional,
        strip_prefix
          | String | optional,
    },

    Local = {
        ty | Tys = 'Local,
        file
          | String,
    },

    Subsettable | doc "Possible types which can be subsetted." = fun Contract =>
        std.contract.custom (fun label value =>
            match {
                {ty = 'Builder, ..} => std.contract.check BuildSpec label value,
                {ty = 'Upstream, ..} => std.contract.check UpstreamPkg label value,
                _ => 'Error {
                    message = "Expected Input type",
                },
            }
            value
        ),
    Subset | doc "A dependency on a subset of the outputs from another build spec." = {
        ty | Tys = 'Subset,
        from
          | Subsettable,
        outputs
          | Array String,
    },
    subsetOf | Dyn -> Array String -> Subset | doc "Constructs a subset of the outputs of a build, for use as an input or runtime_dep." =
      fun spec outputs =>
        {from = spec, include outputs}  | Subset,

    Attrs | doc "A map of attributes applied to a build-spec, which are validated according to attr_classes.ncl."
        = std.contract.custom (fun label record_value =>
        if !(std.is_record record_value) then
            'Error { message = "not a record" }
        else
            record_value
            |> std.record.to_array
            |> std.array.try_fold_left
            (fun acc { field, value } =>
                if std.record.has_field field attrs_schema then
                std.contract.check attrs_schema."%{field}".validate label value
                |> match {
                    'Ok wrapped_value => 'Ok (acc @ [{ include field, value = wrapped_value }]),
                    'Error e => 'Error { message = "failed to validate %{field}", blame_location = e.blame_location }
                }
                else
                'Error { message = "`%{field}` is not a valid attribute" }
            )
            []
            |> match {
            'Ok array => 'Ok (std.record.from_array array),
            'Error e => 'Error e,
            }
        ),
    Needs | doc "Abstract dependencies needed by a build-spec, which are validated according to need_classes.ncl."
        = std.contract.custom (fun label record_value =>
        if !(std.is_record record_value) then
        'Error { message = "not a record" }
        else
        record_value
        |> std.record.to_array
        |> std.array.try_fold_left
            (fun acc { field, value } =>
            if std.record.has_field field needs_schema then
                std.contract.check needs_schema."%{field}".validate label value
                |> match {
                'Ok wrapped_value => 'Ok (acc @ [{ include field, value = wrapped_value }]),
                'Error e => 'Error { message = "failed to validate %{field}", blame_location = e.blame_location }
                }
            else
                'Error { message = "`%{field}` is not a valid need" }
            )
            []
        |> match {
            'Ok array => 'Ok (std.record.from_array array),
            'Error e => 'Error e,
        }
    ),

    # # Profiles were removed 2026-08-06, left to avoid breaking old spec-files
    # profile | Dyn -> Dyn =
    #     fun spec => spec,

    # Intended for internal use
    Layer | doc "Implementation detail: the set of build-specs and profiles to be ingested." = {
        ty | Tys = 'Layer,

        builds | Array BuildSpec,
        profiles | Array Dyn, # Profiles were removed 2026-08-06.
        stacks | Array Stack,
        containers | Array Container,
    },
    layer | Dyn -> Layer | doc "Constructs a layer." =
        fun spec => spec | Layer,

    UpstreamPkg = {
        ty | Tys = 'Upstream,
        name | String,
    },
    upstream | String -> UpstreamPkg | doc "Symbolizes a build with the given name from upstream." =
        fun n => {name = n},

    Test | doc "A unit test for a decl." = {
        ty | Tys = 'Test,
        class | [| 'Standalone, 'Build |],

        test_deps
          | Array RuntimeDep | optional,

        cmd | String | optional,
        cmds | Array (Array String) | optional,
    },
    standaloneTest | String -> Test | doc "A test, run using the outputs of the build." =
        fun cmd => {
            class = 'Standalone,
            include cmd,
        },
    buildTest | String -> Test | doc "A test, run in the build container once the build is completed." =
        fun cmd => {
            class = 'Build,
            include cmd,
        },

    AdditionalPackageMatcherEntry = {
        file_regexes | {_ : String} | optional,
        file_predicates | {_ : String} | optional,
    },
    StackMatcherEntry = {
        file_regexes | {_ : String} | optional,
        file_predicates | {_ : String} | optional,

        build_package_if_any | {_ : Array AdditionalPackageMatcherEntry} | optional,
        runtime_package_if_any | {_ : Array AdditionalPackageMatcherEntry} | optional,
    },

    Stack | doc "A specific way to build a directory of source into software." = {
        ty | Tys = 'Stack,
        name
            | String,

        build_packages
            | Array String | optional,
        runtime_packages
        | Array String | optional,
        build_env_vars
            | {_ : String} | optional,

        build_cmd | CmdSpec | optional,
        build_cmds_cmd | CmdSpec | optional,

        matches_project_if_any | Array StackMatcherEntry | optional,
        matches_project_priority | Number | optional,
    },
    stack | Dyn -> Stack | doc "Constructs a stack." =
        fun spec => spec | Stack,

    Target | doc "A specific system that packages can run on." = {
        os | [| 'Linux, 'MacOS |],
        arch | [| 'Amd64, 'Arm64 |],
    },

    Container | doc "A declared container image." = {
        ty | Tys = 'Container,
        name
            | ImageName,
        packages
            | Array String,

        # OCI has no shell form: a string is word-split into exec form, so an
        # unbalanced quote is an error rather than something the shell sees.
        entrypoint | CmdSpec | optional,
        cmd | CmdSpec | optional,
        # Must match the architecture the packages were built for, or the
        # image pulls cleanly and then fails with `exec format error`.
        arch | [| 'Amd64, 'Arm64 |] | optional,
        working_dir | AbsolutePath | optional,

        env_vars
            | EnvVars | optional,

        # Element contracts can only refer to builtins (see the note above
        # `AbsolutePath`), so the port range, the volume paths, and the
        # set semantics of both are checked by the decoder.
        exposed_ports
            | Array { port | Number, proto | [| 'Tcp, 'Udp |] | default = 'Tcp } | optional,
        volumes
            | Array String | optional,
        user | UserSpec | optional,
        stop_signal | StopSignal | optional,

        labels
            | {_ : String} | optional,
        config
            | {_ : String} | optional,
    },
    container | Dyn -> Container | doc "Constructs a container image." =
        fun spec => spec | Container,
}
