let Tys = [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |]
in
let attrs_schema = import "attr_classes.ncl"
in
{
    Attrs = std.contract.custom (fun label value =>
        if std.is_record value then
            value
            |> std.record.fields
            |> std.array.fold_right
                (fun field_name rest =>
                    if std.record.has_field field_name attrs_schema then
                        rest
                    else
                        'Error { message = "no such attribute `%{field_name}`" }
                )
                ('Ok value)
        else
            'Error { message = "not a record" }
    ),

    BuildSpec | doc "A minimal build spec, defining inputs to the build as well as outputs which carry build artifacts downstream" = {
        ty | Tys = 'Builder,
        name
          | String,
        inputs
          | Array Input,
        runtime_deps
          | Array RuntimeDep | optional,

        attrs | Attrs | optional,

        cmd | String,
        build_args | {_: String} | optional,

        # Do NOT set this yourself
        __magic_buildspec_id | optional,

        target | String | optional,

        replace_on_cycle | BuildSpec | optional,

        outputs
          | {_ : Output} | optional = {},
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
    },
    OutputBin | doc "An output of a build spec which represents a shared library." = {
        ty | Tys = 'OutputBin,
        glob
          | String,
    },
    OutputData | doc "An output of a build spec which represents data files that are used during execution." = {
        ty | Tys = 'OutputData,
        glob
          | String,
    },

    RuntimeDep | doc "Possible values for a runtime dependency entry." = fun Contract =>
        std.contract.custom (fun label value =>
            match {
                {ty = 'Builder, ..} => std.contract.check BuildSpec label value,
                {ty = 'Subset, ..} => std.contract.check Subset label value,
                _ => 'Error {
                    message = "Expected Input type",
                },
            }
            value
        ),

    Input | doc "Possible inputs to a build spec." = fun Contract =>
        std.contract.custom (fun label value =>
            match {
                {ty = 'Builder, ..} => std.contract.check BuildSpec label value,
                {ty = 'Path, ..} => std.contract.check HostPath label value,
                {ty = 'Source, ..} => std.contract.check Source label value,
                {ty = 'Local, ..}  => std.contract.check Local label value,
                {ty = 'Prebuilt, ..} => std.contract.check Prebuilt label value,
                {ty = 'Subset, ..} => std.contract.check Subset label value,
                _ => 'Error {
                    message = "Expected Input type",
                },
            }
            value
        ),

    HostPath | doc "An input which represents a path on the building machine" = {
        ty | Tys = 'Path,
        path
            | String,
    },

    Source | doc "An input to a build spec which represents source code from some location." = {
        ty | Tys = 'Source,
        url
          | String,
        sha256
          | String,
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

    Prebuilt | doc "An input to a build spec which represents a prebuilt package from remote storage." = {
        ty | Tys = 'Prebuilt,
        package
          | String,
        sha256
          | String | optional,
    },

    Subset | doc "A dependency on a subset of the outputs from another build spec." = {
        ty | Tys = 'Subset,
        from
          | BuildSpec,
        outputs
          | Array String,
    },

    subsetOf | BuildSpec -> Array String -> Subset | doc "Constructs a subset of the outputs of a build, for use as an input or runtime_dep." =
      fun spec outputs =>
        {from = spec, include outputs}  | Subset,
}
