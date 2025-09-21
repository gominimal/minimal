{
    BuildSpec | doc "A minimal build spec, defining inputs to the build as well as outputs which carry build artifacts downstream" = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'Builder,
        name
          | String,
        inputs
          | Array Input,
        runtime_deps
          | Array BuildSpec | optional,

        cmd | String,
        build_args | {_: String} | optional,

        # Do NOT set this yourself
        __magic_buildspec_id | optional,

        replace_on_cycle | BuildSpec | optional,

        outputs
          | {_ : Output} | optional = {},
    },
    build | Dyn -> BuildSpec | doc "Constructs a minimal build spec." =
      fun spec => spec | BuildSpec,

    Output | doc "An artifact produced by the execution of a build spec" = std.contract.any_of [OutputLib, OutputBin, OutputData],

    OutputLib | doc "An output of a build spec which represents a shared library." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'OutputLib,
        glob
          | String,
    },
    OutputBin | doc "An output of a build spec which represents a shared library." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'OutputBin,
        path
          | String,
    },
    OutputData | doc "An output of a build spec which represents data files that are used during execution." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'OutputData,
        data
          | String,
    },

    HostPath | doc "An input which represents a path on the building machine" = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'Path,
        path
          | String,
    },

    Input = std.contract.any_of [BuildSpec, HostPath, Source, Local, Prebuilt, Subset],

    Source | doc "An input to a build spec which represents source code from some location." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'Source,
        url
          | String,
        sha256
          | String,
    },

    Local = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'Local,
        file
          | String,
    },

    Prebuilt | doc "An input to a build spec which represents a prebuilt package from remote storage." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'Prebuilt,
        package
          | String,
        sha256
          | String | optional,
    },

    Subset | doc "A dependency on a subset of the outputs from another build spec." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'OutputData, 'Source, 'Local, 'Prebuilt, 'Subset |] = 'Subset,
        from
          | BuildSpec,
        outputs
          | Array String,
        strict
          | Bool | optional = false,
    },

    subsetOf | BuildSpec -> Array String -> Subset | doc "Constructs a subset of the outputs of a build, for use as an input or runtime_dep." = 
      fun spec outputs =>
        {from = spec, include outputs}  | Subset,
}
