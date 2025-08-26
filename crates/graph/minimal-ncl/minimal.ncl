{
    BuildSpec | doc "A minimal build spec, defining inputs to the build as well as outputs which carry build artifacts downstream" = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'Builder,
        name
          | String,
        inputs
          | Array Input,

        cmd | String,

        outputs
          | {_ : Output} | optional = {},
    },

    Output | doc "An artifact produced by the execution of a build spec" = std.contract.any_of [OutputLib, OutputBin],

    OutputLib | doc "An output of a build spec which represents a shared library." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'OutputLib,
        glob
          | String,
    },
    OutputBin | doc "An output of a build spec which represents a shared library." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'OutputBin,
        path
          | String,
    },

    HostPath | doc "An input which represents a path on the building machine" = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'Path,
        path
          | String,
    },

    Input = std.contract.any_of [BuildSpec, HostPath, Source, Local, Prebuilt],

    Source | doc "An input to a build spec which represents source code from some location." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'Source,
        url
          | String,
        sha256
          | String,
    },

    Local = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'Local,
        file
          | String,
    },

    Prebuilt | doc "An input to a build spec which represents a prebuilt package from remote storage." = {
        ty | [| 'Builder, 'Path, 'OutputLib, 'OutputBin, 'Source, 'Local, 'Prebuilt |] = 'Prebuilt,
        package
          | String,
    },
}
