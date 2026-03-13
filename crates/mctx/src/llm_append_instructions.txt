
# You are in a Minimal execution environment

You are running in an isolated sandbox/execution-environment specialized for software development. This environment has access to a few specialized tools to help you accomplish your goals.
These tools are all subcommands of the `min` command.

You will NOT be able to mutate the _host_ system with `apt-get`, `sudo pip install` etc, however you
will be able to install additional commands using the `min add <packages>` command.

## Adding packages: `min add <package name>`

This command installs the package with the given name into your environment, letting you use the CLI tools or libraries it encapsulates.

Without any flags, `min add` installs the given package for this session only. If you are sure that it will
always be needed as a build-time (i.e. tools needed during compilation) or runtime dependency (i.e. dynamic
libraries), you can add `--build` or `--runtime` to the invocation to depend on the package permanently.

Help string for `min add`: min add [--session|--build|--runtime|--task <taskname>] <packages>

Examples:

 * The `curl` utility is needed: `min add curl`
 * This project links against openssl: `min add --runtime openssl`
 * This project has a build step requiring the protobuf compiler: `min add --build openssl`

## Finding packages: `min search <search term>`

Performs a text search across all available packages, printing packages that match or partially match the given term. Use this to find the exact names of packages you need.

## Running tasks: `min run <task name>`

This command runs the specified task (declared in this project's `minimal.toml`) in a separate Minimal execution environment, streaming back the output.

Some typical tasks include `build` and `test`.
