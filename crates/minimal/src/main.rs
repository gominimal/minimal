use build_sandbox::{BuildConfig, Result, config::BuildScript, run_build};
use clap::Parser;
use graph::{
    ExecPlan, SpecReader, SpecReaderOptions,
    dep_graph::{BuildOutput, DepGraph},
};
use std::path::{Path, PathBuf};
use tracing::debug;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "minimal")]
#[command(about = "A minimal package manager")]
struct Args {
    /// Package name to build
    #[arg(short, long)]
    package: String,

    /// Output directory for build results
    #[arg(short, long, default_value = "minimal-out")]
    output: String,

    /// Launch debug shell instead of building
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let base_package_dir = Path::new("packages");
    let package_name = &args.package;
    let package_dir = base_package_dir.join(package_name);

    let build_ncl_path = package_dir.join("build.ncl");
    if !build_ncl_path.exists() {
        eprintln!(
            "Error: build.ncl not found in package directory: {}",
            package_dir.display()
        );
        std::process::exit(1);
    }

    let sr = SpecReader::new_with_path(
        build_ncl_path,
        &SpecReaderOptions {
            minimal_lib_path: "crates/graph/minimal-ncl".into(),
        },
    );

    sr.as_ref().err().into_iter().for_each(|e| {
        e.report_to_stderr();
        panic!("spec parsing failed");
    });
    let sr = sr.unwrap();

    let dp = DepGraph::new(sr).unwrap();
    let plan = ExecPlan::new(&dp);

    let output_base_dir = Path::new(&args.output);

    // Execute builds in dependency order - each build runs in isolation
    // and can only access outputs from previously completed builds
    for phase in plan {
        for bsr in phase.iter() {
            let build = dp.get(bsr).unwrap();
            // In debug mode, only debug the requested package, not its dependencies
            if args.debug {
                if build.name != *package_name {
                    println!("Skipping dependency build in debug mode: {}", build.name);
                    continue;
                }
                println!("Launching debug shell for: {}", build.name);
            } else {
                println!("Executing build: {} (isolated)", build.name);
            }

            // For this build, only include:
            // 1. Host paths from its own inputs
            // 2. Output directories from already-completed dependency builds
            let mut dependencies = Vec::new();

            // Add host paths from this build's own inputs
            debug!("Build {} has {} inputs", build.name, build.inputs.len());
            for (i, input) in build.inputs.iter().enumerate() {
                use graph::BuildSpecInput;
                match input {
                    BuildSpecInput::Path(path) => {
                        debug!("  Input {}: HostPath({})", i, path.display());
                        dependencies.push(PathBuf::from(path));
                    }
                    BuildSpecInput::Build(_build_ref) => {
                        debug!("  Input {}: BuildSpec dependency", i);
                        // Build dependencies are handled by execution order -
                        // their outputs are already available in output_base_dir
                        let abs_output_dir = output_base_dir
                            .canonicalize()
                            .unwrap_or_else(|_| output_base_dir.to_path_buf());
                        dependencies.push(abs_output_dir);
                    }
                    BuildSpecInput::Source(_) => todo!(),
                }
            }

            // Add toolchain and scripts (always needed)
            dependencies.push(
                PathBuf::from("toolchains/x86_64-buildroot-linux-gnu")
                    .canonicalize()
                    .unwrap(),
            );
            dependencies.push(PathBuf::from("scripts").canonicalize().unwrap());

            debug!(
                "Dependencies for isolated build {}: {:?}",
                build.name, dependencies
            );

            let build_package_dir = base_package_dir.join(&build.name);

            // Collect inputs - the package directory plus any build dependencies' outputs
            let inputs = vec![build_package_dir];

            // For build dependencies, we don't copy to inputs anymore -
            // they will be bind mounted directly into the sandbox root
            // Just keep inputs as the package directory only

            let config = BuildConfig {
                dependencies,
                inputs,
                build_script: BuildScript {
                    executable: build.cmd.clone().into(),
                    args: vec![],
                },
                outputs: build
                    .outputs
                    .values()
                    .map(|output| match output {
                        BuildOutput::Library { glob } => glob.clone(),
                        BuildOutput::Binary { .. } => todo!(),
                    })
                    .collect(),
                debug_shell: args.debug,
            };

            // Each build runs in complete isolation and outputs to the shared directory
            // Later builds can access outputs from earlier builds via the shared directory
            let _build_result = run_build(&config, output_base_dir, true)?;

            println!("Completed isolated build: {}", build.name);
        }
    }

    Ok(())
}
