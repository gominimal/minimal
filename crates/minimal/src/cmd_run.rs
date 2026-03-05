use std::{
    io::BufRead,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::anyhow;
use graph::Graph;
use mctx::{Context, Error, Invocation};
use mfile::TaskAction;
use shlex::Shlex;
use tracing::trace;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    pub task_name: String,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_run");
    let graph = ctx.graph_from_all_packages()?;
    let (task, graph) = match ctx.task(graph, &args.task_name)? {
        None => return Err(Error::Other(anyhow!("no such task: {}", args.task_name))),
        Some((t, g)) => (t, g),
    };

    run_task(&args.task_name, &task, graph, ctx).await
}

pub async fn run_task(
    task_name: &str,
    task: &mfile::Task,
    mut graph: Graph,
    ctx: &mut Context,
) -> Result<(), Error> {
    let mut env = ctx
        .make_env(
            task_name,
            &mut graph,
            if task.inherit_cwd {
                Some(std::env::current_dir().unwrap())
            } else {
                None
            },
            task.state_key.as_ref(),
            Some(&task.patch),
            Some(&task.vars),
            task.packages.clone(),
        )
        .await?;

    if let Some((command, args)) = task.exec_and_args() {
        let container = env
            .container()
            .map_err(|e| Error::Other(anyhow!("building container failed: {}", e)))?;
        let mut cmd = env
            .command(&container, &command, args)
            .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
        cmd.spawn()
            .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
            .wait()
            .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;
    } else if let TaskAction::CmdCmd(argv) = &task.action {
        // Phase 1: Run the meta-command, capturing stdout so we can parse
        // the lines it emits into commands for phase 2.
        let (capture, buf) = CaptureWriter::new();
        env.run(
            vec![Invocation {
                executable: argv[0].clone(),
                args: argv[1..].to_vec(),
                envs: Default::default(),
            }],
            Some(capture),
            Some(tokio::io::stderr()),
        )
        .await?;

        // Phase 2: Each line of the meta-command's stdout is a shell command.
        let stdout = buf.lock().unwrap().clone();
        let mut invocations = Vec::new();
        for line_result in std::io::Cursor::new(stdout).lines() {
            let line =
                line_result.map_err(|e| Error::IO("reading meta-commands", PathBuf::new(), e))?;
            let mut lexer = Shlex::new(&line);
            let Some(prog) = lexer.next() else {
                continue;
            };
            println!("+ {}", &line);
            invocations.push(Invocation {
                executable: prog,
                args: lexer.collect(),
                envs: Default::default(),
            });
        }
        env.run(
            invocations,
            Some(tokio::io::stdout()),
            Some(tokio::io::stderr()),
        )
        .await?;
    } else {
        unreachable!();
    }

    Ok(())
}

/// An [`tokio::io::AsyncWrite`] adapter that captures all written bytes into a
/// shared buffer, allowing the caller to read back the data after the writer
/// has been consumed.
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Self(buf.clone()), buf)
    }
}

impl tokio::io::AsyncWrite for CaptureWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.0.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
