use std::{
    io::BufRead,
    sync::{Arc, Mutex},
};

use mfile::{Task, TaskAction};
use sandbox2::config::Invocation;
use shlex::Shlex;

use crate::{Error, Options, Runnable};

/// Resolves the commands to run for a task within an existing sandbox.
///
/// When [Runnable::run] is called, this computes invocations from the task's
/// action. For [TaskAction::Exec] and [TaskAction::Bash], invocations are
/// derived directly. For [TaskAction::CmdCmd], the meta-command is executed
/// in the sandbox and its stdout parsed into the final command list.
///
/// The caller receives `Vec<Invocation>` and can execute them on the sandbox.
pub struct TaskEnv<'a, C: sandbox2::Channel> {
    /// The task definition.
    pub task: &'a Task,
    /// The sandbox to use for resolving [TaskAction::CmdCmd] meta-commands.
    pub sandbox: &'a mut sandbox2::Sandbox<C>,
}

impl<C: sandbox2::Channel> TaskEnv<'_, C> {
    /// Resolves the invocations to run for this task.
    ///
    /// For [TaskAction::Exec] and [TaskAction::Bash], invocations are derived
    /// directly from the task definition. For [TaskAction::CmdCmd], the
    /// meta-command is executed in the sandbox and its stdout parsed into the
    /// final command list.
    pub async fn resolve(&mut self) -> Result<Vec<Invocation>, Error> {
        if let Some((command, args)) = self.task.exec_and_args() {
            Ok(vec![Invocation {
                executable: command,
                args,
                envs: Default::default(),
            }])
        } else if let TaskAction::CmdCmd(argv) = &self.task.action {
            // Phase 1: run the meta-command, capturing its stdout.
            let (capture, buf) = CaptureWriter::new();
            self.sandbox
                .run(
                    vec![Invocation {
                        executable: argv[0].clone(),
                        args: argv[1..].to_vec(),
                        envs: Default::default(),
                    }],
                    Some(capture),
                    Some(tokio::io::stderr()),
                )
                .await?;

            // Phase 2: parse each stdout line as a shell command.
            let stdout = buf.lock().unwrap().clone();
            let mut invocations = Vec::new();
            for line_result in std::io::Cursor::new(stdout).lines() {
                let line = line_result.map_err(Error::IO)?;
                let mut lexer = Shlex::new(&line);
                let Some(prog) = lexer.next() else {
                    continue;
                };
                invocations.push(Invocation {
                    executable: prog,
                    args: lexer.collect(),
                    envs: Default::default(),
                });
            }
            Ok(invocations)
        } else {
            Err(Error::Other(anyhow::anyhow!(
                "task has no executable action"
            )))
        }
    }
}

impl<C: sandbox2::Channel> Runnable for TaskEnv<'_, C> {
    type Result = Vec<Invocation>;

    async fn run(&mut self, _opts: &Options<'_>) -> Result<Self::Result, Error> {
        self.resolve().await
    }
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
