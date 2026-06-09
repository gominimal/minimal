//! Test helper binary for `tests/krun_smoke.rs`.
//!
//! Exists as a separate process because `krun_start_enter`, on success, calls
//! `exit()` with the guest workload's exit code and never returns. Driving it
//! from inside the test process would tear down the test harness; running it
//! in a child lets the parent test observe the outcome via the child's exit
//! status.
//!
//! Behaviour:
//! 1. Always drive the FFI bring-up surface: create_ctx → set_vm_config(1, 512)
//!    → set_exec("/bin/true"). Print stage markers.
//! 2. If `MINVMD_KERNEL_PATH` and `MINVMD_ROOTFS_PATH` are both set, also
//!    configure them and call `krun_start_enter`. Without either, skip
//!    start_enter — libkrun aborts internally on an incomplete config, so
//!    calling it would be a false-negative for the FFI surface itself.
//!
//! Exit codes:
//!   0 — bring-up surface drove cleanly; or guest workload (/bin/true) ran.
//!   2 — start_enter returned an error (libkrun-side failure before boot).
//!   125/126/127 — libkrun init-time error codes per `krun_start_enter` docs.
//!
//! Linux is a no-op stub (exit 0); the integration test is `target_os = macos`.

fn main() -> Result<(), minvmd::VmError> {
    #[cfg(target_os = "macos")]
    return run_macos();

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("krun_smoke_child: macOS-only; nothing to do on this platform");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn run_macos() -> Result<(), minvmd::VmError> {
    use minvmd::krun::{Context, KernelFormat};

    eprintln!("STAGE: create_ctx");
    let mut ctx = Context::create()?;
    eprintln!("STAGE: create_ctx ok ctx_id={}", ctx.id());

    eprintln!("STAGE: set_vm_config");
    ctx.set_vm_config(1, 512)?;
    eprintln!("STAGE: set_vm_config ok");

    eprintln!("STAGE: set_exec");
    ctx.set_exec("/bin/true", &[] as &[&str], None::<&[&str]>)?;
    eprintln!("STAGE: set_exec ok");

    let kernel = std::env::var("MINVMD_KERNEL_PATH").ok();
    let rootfs = std::env::var("MINVMD_ROOTFS_PATH").ok();
    let Some((kernel, rootfs)) = kernel.zip(rootfs) else {
        eprintln!(
            "STAGE: skip_start_enter \
             (MINVMD_KERNEL_PATH or MINVMD_ROOTFS_PATH unset; FFI bring-up verified, \
             start_enter requires a configured kernel + rootfs)"
        );
        drop(ctx); // RAII free_ctx
        return Ok(());
    };

    eprintln!("STAGE: set_root path={rootfs}");
    ctx.set_root(&rootfs)?;
    eprintln!("STAGE: set_root ok");

    // Per-arch kernel format: the virtio-linux package ships `Image.gz` on
    // aarch64 and `bzImage` on x86_64.
    let format = if cfg!(target_arch = "aarch64") {
        KernelFormat::ImageGz
    } else {
        KernelFormat::Elf
    };
    eprintln!("STAGE: set_kernel path={kernel} format={format:?}");
    ctx.set_kernel(&kernel, format, None::<&std::path::Path>, None)?;
    eprintln!("STAGE: set_kernel ok");

    eprintln!("STAGE: start_enter");
    let err = ctx.start_enter();
    // Reaching this point means start_enter returned an error (libkrun
    // `exit()`s on success and never comes back). Surface the typed error
    // and report exit 2 so the parent test can distinguish from a clean
    // workload run (exit 0) or libkrun init errors (125/126/127).
    eprintln!("STAGE: start_enter returned: {err}");
    std::process::exit(2);
}
