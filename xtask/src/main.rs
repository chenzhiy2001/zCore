#![deny(warnings)]

#[macro_use]
extern crate clap;

#[cfg(not(target_arch = "riscv64"))]
mod dump;

mod arch;
mod build;
mod commands;
mod errors;
mod linux;

use arch::{Arch, ArchArg};
use build::{GdbArgs, OutArgs, QemuArgs};
use clap::Parser;
use errors::XError;
use linux::LinuxRootfs;
use once_cell::sync::Lazy;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use crate::build::{BuildArgs, BuildConfig};

/// The path of zCore project.
static PROJECT_DIR: Lazy<&'static Path> =
    Lazy::new(|| Path::new(std::env!("CARGO_MANIFEST_DIR")).parent().unwrap());
/// The path to store arch-dependent files from network.
static ARCHS: Lazy<PathBuf> =
    Lazy::new(|| PROJECT_DIR.join("ignored").join("origin").join("archs"));
/// The path to store third party repos from network.
static REPOS: Lazy<PathBuf> =
    Lazy::new(|| PROJECT_DIR.join("ignored").join("origin").join("repos"));
/// The path to cache generated files durning processes.
static TARGET: Lazy<PathBuf> = Lazy::new(|| PROJECT_DIR.join("ignored").join("target"));

/// Build or test zCore.
#[derive(Parser)]
#[clap(name = "zCore configure")]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 设置 git 代理。Sets git proxy.
    ///
    /// 通过 `--port` 传入代理端口，或者不传入端口以清除代理设置。
    ///
    /// Input your proxy port through `--port`,
    /// or leave blank to unset it.
    ///
    /// 设置 `--global` 修改全局设置。
    ///
    /// Set `--global` for global configuration.
    ///
    /// ## Example
    ///
    /// ```bash
    /// cargo git-proxy --global --port 12345
    /// ```
    ///
    /// ```bash
    /// cargo git-proxy --global
    /// ```
    GitProxy(ProxyPort),

    /// 打印构建信息。Dumps build config.
    ///
    /// ## Example
    ///
    /// ```bash
    /// cargo dump
    /// ```
    #[cfg(not(target_arch = "riscv64"))]
    Dump,

    /// 下载 zircon 模式需要的二进制文件。Download zircon binaries.
    ///
    /// ## Example
    ///
    /// ```bash
    /// cargo zircon-init
    /// ```
    ZirconInit,

    /// 更新工具链、依赖和子项目。Updates toolchain, dependencies and submodules.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo update-all
    /// ```
    UpdateAll,

    /// 静态检查。Checks code without running.
    ///
    /// 设置多种编译选项，检查代码能否编译。
    ///
    /// Try to compile the project with various different features.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo check-style
    /// ```
    CheckStyle,

    /// 生成内核反汇编文件。Dumps the asm of kernel.
    ///
    /// 默认保存到 `target/zcore.asm`。
    ///
    /// The default output is `target/zcore.asm`.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo asm --arch riscv64 --output riscv64.asm
    /// ```
    Asm(OutArgs),

    /// 生成内核 raw 镜像到指定位置。Strips kernel binary for specific architecture.
    ///
    /// 默认输出到 `target/{arch}/release/zcore.bin`。
    ///
    /// The default output is `target/{arch}/release/zcore.bin`.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo bin --arch riscv64 --output zcore.bin
    /// ```
    Bin(OutArgs),

    /// 在 qemu 中启动 zCore。Runs zCore in qemu.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo qemu --arch riscv64 --smp 4
    /// ```
    Qemu(QemuArgs),

    /// 启动 gdb 并连接到指定端口。Launches gdb and connects to a port.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo gdb --arch riscv64 --port 1234
    /// ```
    Gdb(GdbArgs),

    /// 重建 Linux rootfs。Rebuilds the linux rootfs.
    ///
    /// 这个命令会清除已有的为此架构构造的 rootfs 目录，重建最小的 rootfs。
    ///
    /// This command will remove the existing rootfs directory for this architecture,
    /// and rebuild the minimum rootfs.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo rootfs --arch riscv64
    /// ```
    Rootfs(ArchArg),

    /// 将 musl 动态库拷贝到 rootfs 目录对应位置。Copies musl so files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo musl-libs --arch riscv64
    /// ```
    MuslLibs(ArchArg),

    /// 将 ffmpeg 动态库拷贝到 rootfs 目录对应位置。Copies ffmpeg so files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo ffmpeg --arch riscv64
    /// ```
    Ffmpeg(ArchArg),

    /// 将 opencv 动态库拷贝到 rootfs 目录对应位置。Copies opencv so files to rootfs directory.
    ///
    /// 如果 ffmpeg 已经放好了，opencv 将会编译出包含 ffmepg 支持的版本。
    ///
    /// If ffmpeg is already there, this opencv will build with ffmpeg support.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo opencv --arch riscv64
    /// ```
    Opencv(ArchArg),

    /// 将 libc 测试集拷贝到 rootfs 目录对应位置。Copies libc test files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo libc-test --arch riscv64
    /// ```
    LibcTest(ArchArg),

    /// 将其他测试集拷贝到 rootfs 目录对应位置。Copies other test files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo other-test --arch riscv64
    /// ```
    OtherTest(ArchArg),

    /// 构造 Linux rootfs 镜像文件。Builds the linux rootfs image file.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo image --arch riscv64
    /// ```
    Image(ArchArg),

    /// 构造 libos 需要的 rootfs 并放入 libc test。Builds the libos rootfs and puts it into libc test.
    ///
    /// > **注意** 这可能不是这个命令的最终形态，因此这个命令没有别名。
    /// >
    /// > **NOTICE** This may not be the final form of this command, so this command has no alias.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo xtask libos-libc-test
    /// ```
    LibosLibcTest,

    /// 在 linux libos 模式下启动 zCore 并执行位于指定路径的应用程序。Runs zCore in linux libos mode and runs the executable at the specified path.
    ///
    /// > **注意** libos 模式只能执行单个应用程序，完成就会退出。
    /// >
    /// > **NOTICE** zCore can only run a single executable in libos mode, and it will exit after finishing.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo linux-libos --args /bin/busybox
    /// ```
    LinuxLibos(LinuxLibosArg),
}

#[derive(Args)]
struct ProxyPort {
    /// Proxy port.
    #[clap(long)]
    port: Option<u16>,
    /// Global config.
    #[clap(short, long)]
    global: bool,
}

#[derive(Args)]
struct LinuxLibosArg {
    /// Command for busybox.
    #[clap(short, long)]
    pub args: String,
}

fn main() {
    use Commands::*;
    match Cli::parse().command {
        GitProxy(ProxyPort { port, global }) => {
            if let Some(port) = port {
                set_git_proxy(global, port);
            } else {
                unset_git_proxy(global);
            }
        }
        #[cfg(not(target_arch = "riscv64"))]
        Dump => dump::dump_config(),
        ZirconInit => install_zircon_prebuilt(),
        UpdateAll => update_all(),
        CheckStyle => check_style(),

        Rootfs(arg) => arg.linux_rootfs().make(true),
        MuslLibs(arg) => {
            // 丢弃返回值
            arg.linux_rootfs().put_musl_libs();
        }
        Opencv(arg) => arg.linux_rootfs().put_opencv(),
        Ffmpeg(arg) => arg.linux_rootfs().put_ffmpeg(),
        LibcTest(arg) => arg.linux_rootfs().put_libc_test(),
        OtherTest(arg) => arg.linux_rootfs().put_other_test(),
        Image(arg) => arg.linux_rootfs().image(),
        Asm(args) => args.asm(),
        Bin(args) => {
            // 丢弃返回值
            args.bin();
        }
        Qemu(args) => args.qemu(),
        Gdb(args) => args.gdb(),

        LibosLibcTest => {
            libos::rootfs(true);
            libos::put_libc_test();
        }
        LinuxLibos(arg) => libos::linux_run(arg.args),
    }
}

/// 更新子项目。
fn git_submodule_update(init: bool) {
    use os_xtask_utils::{CommandExt, Git};
    Git::submodule_update(init).invoke();
}

/// 下载 zircon 模式所需的测例和库
fn install_zircon_prebuilt() {
    use commands::wget;
    use os_xtask_utils::{dir, CommandExt, Tar};
    const URL: &str =
        "https://github.com/rcore-os/zCore/releases/download/prebuilt-2208/prebuilt.tar.xz";
    let tar = Arch::X86_64.origin().join("prebuilt.tar.xz");
    wget(URL, &tar);
    // 解压到目标路径
    let dir = PROJECT_DIR.join("prebuilt");
    let target = TARGET.join("zircon");
    dir::rm(&dir).unwrap();
    dir::rm(&target).unwrap();
    fs::create_dir_all(&target).unwrap();
    Tar::xf(&tar, Some(&target)).invoke();
    dircpy::copy_dir(target.join("prebuilt"), dir).unwrap();
}

/// 更新工具链和依赖。
fn update_all() {
    use os_xtask_utils::{Cargo, CommandExt, Ext};
    git_submodule_update(false);
    Ext::new("rustup").arg("update").invoke();
    Cargo::update().invoke();
}

/// 设置 git 代理。
fn set_git_proxy(global: bool, port: u16) {
    use os_xtask_utils::{CommandExt, Git};
    let dns = fs::read_to_string("/etc/resolv.conf")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("nameserver ")
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
        })
        .expect("FAILED: detect DNS");
    let proxy = format!("socks5://{dns}:{port}");
    Git::config(global).args(&["http.proxy", &proxy]).invoke();
    Git::config(global).args(&["https.proxy", &proxy]).invoke();
    println!("git proxy = {proxy}");
}

/// 移除 git 代理。
fn unset_git_proxy(global: bool) {
    use os_xtask_utils::{CommandExt, Git};
    Git::config(global)
        .args(&["--unset", "http.proxy"])
        .invoke();
    Git::config(global)
        .args(&["--unset", "https.proxy"])
        .invoke();
    println!("git proxy =");
}

/// 风格检查。
fn check_style() {
    use os_xtask_utils::{Cargo, CommandExt};
    println!("Check workspace");
    Cargo::fmt().arg("--all").arg("--").arg("--check").invoke();
    Cargo::clippy().all_features().invoke();
    Cargo::doc().all_features().arg("--no-deps").invoke();

    println!("Check libos");
    // println!("    Checks zircon libos");
    // Cargo::clippy()
    //     .package("zcore")
    //     .features(false, &["zircon", "libos"])
    //     .invoke();
    println!("    Checks linux libos");
    Cargo::clippy()
        .package("zcore")
        .features(false, &["linux", "libos"])
        .invoke();

    println!("Check bare-metal");
    for arch in [Arch::Riscv64, Arch::X86_64, Arch::Aarch64] {
        println!("    Checks {} bare-metal", arch.name());
        BuildConfig::from_args(BuildArgs {
            machine: format!("virt-{}", arch.name()),
            debug: false,
        })
        .invoke(Cargo::clippy);
    }
}

mod libos {
    use crate::{arch::Arch, commands::wget, linux::LinuxRootfs, ARCHS, TARGET};
    use os_xtask_utils::{dir, Cargo, CommandExt, Tar};
    use std::fs;

    /// 部署 libos 使用的 rootfs。
    pub(super) fn rootfs(clear: bool) {
        // 下载
        const URL: &str =
            "https://github.com/YdrMaster/zCore/releases/download/musl-cache/rootfs-libos.tar.gz";
        let origin = ARCHS.join("libos").join("rootfs-libos.tar.gz");
        dir::create_parent(&origin).unwrap();
        wget(URL, &origin);
        // 解压
        let target = TARGET.join("libos");
        fs::create_dir_all(&target).unwrap();
        Tar::xf(origin.as_os_str(), Some(&target)).invoke();
        // 拷贝
        const ROOTFS: &str = "rootfs/libos";
        if clear {
            dir::clear(ROOTFS).unwrap();
        }
        dircpy::copy_dir(target.join("rootfs"), ROOTFS).unwrap();
    }

    /// 将 x86_64 的 libc-test 复制到 libos。
    pub(super) fn put_libc_test() {
        const TARGET: &str = "rootfs/libos/libc-test";
        let x86_64 = LinuxRootfs::new(Arch::X86_64);
        x86_64.put_libc_test();
        dir::clear(TARGET).unwrap();
        dircpy::copy_dir(x86_64.path().join("libc-test"), TARGET).unwrap();
    }

    /// libos 模式执行应用程序。
    pub(super) fn linux_run(args: String) {
        println!("{}", std::env!("OUT_DIR"));
        rootfs(false);
        // 启动！
        Cargo::run()
            .package("zcore")
            .release()
            .features(true, ["linux", "libos"])
            .arg("--")
            .args(args.split_whitespace())
            .invoke()
    }
}
