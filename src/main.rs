//! A tiny shell with job control, implemented in Rust.
//!
//! This is a Rust port of the CS:APP Shell Lab (tsh).

use std::env;
use std::ffi::{CStr, CString};
use std::io::{self, BufRead, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::libc;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::stat;
use nix::sys::wait::{self, WaitPidFlag, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};

// Constants
const MAXJOBS: usize = 16;

/// Job states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobState {
    Undefined,
    Foreground,
    Background,
    Stopped,
}

impl JobState {
    fn as_str(self) -> &'static str {
        match self {
            JobState::Undefined => "Undefined",
            JobState::Foreground => "Foreground",
            JobState::Background => "Running",
            JobState::Stopped => "Stopped",
        }
    }
}

/// A job in the shell
#[derive(Debug, Clone)]
struct Job {
    pid: Pid,
    jid: i32,
    state: JobState,
    cmdline: String,
}

impl Job {
    fn new() -> Self {
        Self {
            pid: Pid::from_raw(0),
            jid: 0,
            state: JobState::Undefined,
            cmdline: String::new(),
        }
    }

    fn clear(&mut self) {
        self.pid = Pid::from_raw(0);
        self.jid = 0;
        self.state = JobState::Undefined;
        self.cmdline.clear();
    }

    fn is_empty(&self) -> bool {
        self.pid.as_raw() == 0
    }
}

/// Shell state
struct ShellState {
    jobs: [Job; MAXJOBS],
    next_jid: i32,
    verbose: bool,
}

impl ShellState {
    fn new() -> Self {
        Self {
            jobs: std::array::from_fn(|_| Job::new()),
            next_jid: 1,
            verbose: false,
        }
    }

    fn add_job(&mut self, pid: Pid, state: JobState, cmdline: &str) -> bool {
        if pid.as_raw() < 1 {
            return false;
        }

        for job in &mut self.jobs {
            if job.is_empty() {
                job.pid = pid;
                job.state = state;
                job.jid = self.next_jid;
                self.next_jid += 1;
                if self.next_jid > MAXJOBS as i32 {
                    self.next_jid = 1;
                }
                job.cmdline = cmdline.to_string();
                if self.verbose {
                    println!("Added job [{}] {} {}", job.jid, job.pid, job.cmdline);
                }
                return true;
            }
        }
        println!("Tried to create too many jobs");
        false
    }

    fn delete_job(&mut self, pid: Pid) -> bool {
        if pid.as_raw() < 1 {
            return false;
        }

        for job in &mut self.jobs {
            if job.pid == pid {
                job.clear();
                self.next_jid = self.max_jid() + 1;
                return true;
            }
        }
        false
    }

    fn max_jid(&self) -> i32 {
        self.jobs.iter().map(|j| j.jid).max().unwrap_or(0)
    }

    fn fg_pid(&self) -> Option<Pid> {
        self.jobs
            .iter()
            .find(|j| j.state == JobState::Foreground)
            .map(|j| j.pid)
    }

    fn get_job_by_pid(&self, pid: Pid) -> Option<&Job> {
        if pid.as_raw() < 1 {
            return None;
        }
        self.jobs.iter().find(|j| j.pid == pid)
    }

    fn get_job_by_pid_mut(&mut self, pid: Pid) -> Option<&mut Job> {
        if pid.as_raw() < 1 {
            return None;
        }
        self.jobs.iter_mut().find(|j| j.pid == pid)
    }

    fn get_job_by_jid_mut(&mut self, jid: i32) -> Option<&mut Job> {
        if jid < 1 {
            return None;
        }
        self.jobs.iter_mut().find(|j| j.jid == jid)
    }

    fn list_jobs(&self) {
        for job in &self.jobs {
            if !job.is_empty() {
                print!("[{}] ({}) {} ", job.jid, job.pid, job.state.as_str());
                print!("{}", job.cmdline);
            }
        }
    }
}

// Atomic flags for signal communication
static GOT_SIGCHLD: AtomicBool = AtomicBool::new(false);
static GOT_SIGINT: AtomicBool = AtomicBool::new(false);
static GOT_SIGTSTP: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe write to stdout
fn sio_puts(s: &str) {
    let _ = unistd::write(io::stdout(), s.as_bytes());
}

/// Signal handler for SIGCHLD
extern "C" fn sigchld_handler(_: libc::c_int) {
    GOT_SIGCHLD.store(true, Ordering::SeqCst);
}

/// Signal handler for SIGINT
extern "C" fn sigint_handler(_: libc::c_int) {
    GOT_SIGINT.store(true, Ordering::SeqCst);
}

/// Signal handler for SIGTSTP
extern "C" fn sigtstp_handler(_: libc::c_int) {
    GOT_SIGTSTP.store(true, Ordering::SeqCst);
}

/// Signal handler for SIGQUIT
extern "C" fn sigquit_handler(_: libc::c_int) {
    sio_puts("Terminating after receipt of SIGQUIT signal\n");
    std::process::exit(1);
}

/// Process any pending signals
fn process_signals(state: &mut ShellState) {
    // Handle SIGCHLD
    if GOT_SIGCHLD.swap(false, Ordering::SeqCst) {
        // Reap all available zombie children
        loop {
            match wait::waitpid(
                Pid::from_raw(-1),
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
            ) {
                Ok(WaitStatus::Exited(pid, _)) | Ok(WaitStatus::Signaled(pid, _, _)) => {
                    if let Some(job) = state.get_job_by_pid(pid) {
                        if job.state == JobState::Background {
                            state.delete_job(pid);
                        }
                    }
                }
                Ok(WaitStatus::StillAlive) | Err(_) => break,
                _ => {}
            }
        }
    }

    // Handle SIGINT
    if GOT_SIGINT.swap(false, Ordering::SeqCst) {
        if let Some(fg_pid) = state.fg_pid() {
            state.delete_job(fg_pid);
            let _ = signal::kill(fg_pid, Signal::SIGINT);
        } else {
            println!("No running foreground job to quit");
            std::process::exit(0);
        }
    }

    // Handle SIGTSTP
    if GOT_SIGTSTP.swap(false, Ordering::SeqCst) {
        if let Some(fg_pid) = state.fg_pid() {
            if let Some(job) = state.get_job_by_pid_mut(fg_pid) {
                let jid = job.jid;
                job.state = JobState::Stopped;
                println!("Job [{}] ({}) stopped by signal SIGTSTP", jid, fg_pid);
            }
            // Send SIGSTOP because SIGTSTP doesn't always work
            let _ = signal::kill(fg_pid, Signal::SIGSTOP);
        } else {
            println!("No running foreground job to stop");
        }
    }
}

/// Find an executable in the PATH
fn find_executable(executable: &str, path_str: &str) -> Option<String> {
    for dir in path_str.split(':') {
        let full_path = format!("{}/{}", dir, executable);
        if let Ok(stat_result) = stat::stat(full_path.as_str()) {
            // Check if file has user execute permission
            if stat_result.st_mode & libc::S_IXUSR != 0 {
                return Some(full_path);
            }
        }
    }
    None
}

/// Check if a command contains a path separator
fn command_is_path(cmd: &str) -> bool {
    cmd.contains('/')
}

/// Parse the command line into arguments and determine if it's a background job
fn parse_cmdline(cmdline: &str) -> (Vec<String>, bool) {
    let trimmed = cmdline.trim_end_matches('\n').trim();

    // Check for background job
    let (cmd_str, is_bg) = if trimmed.ends_with('&') {
        (trimmed.trim_end_matches('&').trim(), true)
    } else {
        (trimmed, false)
    };

    // Split into arguments, handling single quotes
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in cmd_str.chars() {
        match c {
            '\'' if !in_quotes => {
                in_quotes = true;
            }
            '\'' if in_quotes => {
                in_quotes = false;
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    (args, is_bg)
}

/// Execute a built-in command, returning true if it was a built-in
fn builtin_cmd(state: &mut ShellState, args: &[String]) -> bool {
    if args.is_empty() {
        return true;
    }

    match args[0].as_str() {
        "quit" => std::process::exit(0),
        "jobs" => {
            state.list_jobs();
            true
        }
        "bg" | "fg" => {
            do_bgfg(state, args);
            true
        }
        _ => false,
    }
}

/// Execute the bg or fg built-in command
fn do_bgfg(state: &mut ShellState, args: &[String]) {
    let is_fg = args[0] == "fg";

    if args.len() < 2 {
        println!("Format: {} <job_id>", args[0]);
        return;
    }

    let job = if args[1].starts_with('%') {
        // Job ID
        let jid_str = &args[1][1..];
        match jid_str.parse::<i32>() {
            Ok(jid) if jid > 0 => state.get_job_by_jid_mut(jid),
            _ => {
                println!("Job id must be a positive integer");
                return;
            }
        }
    } else {
        // PID
        match args[1].parse::<i32>() {
            Ok(pid) if pid > 0 => state.get_job_by_pid_mut(Pid::from_raw(pid)),
            _ => {
                println!("Pid must be a positive integer");
                return;
            }
        }
    };

    let Some(job) = job else {
        println!("No such job");
        return;
    };

    if job.state != JobState::Stopped {
        println!("Job {} is not stopped", job.jid);
        return;
    }

    let pid = job.pid;
    let new_state = if is_fg {
        JobState::Foreground
    } else {
        JobState::Background
    };
    job.state = new_state;

    println!("Continuing {}: {:?}", pid, new_state);
    let _ = signal::kill(pid, Signal::SIGCONT);

    if is_fg {
        wait_fg(state, pid);
    }
}

/// Wait for a foreground job to complete
fn wait_fg(state: &mut ShellState, pid: Pid) {
    // Block until process exits, stops, or continues
    let _ = wait::waitpid(pid, Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED));

    // If it exited and job is still foreground, delete it
    if let Some(job) = state.get_job_by_pid(pid) {
        if job.state == JobState::Foreground {
            state.delete_job(pid);
        }
    }
}

/// Evaluate and execute a command line
fn eval(state: &mut ShellState, cmdline: &str, path_str: &str) {
    let (args, is_bg) = parse_cmdline(cmdline);

    if args.is_empty() {
        return;
    }

    // Check for built-in command
    if builtin_cmd(state, &args) {
        return;
    }

    // Find the executable
    let cmd_path = if command_is_path(&args[0]) {
        args[0].clone()
    } else {
        match find_executable(&args[0], path_str) {
            Some(path) => path,
            None => {
                println!("Executable {} not found!", args[0]);
                return;
            }
        }
    };

    // Fork and execute
    match unsafe { unistd::fork() } {
        Ok(ForkResult::Child) => {
            // Child process
            // Set process group to the child's PID
            let _ = unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0));

            // Convert args to CStrings
            let c_path = CString::new(cmd_path.as_str()).unwrap();
            let c_args: Vec<CString> = args
                .iter()
                .map(|s| CString::new(s.as_str()).unwrap())
                .collect();
            let c_args_refs: Vec<&CStr> = c_args.iter().map(|s| s.as_c_str()).collect();

            // Execute
            let _ = unistd::execv(&c_path, &c_args_refs);
            eprintln!("execv failed for {}", cmd_path);
            std::process::exit(1);
        }
        Ok(ForkResult::Parent { child }) => {
            // Parent process
            let job_state = if is_bg {
                JobState::Background
            } else {
                JobState::Foreground
            };
            state.add_job(child, job_state, cmdline);

            if !is_bg {
                wait_fg(state, child);
            }
        }
        Err(e) => {
            eprintln!("fork failed: {}", e);
        }
    }
}

/// Install signal handlers
fn install_signal_handlers() -> nix::Result<()> {
    let empty_mask = SigSet::empty();

    // SIGINT handler
    let sigint_action = SigAction::new(
        SigHandler::Handler(sigint_handler),
        SaFlags::SA_RESTART,
        empty_mask,
    );
    unsafe { signal::sigaction(Signal::SIGINT, &sigint_action)? };

    // SIGTSTP handler
    let sigtstp_action = SigAction::new(
        SigHandler::Handler(sigtstp_handler),
        SaFlags::SA_RESTART,
        empty_mask,
    );
    unsafe { signal::sigaction(Signal::SIGTSTP, &sigtstp_action)? };

    // SIGCHLD handler
    let sigchld_action = SigAction::new(
        SigHandler::Handler(sigchld_handler),
        SaFlags::SA_RESTART,
        empty_mask,
    );
    unsafe { signal::sigaction(Signal::SIGCHLD, &sigchld_action)? };

    // SIGQUIT handler
    let sigquit_action = SigAction::new(
        SigHandler::Handler(sigquit_handler),
        SaFlags::SA_RESTART,
        empty_mask,
    );
    unsafe { signal::sigaction(Signal::SIGQUIT, &sigquit_action)? };

    Ok(())
}

fn print_usage() {
    println!("Usage: shell [-hvp]");
    println!("   -h   print this message");
    println!("   -v   print additional diagnostic information");
    println!("   -p   do not emit a command prompt");
    std::process::exit(1);
}

fn main() {
    let mut emit_prompt = true;
    let mut verbose = false;

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    for arg in args.iter().skip(1) {
        if arg.starts_with('-') {
            for c in arg.chars().skip(1) {
                match c {
                    'h' => print_usage(),
                    'v' => verbose = true,
                    'p' => emit_prompt = false,
                    _ => print_usage(),
                }
            }
        }
    }

    // Redirect stderr to stdout
    if let Err(e) = unistd::dup2(io::stdout().as_raw_fd(), io::stderr().as_raw_fd()) {
        eprintln!("dup2 error: {}", e);
        std::process::exit(1);
    }

    // Install signal handlers
    if let Err(e) = install_signal_handlers() {
        eprintln!("Failed to install signal handlers: {}", e);
        std::process::exit(1);
    }

    // Get PATH
    let path_str = env::var("PATH").unwrap_or_default();

    // Initialize shell state
    let mut state = ShellState::new();
    state.verbose = verbose;

    // Main read/eval loop
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        // Process any pending signals
        process_signals(&mut state);

        // Print prompt
        if emit_prompt {
            print!("tsh> ");
            let _ = stdout.flush();
        }

        // Read command line
        let mut cmdline = String::new();
        match stdin.lock().read_line(&mut cmdline) {
            Ok(0) => {
                // EOF (Ctrl-D)
                std::process::exit(0);
            }
            Ok(_) => {
                eval(&mut state, &cmdline, &path_str);
                let _ = stdout.flush();
            }
            Err(e) => {
                eprintln!("read error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
