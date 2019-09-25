//! Read process-specific information from `/proc`.

use std::collections::HashMap;
use std::fs::{self, read_dir, read_link};
use std::fs::{File};
use std::io::{Error, ErrorKind, Result};
use std::io::{self, prelude::*, BufReader}; //TODO integrate in above?
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::ToString;

use lazy_static::lazy_static;
use libc::{kill, sysconf, readlink};
use libc::{SIGKILL, _SC_CLK_TCK, _SC_PAGESIZE, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM};
use libc::{c_char};

use crate::{GID, PID, UID};

lazy_static! {
    static ref TICKS_PER_SECOND: f64 = { unsafe { sysconf(_SC_CLK_TCK) as f64 } };
    static ref PAGE_SIZE: u64 = { unsafe { sysconf(_SC_PAGESIZE) as u64 } };
}

/// Return a path to a file in `/proc/[pid]/`.
fn procfs_path(pid: PID, name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    path.push("/proc");
    path.push(&pid.to_string());
    path.push(&name);
    path
}

/// Return an `io::Error` value and include the path in the message.
fn parse_error<P>(message: &str, path: P) -> Error
where
    P: AsRef<Path>,
{
    let path = path.as_ref().to_str().unwrap_or("unknown path");
    Error::new(
        ErrorKind::InvalidInput,
        format!("{} (from {})", message, path),
    )
}

/// Possible statuses for a process.
#[derive(Clone, Copy, Debug)]
pub enum State {
    Running,
    Sleeping,
    Waiting,
    Stopped,
    Traced,
    Paging,
    Dead,
    Zombie,
    Idle,
}

impl State {
    /// Returns a State based on a status character from `/proc/[pid]/stat`.
    ///
    /// See [array.c:115] and [proc(5)].
    ///
    /// [array.c:115]: https://github.com/torvalds/linux/blob/master/fs/proc/array.c#L115
    /// [proc(5)]: http://man7.org/linux/man-pages/man5/proc.5.html
    pub fn from_char(state: char) -> Result<Self> {
        match state {
            'R' => Ok(State::Running),
            'S' => Ok(State::Sleeping),
            'D' => Ok(State::Waiting),
            'T' => Ok(State::Stopped),
            't' => Ok(State::Traced),
            'W' => Ok(State::Paging),
            'Z' => Ok(State::Zombie),
            'X' => Ok(State::Dead),
            'I' => Ok(State::Idle),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid state character: {:?}", state),
            )),
        }
    }
}

impl FromStr for State {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if !s.len() == 1 {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("State is not a single character: {:?}", s),
            ))
        } else {
            State::from_char(s.chars().nth(0).unwrap())
        }
    }
}

impl ToString for State {
    fn to_string(&self) -> String {
        match *self {
            State::Running => "R".to_string(),
            State::Sleeping => "S".to_string(),
            State::Waiting => "D".to_string(),
            State::Stopped => "T".to_string(),
            State::Traced => "t".to_string(),
            State::Paging => "W".to_string(),
            State::Zombie => "Z".to_string(),
            State::Dead => "X".to_string(),
            State::Idle => "I".to_string(),
        }
    }
}

/// Memory usage of a process read from `/proc/[pid]/statm`.
///
/// The `lib` [4, u64] and `dt` [6, u64] fields are ignored.
#[derive(Clone, Copy, Debug)]
pub struct Memory {
    /// Total program size (bytes).
    pub size: u64,

    /// Resident Set Size (bytes).
    pub resident: u64,

    /// Shared pages (bytes).
    pub share: u64,

    /// Text.
    pub text: u64,

    /// Data + stack.
    pub data: u64,
}

impl Memory {
    pub fn new(pid: PID) -> Result<Memory> {
        let path = procfs_path(pid, "statm");
        let statm = fs::read_to_string(&path)?;
        let fields: Vec<&str> = statm.trim_end().split(' ').collect();

        Ok(Memory {
            size: Memory::parse_bytes(fields[0], &path)? * *PAGE_SIZE,
            resident: Memory::parse_bytes(fields[1], &path)? * *PAGE_SIZE,
            share: Memory::parse_bytes(fields[2], &path)? * *PAGE_SIZE,
            text: Memory::parse_bytes(fields[3], &path)? * *PAGE_SIZE,
            data: Memory::parse_bytes(fields[5], &path)? * *PAGE_SIZE,
        })
    }

    fn parse_bytes(field: &str, path: &PathBuf) -> Result<u64> {
        u64::from_str(field)
            .map_err(|e| parse_error(&format!("Could not parse memory: {}", e), path))
    }
}

#[derive(Debug)]
pub enum FdType {
    File(PathBuf),
    Socket(u64)
}

#[derive(Debug)]
pub struct Fd {
    /// Number of fd
    pub number: i32,

    /// Where this fd links
    pub link: FdType,
}


#[derive(Copy, Clone, Debug)]
struct ConnVariant {
    file: &'static str,
    conn_type: i32,
    family: i32,
}

/// Information about a process gathered from `/proc/[pid]/stat`.
///
/// More information about specific fields can be found in [proc(5)].
///
/// # Field sizes
///
/// The manual pages for `proc` define integer sizes using `scanf(3)` format specifiers, which parse
/// to implementation specific sizes. This is obviously a terrible idea, and so this code makes some
/// assumptions about the sizes of those specifiers.
///
/// These assumptions are backed up by `libc::types::os::arch::posix88::pid_t`, which declares PIDs
/// to be signed 32 bit integers. `proc(5)` declares that PIDs use the `%d` format specifier.
///
/// - `%d` / `%u` - 32 bit signed and unsigned integers
/// - `%ld` / `%lu` - 64 bit signed and unsigned integers
/// - `%llu` - 128 bit unsigned integers
///
/// ### CPU time fields and clock ticks
///
/// The CPU time fields are very strange. Inside the Linux kernel they each use the same type
/// ([array.c:361]) but when printed use different types ([array.c:456]) - the fields `utime`,
/// `stime` and `gtime` are unsigned integers, whereas `cutime`, `cstime` and `cgtime` are signed
/// integers.
///
/// These values are all returned as a number of clock ticks, which can be divided by
/// `sysconf(_SC_CLK_TCK)` to get a value in seconds. The `Process` struct does this conversion
/// automatically, and all CPU time fields use the `f64` type. A corresponding `_ticks` field  (e.g.
/// `utime_ticks` gives the raw number of ticks as found in `/proc`.
///
/// # Unmaintained fields
///
/// The `itrealvalue` [20], `nswap` [35] and `cnswap` [36] fields are not maintained, and in some
/// cases are hardcoded to 0 in the kernel. The `signal` [30], `blocked` [31], `sigignore` [32] and
/// `sigcatch` [33] fields are included as private fields, but `proc(5)` recommends the use of
/// `/proc/[pid]/status` instead.
///
/// # Examples
///
/// ```
/// psutil::process::Process::new(std::process::id() as i32).unwrap();
/// ```
///
/// [array.c:361]: https://github.com/torvalds/linux/blob/master/fs/proc/array.c#L361
/// [array.c:456]: https://github.com/torvalds/linux/blob/master/fs/proc/array.c#L456
/// [proc(5)]: http://man7.org/linux/man-pages/man5/proc.5.html
/// [rfc521]: https://github.com/rust-lang/rfcs/issues/521
#[derive(Clone, Debug)]
pub struct Process {
    /// PID of the process.
    pub pid: PID,

    /// UID of the process.
    pub uid: UID,

    /// UID of the process.
    pub gid: GID,

    /// Filename of the executable.
    pub comm: String,

    /// State of the process as an enum.
    pub state: State,

    /// PID of the parent process.
    pub ppid: PID,

    /// Process group ID.
    pub pgrp: i32,

    /// Session ID.
    pub session: i32,

    /// Controlling terminal of the process [TODO: Actually two numbers].
    pub tty_nr: i32,

    /// ID of the foreground group of the controlling terminal.
    pub tpgid: i32,

    /// Kernel flags for the process.
    pub flags: u32,

    /// Minor faults.
    pub minflt: u64,

    /// Minor faults by child processes.
    pub cminflt: u64,

    /// Major faults.
    pub majflt: u64,

    /// Major faults by child processes.
    pub cmajflt: u64,

    /// Time scheduled in user mode (seconds).
    pub utime: f64,

    /// Time scheduled in user mode (ticks).
    pub utime_ticks: u64,

    /// Time scheduled in kernel mode (seconds).
    pub stime: f64,

    /// Time scheduled in kernel mode (ticks).
    pub stime_ticks: u64,

    /// Time waited-for child processes were scheduled in user mode (seconds).
    pub cutime: f64,

    /// Time waited-for child processes were scheduled in user mode (ticks).
    pub cutime_ticks: i64,

    /// Time waited-for child processes were scheduled in kernel mode (seconds).
    pub cstime: f64,

    /// Time waited-for child processes were scheduled in kernel mode (ticks).
    pub cstime_ticks: i64,

    /// Priority value (-100..-2 | 0..39).
    pub priority: i64,

    /// Nice value (-20..19).
    pub nice: i64,

    /// Number of threads in the process.
    pub num_threads: i64,

    // Unmaintained field since linux 2.6.17, always 0.
    // itrealvalue: i64,
    /// Time the process was started after system boot (seconds).
    pub starttime: f64,

    /// Time the process was started after system boot (ticks).
    pub starttime_ticks: u128,

    /// Virtual memory size in bytes.
    pub vsize: u64,

    /// Resident Set Size (bytes).
    pub rss: i64,

    /// Current soft limit on process RSS (bytes).
    pub rsslim: u64,

    // These values are memory addresses
    startcode: u64,
    endcode: u64,
    startstack: u64,
    kstkesp: u64,
    kstkeip: u64,

    // Signal bitmaps.
    // These are obsolete, use `/proc/[pid]/status` instead.
    signal: u64,
    blocked: u64,
    sigignore: u64,
    sigcatch: u64,

    /// Channel the process is waiting on (address of a system call).
    pub wchan: u64,

    // Number of pages swapped (not maintained).
    // pub nswap: u64,
    //
    // Number of pages swapped for child processes (not maintained).
    // pub cnswap: u64,
    /// Signal sent to parent when process dies.
    pub exit_signal: i32,

    /// Number of the CPU the process was last executed on.
    pub processor: i32,

    /// Real-time scheduling priority (0 | 1..99).
    pub rt_priority: u32,

    /// Scheduling policy.
    pub policy: u32,

    /// Aggregated block I/O delays (seconds).
    pub delayacct_blkio: f64,

    /// Aggregated block I/O delays (ticks).
    pub delayacct_blkio_ticks: u128,

    /// Guest time of the process (seconds).
    pub guest_time: f64,

    /// Guest time of the process (ticks).
    pub guest_time_ticks: u64,

    /// Guest time of the process's children (seconds).
    pub cguest_time: f64,

    /// Guest time of the process's children (ticks).
    pub cguest_time_ticks: i64,

    // More memory addresses.
    start_data: u64,
    end_data: u64,
    start_brk: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,

    /// The thread's exit status.
    pub exit_code: i32,

    pub connections: Option<Connections>, //TODO: remove pub
}

impl Process {
    /// Attempts to read process information from `/proc/[pid]/stat`.
    ///
    /// Some additional metadata is read from the permissions on the `/proc/[pid]/`, which defines
    /// the process UID/GID. The format of `/proc/[pid]/stat` format is defined in proc(5).
    pub fn new(pid: PID) -> Result<Process> {
        let path = procfs_path(pid, "stat");
        let stat = fs::read_to_string(&path)?;
        let meta = fs::metadata(procfs_path(pid, ""))?;
        Process::new_internal(&stat, meta.uid(), meta.gid(), &path)
        
    }

    fn new_internal<P>(stat: &str, file_uid: UID, file_gid: GID, path: P) -> Result<Process>
    where
        P: AsRef<Path>,
    {
        // Read the PID and comm fields separately, as the comm field is delimited by brackets and
        // could contain spaces.
        let (pid_, rest) = match stat.find('(') {
            Some(i) => stat.split_at(i - 1),
            None => return Err(parse_error("Could not parse comm", path)),
        };
        let (comm, rest) = match rest.rfind(')') {
            Some(i) => rest.split_at(i + 2),
            None => return Err(parse_error("Could not parse comm", path)),
        };

        // Split the rest of the fields on the space character and read them into a vector.
        let mut fields: Vec<&str> = Vec::new();
        fields.push(pid_);
        fields.push(&comm[2..comm.len() - 2]);
        fields.extend(rest.trim_end().split(' '));

        // Check we haven't read more or less fields than expected.
        if fields.len() != 52 {
            return Err(parse_error(
                &format!("Expected 52 fields, got {}", fields.len()),
                path,
            ));
        }

        // Read each field into an attribute for a new Process instance
        let mut proc = Process {
            pid: try_parse!(fields[00]),
            uid: file_uid,
            gid: file_gid,
            comm: try_parse!(fields[1]),
            state: try_parse!(fields[2]),
            ppid: try_parse!(fields[3]),
            pgrp: try_parse!(fields[4]),
            session: try_parse!(fields[5]),
            tty_nr: try_parse!(fields[6]),
            tpgid: try_parse!(fields[7]),
            flags: try_parse!(fields[8]),
            minflt: try_parse!(fields[9]),
            cminflt: try_parse!(fields[10]),
            majflt: try_parse!(fields[11]),
            cmajflt: try_parse!(fields[12]),
            utime: try_parse!(fields[13], u64::from_str) as f64 / *TICKS_PER_SECOND,
            utime_ticks: try_parse!(fields[13], u64::from_str),
            stime: try_parse!(fields[14], u64::from_str) as f64 / *TICKS_PER_SECOND,
            stime_ticks: try_parse!(fields[14], u64::from_str),
            cutime: try_parse!(fields[15], i64::from_str) as f64 / *TICKS_PER_SECOND,
            cutime_ticks: try_parse!(fields[15], i64::from_str),
            cstime: try_parse!(fields[16], i64::from_str) as f64 / *TICKS_PER_SECOND,
            cstime_ticks: try_parse!(fields[16], i64::from_str),
            priority: try_parse!(fields[17]),
            nice: try_parse!(fields[18]),
            num_threads: try_parse!(fields[19]),
            // itrealvalue: try_parse!(fields[20]),
            starttime: try_parse!(fields[21], u64::from_str) as f64 / *TICKS_PER_SECOND,
            starttime_ticks: try_parse!(fields[21]),
            vsize: try_parse!(fields[22]),
            rss: try_parse!(fields[23], i64::from_str) * *PAGE_SIZE as i64,
            rsslim: try_parse!(fields[24]),
            startcode: try_parse!(fields[25]),
            endcode: try_parse!(fields[26]),
            startstack: try_parse!(fields[27]),
            kstkesp: try_parse!(fields[28]),
            kstkeip: try_parse!(fields[29]),
            signal: try_parse!(fields[30]),
            blocked: try_parse!(fields[31]),
            sigignore: try_parse!(fields[32]),
            sigcatch: try_parse!(fields[33]),
            wchan: try_parse!(fields[34]),
            // nswap: try_parse!(fields[35]),
            // cnswap: try_parse!(fields[36]),
            exit_signal: try_parse!(fields[37]),
            processor: try_parse!(fields[38]),
            rt_priority: try_parse!(fields[39]),
            policy: try_parse!(fields[40]),
            delayacct_blkio: try_parse!(fields[41], u64::from_str) as f64 / *TICKS_PER_SECOND,
            delayacct_blkio_ticks: try_parse!(fields[41]),
            guest_time: try_parse!(fields[42], u64::from_str) as f64 / *TICKS_PER_SECOND,
            guest_time_ticks: try_parse!(fields[42], u64::from_str),
            cguest_time: try_parse!(fields[43], i64::from_str) as f64 / *TICKS_PER_SECOND,
            cguest_time_ticks: try_parse!(fields[43], i64::from_str),
            start_data: try_parse!(fields[44]),
            end_data: try_parse!(fields[45]),
            start_brk: try_parse!(fields[46]),
            arg_start: try_parse!(fields[47]),
            arg_end: try_parse!(fields[48]),
            env_start: try_parse!(fields[49]),
            env_end: try_parse!(fields[50]),
            exit_code: try_parse!(fields[51]),
            connections: None,
        };

        println!("Creating process from new internal: {:p}", &proc);
        proc.connections = Some(Connections::new(&proc as *const Process));
   
//        let _pid = unsafe{(*(proc.clone().connections.unwrap().process)).pid};
//        println!("BLAAAH {}", _pid);
    
        Ok(proc)
    }

    /// Return `true` if the process was alive at the time it was read.
    pub fn is_alive(&self) -> bool {
        match self.state {
            State::Zombie => false,
            _ => true,
        }
    }

    /// Read `/proc/[pid]/cmdline` as a vector.
    ///
    /// Returns `Err` if `/proc/[pid]/cmdline` is empty.
    pub fn cmdline_vec(&self) -> Result<Option<Vec<String>>> {
        let cmdline = fs::read_to_string(&procfs_path(self.pid, "cmdline"))?;

        if cmdline.is_empty() {
            return Ok(None);
        }
        // Split terminator skips empty trailing substrings.
        let split = cmdline.split_terminator(|c: char| c == '\0' || c == ' ');

        // `split` returns a vector of slices viewing `cmdline`, so they
        // get mapped to actual strings before being returned as a vector.
        Ok(Some(split.map(|x| x.to_string()).collect()))
    }

    /// Return the result of `cmdline_vec` as a String.
    pub fn cmdline(&self) -> Result<Option<String>> {
        Ok(self.cmdline_vec()?.and_then(|c| Some(c.join(" "))))
    }

    /// Read the path of the process' current working directory.
    pub fn cwd(&self) -> Result<PathBuf> {
        read_link(procfs_path(self.pid, "cwd"))
    }

    /// Read the absolute path of the process
    pub fn exe(&self) -> Result<PathBuf> {
        read_link(procfs_path(self.pid, "exe"))
    }

    fn environ_internal(file_contents: &str) -> Result<HashMap<String, String>> {
        let mut ret = HashMap::new();
        for s in file_contents.split_terminator('\0') {
            let vv: Vec<&str> = s.splitn(2, '=').collect();
            if vv.len() != 2 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Item {} has too few fields", s),
                ));
            }
            ret.insert(vv[0].to_owned(), vv[1].to_owned());
        }

        Ok(ret)
    }

    pub fn environ(&self) -> Result<HashMap<String, String>> {
        let path = procfs_path(self.pid, "environ");
        let env = fs::read_to_string(&path)?;
        Process::environ_internal(&env)
    }

    /// Reads `/proc/[pid]/statm` into a struct.
    pub fn memory(&self) -> Result<Memory> {
        Memory::new(self.pid)
    }

    fn get_fd(path: &PathBuf) -> Result<Fd> {
        let mut link_dest: [u8; 4096] = [0; 4096]; //TODO: 4096 is the largest path size in linux. Where is it defined to that it wan't be a magic number
        let mut n_read: isize;

        unsafe {
            n_read = readlink(path.to_str().unwrap().as_ptr() as *const c_char, link_dest.as_mut_ptr() as *mut c_char, 4096);
            println!("----------------------{}", n_read);
            println!("++{}", std::str::from_utf8(&link_dest).unwrap());
        }

        if n_read <= 0 {
            Err(parse_error("Could not parse fd", path))
        } else {
            let fd_number = path
                .file_name()
                .ok_or(parse_error("Could not parse path in /proc entry", &path))?
                .to_str()
                .ok_or(parse_error("Could not parse path in /proc entry", &path))?
                .parse::<i32>().map_err(|e| parse_error(&format!("Could not convert fd number to i32 in /proc entry: {}", e), &path))?;
            
            let link_dest_str = std::str::from_utf8(&link_dest[..n_read as usize])
                .map_err(|e| parse_error(&format!("Could not parse link destination of fd: {}", e), &path))?
                .to_string();
            
            // For now just look at sockets and open files
            if link_dest_str.starts_with("socket:[") { 
                // Socket
                println!("SOCKET FOUND {}", link_dest_str);

                let fd = match link_dest_str.rfind(']') {
                    Some(i) => { Fd { number: fd_number, link: FdType::Socket(try_parse!(&link_dest_str[8..i], u64::from_str)) } },
                    None => return Err(parse_error("Could not parse fd", path)),
                };

                return Ok(fd);
            }

            let link_dest_pathbuf = PathBuf::from(link_dest_str);
            if link_dest_pathbuf.has_root() {
                // File
                return Ok(Fd { number: fd_number, link: FdType::File(link_dest_pathbuf) });
            }

            Err(parse_error("Could not parse fd since it's currently unsupported.", path))
        }
    }

    /// Reads `/proc/[pid]/fd` directory
    pub fn open_fds(&self) -> Result<Vec<Fd>> {
        let mut fds = Vec::new();
        let entry_set = read_dir(procfs_path(self.pid, "fd"))?;

        println!("pid: {}", self.pid);
        for entry in entry_set {
            if let Ok(entry) = entry {
                let path = entry.path();
                let fd_number = path
                    .file_name()
                    .ok_or_else(|| parse_error("Could not read /proc entry", &path))?;
                if let Ok(fd) = Process::get_fd(&path) {
                    fds.push(fd);
                }
            }
        }

        Ok(fds)
    }

    /// Send SIGKILL to the process.
    pub fn kill(&self) -> Result<()> {
        match unsafe { kill(self.pid, SIGKILL) } {
            0 => Ok(()),
            -1 => Err(Error::last_os_error()),
            _ => unreachable!(),
        }
    }
}

impl PartialEq for Process {
    // Compares processes using their PID and `starttime` as an identity.
    fn eq(&self, other: &Process) -> bool {
        (self.pid == other.pid) && (self.starttime == other.starttime)
    }
}

/// Return a vector of all processes in `/proc`.
///
/// You may want to retry after a `std::io::ErrorKind::NotFound` error
/// due to a race condition where the contents of `/proc` are read,
/// and then a particular process dies before getting to read its info.
/// See example below.
///
/// ```ignore
/// loop {
///     match psutil::process::all() {
///         Ok(procs) => return Ok(procs),
///         Err(why) => {
///             if why.kind() != std::io::ErrorKind::NotFound {
///                 return Err(why);
///             }
///         }
///     }
/// }
/// ```
pub fn all() -> Result<Vec<Process>> {
    let mut processes = Vec::new();

    for entry in read_dir("/proc")? {
        let path = entry?.path();
        let name = path
            .file_name()
            .ok_or_else(|| parse_error("Could not read /proc entry", &path))?;
        if let Ok(pid) = PID::from_str(&name.to_string_lossy()) {
            let proc = Process::new(pid)?;
            let _pid = unsafe{(*(proc.clone().connections.unwrap().process)).pid};
            println!("MOO {}", _pid);
           
            processes.push(proc);
        }
    }

    Ok(processes)
}

#[derive(Clone, Debug)]
pub struct Connections {
//    """A wrapper on top of /proc/net/* files, retrieving per-process
//    and system-wide open connections (TCP, UDP, UNIX) similarly to
//    "netstat -an".
//
//    Note: in case of UNIX sockets we're only able to determine the
//    local endpoint/path, not the one it's connected to.
//    According to [1] it would be possible but not easily.
//
//    [1] http://serverfault.com/a/417946
//    """
    tmap: HashMap<&'static str, Vec<ConnVariant>>,
    _procfs_path: Option<PathBuf>,
    process: *const Process,
}
        
impl Connections {
    pub fn new(process: *const Process) -> Connections{
        let tcp4 = ConnVariant{file: "tcp", conn_type: AF_INET, family: SOCK_STREAM};
        let tcp6 = ConnVariant{file: "tcp6", conn_type: AF_INET6, family: SOCK_STREAM};
        let udp4 = ConnVariant{file: "udp", conn_type: AF_INET, family: SOCK_DGRAM};
        let udp6 = ConnVariant{file: "udp6", conn_type: AF_INET6, family: SOCK_DGRAM};
        let mut conn = Connections {tmap: HashMap::new(), _procfs_path: None, process: process};
        conn.tmap.insert("all", vec![tcp4, tcp6, udp4, udp6]);
        conn.tmap.insert("tcp", vec![tcp4, tcp6]);
        conn.tmap.insert("tcp4", vec![tcp4]);
        conn.tmap.insert("tcp6", vec![tcp6]);
        conn.tmap.insert("udp4", vec![udp4]);
        conn.tmap.insert("udp6", vec![udp6]);
        conn.tmap.insert("udp", vec![udp4, udp6]);
        conn.tmap.insert("inet", vec![tcp4, tcp6, udp4, udp6]);
        conn.tmap.insert("inet4", vec![tcp4, udp4]);
        conn.tmap.insert("inet6", vec![tcp6, udp6]);

        conn._procfs_path = None;
        conn.process = process;
        println!("Creating connection: {:p}", process);
        //let pid = unsafe{(*conn.process).pid};
//        println!("CONNECTION PID IS {}", pid);

        conn
    }

    fn get_proc_inodes(&self) {
        //inodes = defaultdict(list)
        let inodes: HashMap<PID, i32> = HashMap::new();

        let fds = unsafe {
            (*self.process).open_fds().unwrap() //TODO: Error handling?
        };

        println!("{:?}", fds);

        for fd in fds {
            println!("PATH {:?}", fd.link);
            println!("PATH {:?}", fd.number);

//            let mut link_dest: [u8; 50] = [0; 50];
//            unsafe {
//                
//                let n_read = readlink(fd.path.to_str().unwrap().as_ptr() as *const c_char, link_dest.as_mut_ptr() as *mut c_char, 50);
//                println!("----------------------{}", n_read);
//                println!("++{}", std::str::from_utf8(&link_dest).unwrap());
//            }
            
        }
//        for fd in os.listdir("%s/%s/fd" % (self._procfs_path, pid)):
//            try:
//                inode = readlink("%s/%s/fd/%s" % (self._procfs_path, pid, fd))
//            except OSError as err:
//                # ENOENT == file which is gone in the meantime;
//                # os.stat('/proc/%s' % self.pid) will be done later
//                # to force NSP (if it's the case)
//                if err.errno in (errno.ENOENT, errno.ESRCH):
//                    continue
//                elif err.errno == errno.EINVAL:
//                    # not a link
//                    continue
//                else:
//                    raise
//            else:
//                if inode.startswith('socket:['):
//                    # the process is using a socket
//                    inode = inode[8:][:-1]
//                    inodes[inode].append((pid, int(fd)))
//        return inodes
    }
//
//    def get_all_inodes(self):
//        inodes = {}
//        for pid in pids():
//            try:
//                inodes.update(self.get_proc_inodes(pid))
//            except OSError as err:
//                # os.listdir() is gonna raise a lot of access denied
//                # exceptions in case of unprivileged user; that's fine
//                # as we'll just end up returning a connection with PID
//                # and fd set to None anyway.
//                # Both netstat -an and lsof does the same so it's
//                # unlikely we can do any better.
//                # ENOENT just means a PID disappeared on us.
//                if err.errno not in (
//                        errno.ENOENT, errno.ESRCH, errno.EPERM, errno.EACCES):
//                    raise
//        return inodes
//
//    @staticmethod
//    def decode_address(addr, family):
//        """Accept an "ip:port" address as displayed in /proc/net/*
//        and convert it into a human readable form, like:
//
//        "0500000A:0016" -> ("10.0.0.5", 22)
//        "0000000000000000FFFF00000100007F:9E49" -> ("::ffff:127.0.0.1", 40521)
//
//        The IP address portion is a little or big endian four-byte
//        hexadecimal number; that is, the least significant byte is listed
//        first, so we need to reverse the order of the bytes to convert it
//        to an IP address.
//        The port is represented as a two-byte hexadecimal number.
//
//        Reference:
//        http://linuxdevcenter.com/pub/a/linux/2000/11/16/LinuxAdmin.html
//        """
//        ip, port = addr.split(':')
//        port = int(port, 16)
//        # this usually refers to a local socket in listen mode with
//        # no end-points connected
//        if not port:
//            return ()
//        if PY3:
//            ip = ip.encode('ascii')
//        if family == socket.AF_INET:
//            # see: https://github.com/giampaolo/psutil/issues/201
//            if LITTLE_ENDIAN:
//                ip = socket.inet_ntop(family, base64.b16decode(ip)[::-1])
//            else:
//                ip = socket.inet_ntop(family, base64.b16decode(ip))
//        else:  # IPv6
//            # old version - let's keep it, just in case...
//            # ip = ip.decode('hex')
//            # return socket.inet_ntop(socket.AF_INET6,
//            #          ''.join(ip[i:i+4][::-1] for i in xrange(0, 16, 4)))
//            ip = base64.b16decode(ip)
//            try:
//                # see: https://github.com/giampaolo/psutil/issues/201
//                if LITTLE_ENDIAN:
//                    ip = socket.inet_ntop(
//                        socket.AF_INET6,
//                        struct.pack('>4I', *struct.unpack('<4I', ip)))
//                else:
//                    ip = socket.inet_ntop(
//                        socket.AF_INET6,
//                        struct.pack('<4I', *struct.unpack('<4I', ip)))
//            except ValueError:
//                # see: https://github.com/giampaolo/psutil/issues/623
//                if not supports_ipv6():
//                    raise _Ipv6UnsupportedError
//                else:
//                    raise
//        return _common.addr(ip, port)
//
//    @staticmethod
    fn process_inet(&self, conn_variant: &ConnVariant, sockets: &Vec<&Fd>, pid: PID) -> Result<()> {
        // Parse /proc/net/tcp* and /proc/net/udp* files.
        let mut path = procfs_path(pid, "net");
        path.push(conn_variant.file);

        if path.to_str().ok_or(Error::new(ErrorKind::InvalidData,
                format!("Unable to parse file name {}", path.display())))?.ends_with('6') && !path.as_path().exists() {
            // IPv6 not supported
            return Ok(());
        }

//        let env = fs::read_to_string(&path)?;
        println!("opening file {}", path.display());
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            println!("{}", line?);
        }

//        with open_text(file, buffering=BIGFILE_BUFFERING) as f:
//            f.readline()  # skip the first line
//            for lineno, line in enumerate(f, 1):
//                try:
//                    _, laddr, raddr, status, _, _, _, _, _, inode = \
//                        line.split()[:10]
//                except ValueError:
//                    raise RuntimeError(
//                        "error while parsing %s; malformed line %s %r" % (
//                            file, lineno, line))
//                if inode in inodes:
//                    # # We assume inet sockets are unique, so we error
//                    # # out if there are multiple references to the
//                    # # same inode. We won't do this for UNIX sockets.
//                    # if len(inodes[inode]) > 1 and family != socket.AF_UNIX:
//                    #     raise ValueError("ambiguos inode with multiple "
//                    #                      "PIDs references")
//                    pid, fd = inodes[inode][0]
//                else:
//                    pid, fd = None, -1
//                if filter_pid is not None and filter_pid != pid:
//                    continue
//                else:
//                    if type_ == socket.SOCK_STREAM:
//                        status = TCP_STATUSES[status]
//                    else:
//                        status = _common.CONN_NONE
//                    try:
//                        laddr = Connections.decode_address(laddr, family)
//                        raddr = Connections.decode_address(raddr, family)
//                    except _Ipv6UnsupportedError:
//                        continue
//                    yield (fd, family, type_, laddr, raddr, status, pid)
        Ok(())
    }
//
//    @staticmethod
//    def process_unix(file, family, inodes, filter_pid=None):
//        """Parse /proc/net/unix files."""
//        with open_text(file, buffering=BIGFILE_BUFFERING) as f:
//            f.readline()  # skip the first line
//            for line in f:
//                tokens = line.split()
//                try:
//                    _, _, _, _, type_, _, inode = tokens[0:7]
//                except ValueError:
//                    if ' ' not in line:
//                        # see: https://github.com/giampaolo/psutil/issues/766
//                        continue
//                    raise RuntimeError(
//                        "error while parsing %s; malformed line %r" % (
//                            file, line))
//                if inode in inodes:
//                    # With UNIX sockets we can have a single inode
//                    # referencing many file descriptors.
//                    pairs = inodes[inode]
//                else:
//                    pairs = [(None, -1)]
//                for pid, fd in pairs:
//                    if filter_pid is not None and filter_pid != pid:
//                        continue
//                    else:
//                        if len(tokens) == 8:
//                            path = tokens[-1]
//                        else:
//                            path = ""
//                        type_ = int(type_)
//                        # XXX: determining the remote endpoint of a
//                        # UNIX socket on Linux is not possible, see:
//                        # https://serverfault.com/questions/252723/
//                        raddr = ""
//                        status = _common.CONN_NONE
//                        yield (fd, family, type_, path, raddr, status, pid)
//
    fn retrieve(&self, kind: &'static str) -> Result<Vec<String>> {
        let variants: &Vec<ConnVariant> =  self.tmap.get(kind).ok_or(Error::new(
                ErrorKind::InvalidInput,
                format!("Unsupported kind of connection: {}", kind)))?;

//        self._procfs_path = get_procfs_path()
        
        let (pid, fds) = unsafe {
            println!("{:p}", self.process);
            ((*self.process).pid, (*self.process).open_fds()?)
        };

        println!("Retrieving for pid {}", pid);
        let sockets: Vec<&Fd> = fds.iter().filter(|x| {
            if let FdType::Socket(_) = x.link {
                true
            } else {
                false
            }
        }).collect();

        if sockets.len() == 0 {
            // no connections for this process
            return Ok(vec![]);
        }

//        ret = set()
        for &conn_variant in variants {
            println!("CONN VARIANT: {:?}", conn_variant);
            match conn_variant.family{
                AF_INET | AF_INET6 => {
                    self.process_inet(&conn_variant, &sockets, pid);
                }
                _ => ()
            }
        }
//                ls = self.process_inet(
//                    "%s/net/%s" % (self._procfs_path, f),
//                    family, type_, inodes, filter_pid=pid)
//            else:
//                ls = self.process_unix(
//                    "%s/net/%s" % (self._procfs_path, f),
//                    family, inodes, filter_pid=pid)
//            for fd, family, type_, laddr, raddr, status, bound_pid in ls:
//                if pid:
//                    conn = _common.pconn(fd, family, type_, laddr, raddr,
//                                         status)
//                else:
//                    conn = _common.sconn(fd, family, type_, laddr, raddr,
//                                         status, bound_pid)
//                ret.add(conn)
//        return list(ret)
        Ok(vec![])

    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn stat_52_fields() {
        let file_contents = "1 (init) S 0 1 1 0 -1 4219136 48162 38210015093 1033 16767427 1781 2205 119189638 18012864 20 0 1 0 9 34451456 504 18446744073709551615 1 1 0 0 0 0 0 4096 536962595 0 0 0 17 0 0 0 189 0 0 0 0 0 0 0 0 0 0\n";
        let p =
            Process::new_internal(&file_contents, 0, 0, &PathBuf::from("/proc/1/stat")).unwrap();
        assert_eq!(p.pid, 1);
        assert_eq!(p.comm, "init");
        assert_eq!(p.utime, 17.81);
    }

    #[test]
    fn starttime_in_seconds_and_ticks() {
        let file_contents = "1 (init) S 0 1 1 0 -1 4219136 48162 38210015093 1033 16767427 1781 2205 119189638 18012864 20 0 1 0 9 34451456 504 18446744073709551615 1 1 0 0 0 0 0 4096 536962595 0 0 0 17 0 0 0 189 0 0 0 0 0 0 0 0 0 0\n";
        let p =
            Process::new_internal(&file_contents, 0, 0, &PathBuf::from("/proc/1/stat")).unwrap();

        // This field should be in seconds
        if *TICKS_PER_SECOND == 100.0 {
            assert_eq!(p.starttime, 0.09);
        } else if *TICKS_PER_SECOND == 1000.0 {
            assert_eq!(p.starttime, 0.009);
        }
        assert_eq!((p.starttime * *TICKS_PER_SECOND) as u64, 9);

        // This field should be in clock ticks, i.e. the raw value from the file
        assert_eq!(p.starttime_ticks, 9);
    }

    #[test]
    fn environ() {
        let fc = "HOME=/\0init=/sbin/init\0recovery=\0TERM=linux\0BOOT_IMAGE=/boot/vmlinuz-3.13.0-128-generic\0PATH=/sbin:/usr/sbin:/bin:/usr/bin\0PWD=/\0rootmnt=/root\0";
        let e = Process::environ_internal(fc).unwrap();
        assert_eq!(e["HOME"], "/");
        assert_eq!(e["rootmnt"], "/root");
        assert_eq!(e["recovery"], "");
    }

    fn get_process() -> Process {
        Process::new(std::process::id() as i32).unwrap()
    }

    #[test]
    fn process_alive() {
        assert!(get_process().is_alive());
    }

    #[test]
    fn process_cpu() {
        let process = get_process();
        assert!(process.utime >= 0.0);
        assert!(process.stime >= 0.0);
        assert!(process.cutime >= 0.0);
        assert!(process.cstime >= 0.0);
    }

    #[test]
    fn process_cmdline() {
        assert!(get_process().cmdline().is_ok());
    }

    #[test]
    fn process_cwd() {
        assert!(get_process().cwd().is_ok());
    }

    #[test]
    fn process_exe() {
        assert!(get_process().exe().is_ok());
    }

    #[test]
    fn process_memory() {
        get_process().memory().unwrap();
    }

    #[test]
    fn process_equality() {
        assert_eq!(get_process(), get_process());
    }

    /// This could fail if you run the tests as PID 1. Please don't do that.
    #[test]
    fn process_inequality() {
        assert!(get_process() != Process::new(1).unwrap());
    }

    #[test]
    fn all() {
        super::all().unwrap();
    }

    #[test]
    fn get_proc_inodes() {
        for p in &super::all().unwrap() {
            print!("{}\t ", p.pid);
        //    p.clone().connections.unwrap().get_proc_inodes();
//            let fd = p.open_fds();
            
            p.connections.clone().unwrap().retrieve("tcp");
//            println!("fd is {:?}", fd);
        }
//        println!("{:?}", get_process().connections.unwrap().get_proc_inodes());
    }

}
