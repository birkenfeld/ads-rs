//! Reproduces the functionality of "adstool" from the Beckhoff ADS C++ library.

use std::convert::TryInto;
use std::io::{stdin, stdout, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use byteorder::{ByteOrder, WriteBytesExt, BE, LE};
use chrono::{DateTime, Utc};
use clap::{AppSettings, ArgGroup, Args, Parser, Subcommand};
use itertools::Itertools;
use parse_int::parse;
use quick_xml::{events::Event, name::QName};
use strum::EnumString;

#[derive(Parser, Debug)]
#[clap(disable_help_subcommand = true)]
#[clap(global_setting = AppSettings::DeriveDisplayOrder)]
/// A utility for managing ADS servers.
struct Cli {
    #[clap(subcommand)]
    cmd: Cmd,

    /// Attempt to automatically create a temporary route on the remote machine if the initial
    /// connection fails
    #[clap(short, long)]
    autoroute: bool,

    /// Sets the ADS client's timeouts. Defaults to 1 sec.
    #[clap(short, long, default_value_t = 1)]
    timeout: u64,

    #[clap(flatten)]
    credentials: CredentialArgs,

    /// Target for the command.
    ///
    /// This can be `hostname[:port]` or include an AMS address using
    /// `hostname[:port]/netid[:amsport]`, for example:
    ///
    /// localhost/5.23.91.23.1.1:851
    ///
    /// The IP port defaults to 0xBF02 (TCP) and 0xBF03 (UDP).
    ///
    /// An AMS address is required for all subcommands except `addroute` and
    /// `info`.  If it's not present, it is queried via UDP from the given
    /// hostname, but only the connected router (normally `.1.1`) can be reached
    /// in that way.
    ///
    /// The default AMS port depends on the command: `file` and `state` default
    /// to the system service, `license` to the license service, while `raw and
    /// `var` default to the first PLC instance (port 851).
    target: Target,
}

impl Cli {
    pub fn credentials(&self) -> (Option<&'_ str>, Option<&'_ str>) {
        let username = self.credentials.username.as_deref();
        let password = self.credentials.password.as_deref();

        (username, password)
    }

    pub const fn timeout(&self) -> ads::Timeouts {
        ads::Timeouts { connect: Some(Duration::from_secs(self.timeout)), ..ads::Timeouts::none() }
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Query basic information about the system over UDP.
    Info,
    /// Query extended information about the system over ADS.
    TargetDesc,
    #[clap(subcommand)]
    Route(RouteAction),
    #[clap(subcommand)]
    File(FileAction),
    #[clap(subcommand)]
    License(LicenseAction),
    State(StateArgs),
    #[clap(subcommand)]
    Raw(RawAction),
    #[clap(subcommand)]
    Var(VarAction),
    Exec(ExecArgs),
}

#[derive(Subcommand, Debug)]
/// Manipulate ADS routes.
enum RouteAction {
    /// Add an ADS route to the remote TwinCAT system.
    Add(AddRouteArgs),
    /// Query and display the list of ADS routes on the system.
    List,
}

#[derive(Debug, Args, Clone)]
struct CredentialArgs {
    /// username for logging into the system (defaults to `Administrator`)
    #[clap(long)]
    username: Option<String>,

    /// password for logging into the system (defaults to `1`)
    #[clap(long)]
    password: Option<String>,
}

#[derive(Parser, Debug)]
struct AddRouteArgs {
    /// hostname or IP address of the route's destionation
    addr: String,

    /// AMS NetId of the route's destination
    netid: ads::AmsNetId,

    /// name of the new route (defaults to `addr`)
    #[clap(long)]
    routename: Option<String>,

    /// mark route as temporary?
    #[clap(long)]
    temporary: bool,
}

#[derive(Subcommand, Debug)]
/// Execute operations on files on the TwinCAT system.
enum FileAction {
    /// List remote files in the given directory.
    List {
        /// the directory path
        path: String,
    },
    /// Read a remote file and write its contents to stdout.
    Read {
        /// the file path
        path: String,
    },
    /// Write a remote file with content from stdin.
    Write {
        /// the file path
        path: String,
        /// whether to append to the file when writing
        #[clap(long)]
        append: bool,
    },
    /// Delete a remote file.
    Delete {
        /// the file path
        path: String,
    },
}

#[derive(Subcommand, Debug)]
/// Query different license ids.
enum LicenseAction {
    /// Get the platform ID
    Platformid,
    /// Get the system ID
    Systemid,
    /// Get the volume number
    Volumeno,
    /// Get the individual module license GUIDs and their activation status
    Modules,
}

#[derive(Parser, Debug)]
/// Read or write the ADS state of the device.
struct StateArgs {
    /// if given, the target state
    ///
    /// Note that state transitions are not always straightforward;
    /// for example, you need to set `Reset` to go from `Config` to `Run`,
    /// and `Reconfig` to go from `Run` to `Config`.
    target_state: Option<ads::AdsState>,
}

#[derive(Subcommand, Debug)]
/// Raw read or write access for an indexgroup.
enum RawAction {
    /// Read some data from an index.  Specify either --length (to print raw
    /// bytes) or --type (to convert to a data type and print that).
    #[clap(group = ArgGroup::with_name("spec").required(true))]
    Read {
        /// the index group, can be 0xABCD
        #[clap(parse(try_from_str = parse))]
        index_group: u32,
        /// the index offset, can be 0xABCD
        #[clap(parse(try_from_str = parse))]
        index_offset: u32,
        /// the length, can be 0xABCD
        #[clap(long, parse(try_from_str = parse), group = "spec")]
        length: Option<usize>,
        /// the data type
        #[clap(long, group = "spec")]
        r#type: Option<VarType>,
        /// whether to print integers as hex, or raw data as hexdump
        #[clap(long)]
        hex: bool,
    },

    /// Write some data to an index.  Data is read from stdin.
    Write {
        /// the index group, can be 0xABCD
        #[clap(parse(try_from_str = parse))]
        index_group: u32,
        /// the index offset, can be 0xABCD
        #[clap(parse(try_from_str = parse))]
        index_offset: u32,
    },

    /// Write some data (read from stdin), then read data from an index.
    #[clap(group = ArgGroup::with_name("spec").required(true))]
    WriteRead {
        /// the index group, can be 0xABCD
        #[clap(parse(try_from_str = parse))]
        index_group: u32,
        /// the index offset, can be 0xABCD
        #[clap(parse(try_from_str = parse))]
        index_offset: u32,
        /// the length to read, can be 0xABCD
        #[clap(long, parse(try_from_str = parse), group = "spec")]
        length: Option<usize>,
        /// the data type to interpret the read data as
        #[clap(long, group = "spec")]
        r#type: Option<VarType>,
        /// whether to print integers as hex, or raw data as hexdump
        #[clap(long)]
        hex: bool,
    },
}

#[derive(Subcommand, Debug)]
/// Variable read or write access.
enum VarAction {
    /// List variables together with their types, sizes and offsets.
    List {
        /// a filter for the returned symbol names
        filter: Option<String>,
    },

    /// List type definitions.
    ListTypes {
        /// a filter for the returned symbol names
        filter: Option<String>,
    },

    /// Read a variable by name.
    #[clap(group = ArgGroup::with_name("spec"))]
    Read {
        /// the variable name
        name: String,
        /// the variable type
        #[clap(long, group = "spec")]
        r#type: Option<VarType>,
        /// the length to read, can be 0xABCD
        #[clap(long, parse(try_from_str = parse), group = "spec")]
        length: Option<usize>,
        /// whether to print integers as hex
        #[clap(long)]
        hex: bool,
    },

    /// Write a variable by name.  If --type is given, the new value
    /// is converted from the command line argument.  If not, the new
    /// value is read as raw data from stdin.
    Write {
        /// the variable name
        name: String,
        /// the new value, if given, to write
        #[clap(requires = "type")]
        value: Option<String>,
        /// the variable type
        #[clap(long)]
        r#type: Option<VarType>,
    },
}

#[derive(Parser, Debug)]
/// Execute a system command on the target.
struct ExecArgs {
    /// the executable with path
    program: String,
    /// the working directory (defaults to the executable's)
    #[clap(long)]
    workingdir: Option<String>,
    /// arguments for the executable
    args: Vec<String>,
}

#[derive(Clone, Copy, Debug, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
// TODO put the type mapping stuff into the lib?
enum VarType {
    Bool,
    Byte,
    Sint,
    Word,
    Int,
    Dword,
    Dint,
    Lword,
    Lint,
    String,
    Real,
    Lreal,
}

impl VarType {
    fn size(&self) -> usize {
        match self {
            VarType::Bool | VarType::Byte | VarType::Sint => 1,
            VarType::Word | VarType::Int => 2,
            VarType::Real | VarType::Dword | VarType::Dint => 4,
            VarType::Lreal | VarType::Lword | VarType::Lint => 8,
            VarType::String => 255,
        }
    }
}

/// Target spec: IP plus optional AMS adress.
#[derive(Debug)]
struct Target {
    host: String,
    port: Option<u16>,
    netid: Option<ads::AmsNetId>,
    amsport: Option<ads::AmsPort>,
}

const RX: &str = "^(?P<host>[^:/]+)(:(?P<port>\\d+))?(/(?P<netid>[0-9.]+)?(:(?P<amsport>\\d+))?)?$";

impl FromStr for Target {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rx = regex::Regex::new(RX).expect("valid regex");
        match rx.captures(s) {
            None => Err("target format is host[:port][/netid[:amsport]]"),
            Some(cap) => Ok(Target {
                host: cap["host"].into(),
                port: cap.name("port").map(|p| p.as_str().parse().expect("from rx")),
                netid: cap.name("netid").map(|p| p.as_str().parse()).transpose()?,
                amsport: cap.name("amsport").map(|p| p.as_str().parse().expect("from rx")),
            }),
        }
    }
}

fn main() {
    let args = Cli::from_args();

    if let Err(e) = main_inner(args) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error(transparent)]
    Lib(#[from] ads::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Str(String),
}

fn connect(port: ads::AmsPort, args: &Cli) -> ads::Result<(ads::Client, ads::AmsAddr)> {
    let target = &args.target;
    let target_netid = match target.netid {
        Some(netid) => netid,
        None => ads::udp::get_netid((target.host.as_str(), ads::UDP_PORT))?,
    };
    let tcp_addr = (target.host.as_str(), target.port.unwrap_or(ads::PORT));
    let amsport = target.amsport.unwrap_or(port);
    let amsaddr = ads::AmsAddr::new(target_netid, amsport);
    let source = if matches!(target.host.as_str(), "127.0.0.1" | "localhost") {
        ads::Source::Request
    } else if args.autoroute {
        // temp. connection to remote to get the corrent IP addr of the interface in use
        let sock = TcpStream::connect(tcp_addr)
            .map_err(|e| ads::Error::Io("attempting to resolve local IP address", e))?;

        let local_ip = sock.local_addr()
            .map(|addr| addr.ip())
            .map_err(|e| ads::Error::Io("attempting to resolve local IP address", e))?;

        // if not using IPv4 address or IPv6 address with IPv4 mapping,
        // create an arbitrary AMS NetID
        let local_net_id = {
            let [a, b, c, d] = match local_ip {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(ip) => ip.to_ipv4().unwrap_or(Ipv4Addr::new(1, 2, 3, 4)).octets()
            };

            ads::AmsNetId::new(a, b, c, d, 1, 1)
        };

        let (username, password) = args.credentials();

        // add the route using the collected IP information and derived AMS NetID
        ads::udp::add_route(
            (target.host.as_str(), ads::UDP_PORT),
            local_net_id,
            &local_ip.to_string(),
            None,
            username,
            password,
            true,
        )?;

        ads::Source::Addr(ads::AmsAddr::new(local_net_id, 58913))
    } else {
        ads::Source::Any
    };

    // timeout here to prevent the remote machine allowing the connection but not responding
    // (probably because of a bad route)
    let client = ads::Client::new(tcp_addr, args.timeout(), source)?;

    Ok((client, amsaddr))
}

fn main_inner(args: Cli) -> Result<(), Error> {
    let udp_addr = (args.target.host.as_str(), args.target.port.unwrap_or(ads::UDP_PORT));
    let (username, password) = args.credentials();

    match &args.cmd {
        Cmd::Route(RouteAction::Add(subargs)) => {
            ads::udp::add_route(
                udp_addr,
                subargs.netid,
                &subargs.addr,
                subargs.routename.as_deref(),
                username,
                password,
                subargs.temporary,
            )?;

            println!("Success.");
        }

        Cmd::Route(RouteAction::List) => {
            let (client, amsaddr) = connect(ads::ports::SYSTEM_SERVICE, &args)?;
            let dev = client.device(amsaddr);
            let mut routeinfo = [0; 2048];
            println!("{:-20} {:-22} {:-18} Flags", "Name", "NetID", "Host IP");
            for subindex in 0.. {
                match dev.read(ads::index::ROUTE_LIST, subindex, &mut routeinfo) {
                    Err(ads::Error::Ads(_, _, 0x716)) => break,
                    Err(other) => return Err(Error::Lib(other)),
                    Ok(n) if n >= 48 => {
                        let netid = ads::AmsNetId::from_slice(&routeinfo[..6]).unwrap();
                        let flags = LE::read_u32(&routeinfo[8..]);
                        let _timeout = LE::read_u32(&routeinfo[12..]);
                        let _max_frag = LE::read_u32(&routeinfo[16..]);
                        let hostlen = LE::read_u32(&routeinfo[32..]) as usize;
                        let namelen = LE::read_u32(&routeinfo[36..]) as usize;
                        let host = String::from_utf8_lossy(&routeinfo[44..][..hostlen - 1]);
                        let name = String::from_utf8_lossy(&routeinfo[44 + hostlen..][..namelen - 1]);
                        print!("{name:-20} {netid:-22} {host:-18}");
                        if flags & 0x01 != 0 {
                            print!(" temporary");
                        }
                        if flags & 0x80 != 0 {
                            print!(" unidirectional");
                        }
                        if flags & 0x100 != 0 {
                            print!(" virtual/nat");
                        }
                        println!();
                    }
                    _ => println!("Route entry {subindex} too short"),
                }
            }
        }

        Cmd::Info => {
            let info = ads::udp::get_info(udp_addr)?;
            println!("NetID: {}", info.netid);
            println!("Hostname: {}", info.hostname);
            println!(
                "TwinCAT version: {}.{}.{}",
                info.twincat_version.0, info.twincat_version.1, info.twincat_version.2
            );
            println!(
                "OS version: {} {}.{}.{} {}",
                info.os_version.0, info.os_version.1, info.os_version.2, info.os_version.3, info.os_version.4
            );
            if !info.fingerprint.is_empty() {
                println!("Fingerprint: {}", info.fingerprint);
            }
        }

        Cmd::TargetDesc => {
            let (client, amsaddr) = connect(ads::ports::SYSTEM_SERVICE, &args)?;
            let dev = client.device(amsaddr);
            let mut xml = [0; 2048];
            dev.read(ads::index::TARGET_DESC, 1, &mut xml)?;
            let mut rdr = quick_xml::Reader::from_reader(&xml[..]);
            rdr.config_mut().trim_text(true);
            let mut stack = Vec::new();
            loop {
                match rdr.read_event() {
                    Ok(Event::Start(el)) => {
                        if el.name() != QName(b"TcTargetDesc") {
                            stack.push(String::from_utf8_lossy(el.name().0).to_string());
                        }
                    }
                    Ok(Event::End(_)) => {
                        let _ = stack.pop();
                    }
                    Ok(Event::Text(t)) => {
                        if !stack.is_empty() {
                            println!("{}: {}", stack.iter().format("."), String::from_utf8_lossy(&t));
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => return Err(Error::Str(format!("error parsing target desc XML: {e}"))),
                    _ => (),
                }
            }
            println!();
            let n = dev.read(ads::index::TARGET_DESC, 4, &mut xml)?;
            println!("Platform: {}", String::from_utf8_lossy(&xml[..n - 1]));
            let n = dev.read(ads::index::TARGET_DESC, 7, &mut xml)?;
            println!("Project name: {}", String::from_utf8_lossy(&xml[..n - 1]));
        }

        Cmd::File(subargs) => {
            use ads::file;
            let (client, amsaddr) = connect(ads::ports::SYSTEM_SERVICE, &args)?;
            let dev = client.device(amsaddr);
            match subargs {
                FileAction::List { path } => {
                    let entries = file::listdir(dev, path)?;
                    for (name, attr, size) in entries {
                        println!(
                            "{} {:8} {}",
                            if attr & file::DIRECTORY != 0 { "D" } else { " " },
                            size,
                            String::from_utf8_lossy(&name)
                        );
                    }
                }

                FileAction::Read { path } => {
                    let mut file = file::File::open(dev, path, file::READ | file::BINARY | file::ENSURE_DIR)?;
                    std::io::copy(&mut file, &mut stdout())?;
                }

                FileAction::Write { path, append } => {
                    let flag = if *append { ads::file::APPEND } else { ads::file::WRITE };
                    let mut file =
                        file::File::open(dev, path, flag | file::BINARY | file::PLUS | file::ENSURE_DIR)?;
                    std::io::copy(&mut stdin(), &mut file)?;
                }

                FileAction::Delete { path } => {
                    file::File::delete(dev, path, file::ENABLE_DIR)?;
                }
            }
        }

        Cmd::State(subargs) => {
            let (client, amsaddr) = connect(ads::ports::SYSTEM_SERVICE, &args)?;
            let dev = client.device(amsaddr);
            let info = dev.get_info()?;
            println!("Device: {} {}.{}.{}", info.name, info.major, info.minor, info.version);
            let (state, dev_state) = dev.get_state()?;
            println!("Current state: {state:?}");
            if let Some(newstate) = subargs.target_state {
                println!("Set new state: {newstate:?}");
                dev.write_control(newstate, dev_state)?;
            }
        }

        Cmd::License(object) => {
            // Connect to the selected target, defaulting to the license server.
            let (client, amsaddr) = connect(ads::ports::LICENSE_SERVER, &args)?;
            let dev = client.device(amsaddr);
            match object {
                LicenseAction::Platformid => {
                    let mut id = [0; 2];
                    dev.read_exact(ads::index::LICENSE, 2, &mut id)?;
                    println!("{}", u16::from_le_bytes(id));
                }

                LicenseAction::Systemid => {
                    let mut id = [0; 16];
                    dev.read_exact(ads::index::LICENSE, 1, &mut id)?;
                    println!("{}", format_guid(&id));
                }

                LicenseAction::Volumeno => {
                    let mut no = [0; 4];
                    dev.read_exact(ads::index::LICENSE, 5, &mut no)?;
                    println!("{}", u32::from_le_bytes(no));
                }

                LicenseAction::Modules => {
                    // Read the number of modules.
                    let mut count = [0; 4];
                    dev.read_exact(ads::index::LICENSE_MODULES, 0, &mut count)?;
                    let nmodules = u32::from_le_bytes(count) as usize;

                    // Read the data (0x30 bytes per module).
                    let mut data = vec![0; 0x30 * nmodules];
                    dev.read_exact(ads::index::LICENSE_MODULES, 0, &mut data)?;

                    // Print the data.
                    for i in 0..nmodules {
                        let guid = &data[0x30 * i..][..0x10];
                        let expires = LE::read_i64(&data[0x30 * i + 0x10..]);
                        let exp_time = convert_filetime(expires);
                        let inst_total = LE::read_u32(&data[0x30 * i + 0x18..]);
                        let inst_used = LE::read_u32(&data[0x30 * i + 0x1c..]);

                        println!("ID: {}", format_guid(guid));
                        if let Some(exp) = exp_time {
                            println!("    Expires: {exp}");
                        }
                        if inst_total != 0 {
                            println!("    Instances used: {inst_used}/{inst_total}");
                        }
                    }
                }
            }
        }

        Cmd::Raw(subargs) => {
            // Connect to the selected target, defaulting to the first PLC instance.
            let (client, amsaddr) = connect(ads::ports::TC3_PLC_SYSTEM1, &args)?;
            let dev = client.device(amsaddr);

            match subargs {
                RawAction::Read { index_group, index_offset, length, r#type, hex } => {
                    if let Some(length) = length {
                        let mut read_data = vec![0; *length];
                        let nread = dev.read(*index_group, *index_offset, &mut read_data)?;
                        if *hex {
                            hexdump(&read_data[..nread]);
                        } else {
                            stdout().write_all(&read_data[..nread])?;
                        }
                    } else if let Some(typ) = r#type {
                        let mut read_data = vec![0; typ.size()];
                        dev.read_exact(*index_group, *index_offset, &mut read_data)?;
                        print_read_value(*typ, &read_data, *hex);
                    }
                }

                RawAction::Write { index_group, index_offset } => {
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;
                    dev.write(*index_group, *index_offset, &write_data)?;
                }

                RawAction::WriteRead { index_group, index_offset, length, r#type, hex } => {
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;

                    if let Some(length) = length {
                        let mut read_data = vec![0; *length];
                        let nread =
                            dev.write_read(*index_group, *index_offset, &write_data, &mut read_data)?;
                        if *hex {
                            hexdump(&read_data[..nread]);
                        } else {
                            stdout().write_all(&read_data[..nread])?;
                        }
                    } else if let Some(typ) = r#type {
                        let mut read_data = vec![0; typ.size()];
                        dev.write_read_exact(*index_group, *index_offset, &write_data, &mut read_data)?;
                        print_read_value(*typ, &read_data, *hex);
                    }
                }
            }
        }

        Cmd::Var(subargs) => {
            // Connect to the selected target, defaulting to the first PLC instance.
            let (client, amsaddr) = connect(ads::ports::TC3_PLC_SYSTEM1, &args)?;
            let dev = client.device(amsaddr);

            fn print_fields(type_map: &ads::symbol::TypeMap, base_offset: u32, typ: &str, level: usize) {
                for field in &type_map[typ].fields {
                    if let Some(offset) = field.offset {
                        let indent = (0..2 * level).map(|_| ' ').collect::<String>();
                        println!(
                            "     {:6x} ({:6x}) {}.{:5$} {}",
                            base_offset + offset,
                            field.size,
                            indent,
                            field.name,
                            field.typ,
                            39 - 2 * level
                        );

                        print_fields(type_map, base_offset + offset, &field.typ, level + 1);
                    }
                }
            }

            match subargs {
                VarAction::List { filter } => {
                    let (symbols, type_map) = ads::symbol::get_symbol_info(dev)?;
                    let filter = filter.as_ref().map(|s| s.as_str()).unwrap_or("").to_lowercase();
                    for sym in symbols {
                        if sym.name.to_lowercase().contains(&filter) {
                            println!(
                                "{:4x}:{:6x} ({:6x}) {:40} {}",
                                sym.ix_group, sym.ix_offset, sym.size, sym.name, sym.typ
                            );
                            print_fields(&type_map, sym.ix_offset, &sym.typ, 1);
                        }
                    }
                }

                VarAction::ListTypes { filter } => {
                    let (_symbols, type_map) = ads::symbol::get_symbol_info(dev)?;
                    let filter = filter.as_ref().map(|s| s.as_str()).unwrap_or("").to_lowercase();
                    for (name, ty) in &type_map {
                        if name.to_lowercase().contains(&filter) {
                            println!("**          ({:6x}) {:40}", ty.size, name);
                            print_fields(&type_map, 0, name, 1);
                        }
                    }
                }

                VarAction::Read { name, r#type, length, hex } => {
                    let handle = ads::symbol::Handle::new(dev, name)?;
                    if let Some(typ) = r#type {
                        let mut read_data = vec![0; typ.size()];
                        handle.read(&mut read_data)?;
                        print_read_value(*typ, &read_data, *hex);
                    } else {
                        let length = match length {
                            Some(l) => *l,
                            None => ads::symbol::get_size(dev, name)?,
                        };
                        let mut read_data = vec![0; length];
                        handle.read(&mut read_data)?;
                        if *hex {
                            hexdump(&read_data);
                        } else {
                            stdout().write_all(&read_data)?;
                        }
                    }
                }

                VarAction::Write { name, value, r#type } => {
                    let handle = ads::symbol::Handle::new(dev, name)?;
                    if let Some(typ) = r#type {
                        let write_data = get_write_value(*typ, value.as_ref().map(|s| s.as_str()).unwrap())?;
                        handle.write(&write_data)?;
                    } else {
                        let mut write_data = Vec::new();
                        stdin().read_to_end(&mut write_data)?;
                        handle.write(&write_data)?;
                    }
                }
            }
        }

        Cmd::Exec(subargs) => {
            let (client, amsaddr) = connect(ads::ports::SYSTEM_SERVICE, &args)?;
            let dev = client.device(amsaddr);

            let workingdir = subargs.workingdir.as_deref().unwrap_or("");
            let args = subargs.args.iter().join(" ");

            let mut data = Vec::new();
            data.write_u32::<LE>(subargs.program.len() as u32).unwrap();
            data.write_u32::<LE>(workingdir.len() as u32).unwrap();
            data.write_u32::<LE>(args.len() as u32).unwrap();
            data.write_all(subargs.program.as_bytes()).unwrap();
            data.write_all(&[0]).unwrap();
            data.write_all(workingdir.as_bytes()).unwrap();
            data.write_all(&[0]).unwrap();
            data.write_all(args.as_bytes()).unwrap();
            data.write_all(&[0]).unwrap();

            dev.write(ads::index::EXECUTE, 0, &data)?;
        }
    }

    Ok(())
}

fn get_write_value(typ: VarType, value: &str) -> Result<Vec<u8>, Error> {
    let err = |_| Error::Str("expected integer".into());
    let float_err = |_| Error::Str("expected floating point number".into());
    Ok(match typ {
        VarType::String => value.as_bytes().to_vec(),
        VarType::Bool => {
            if value == "TRUE" {
                vec![1]
            } else if value == "FALSE" {
                vec![0]
            } else {
                return Err(Error::Str("invalid BOOL value".into()));
            }
        }
        VarType::Byte => parse::<u8>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Sint => parse::<i8>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Word => parse::<u16>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Int => parse::<i16>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Dword => parse::<u32>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Dint => parse::<i32>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Lword => parse::<u64>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Lint => parse::<i64>(value).map_err(err)?.to_le_bytes().into(),
        VarType::Real => value.parse::<f32>().map_err(float_err)?.to_le_bytes().into(),
        VarType::Lreal => value.parse::<f64>().map_err(float_err)?.to_le_bytes().into(),
    })
}

fn print_read_value(typ: VarType, buf: &[u8], hex: bool) {
    let value = match typ {
        VarType::String => {
            println!("{}", String::from_utf8_lossy(buf).split('\0').next().expect("item"));
            return;
        }
        VarType::Bool => {
            match buf[0] {
                0 => println!("FALSE"),
                1 => println!("TRUE"),
                n => println!("non-bool ({n})"),
            }
            return;
        }
        VarType::Real => {
            let v = f32::from_le_bytes(buf[..4].try_into().expect("size"));
            println!("{v}");
            return;
        }
        VarType::Lreal => {
            let v = f64::from_le_bytes(buf[..8].try_into().expect("size"));
            println!("{v}");
            return;
        }
        VarType::Byte => buf[0] as i128,
        VarType::Sint => buf[0] as i8 as i128,
        VarType::Word => u16::from_le_bytes(buf[..2].try_into().expect("size")) as i128,
        VarType::Int => i16::from_le_bytes(buf[..2].try_into().expect("size")) as i128,
        VarType::Dword => u32::from_le_bytes(buf[..4].try_into().expect("size")) as i128,
        VarType::Dint => i32::from_le_bytes(buf[..4].try_into().expect("size")) as i128,
        VarType::Lword => u64::from_le_bytes(buf[..8].try_into().expect("size")) as i128,
        VarType::Lint => i64::from_le_bytes(buf[..8].try_into().expect("size")) as i128,
    };
    // Only reaches here for integer types
    if hex {
        println!("{value:#x}");
    } else {
        println!("{value}");
    }
}

/// If the char is not printable, replace it by a dot.
fn printable(ch: &u8) -> char {
    if *ch >= 32 && *ch <= 127 {
        *ch as char
    } else {
        '.'
    }
}

/// Print a hexdump of a byte slice in the usual format.
fn hexdump(mut data: &[u8]) {
    let mut addr = 0;
    while !data.is_empty() {
        let (line, rest) = data.split_at(data.len().min(16));
        println!(
            "{:#08x}: {:02x}{} | {}",
            addr,
            line.iter().format(" "),
            (0..16 - line.len()).map(|_| "   ").format(""),
            line.iter().map(printable).format("")
        );
        addr += 16;
        data = rest;
    }
    println!();
}

/// Difference between FILETIME and Unix offsets.
const EPOCH_OFFSET: i64 = 11644473600;

/// Convert Windows FILETIME to DateTime
fn convert_filetime(ft: i64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let unix_ts = ft / 10_000_000 - EPOCH_OFFSET;
    DateTime::from_timestamp(unix_ts, 0)
}

/// Format a GUID.
fn format_guid(guid: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:04X}-{:012X}",
        LE::read_u32(guid),
        LE::read_u16(&guid[4..]),
        LE::read_u16(&guid[6..]),
        BE::read_u16(&guid[8..]),
        BE::read_u48(&guid[10..])
    )
}
