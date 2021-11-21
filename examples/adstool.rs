//! Reproduces the functionality of "adstool" from the Beckhoff ADS C++ library.

use std::convert::TryInto;
use std::io::{stdin, stdout, Read, Write};
use std::str::FromStr;

use parse_int::parse;
use structopt::{clap::AppSettings, clap::ArgGroup, StructOpt};
use strum::EnumString;

#[derive(StructOpt, Debug)]
#[structopt(global_setting = AppSettings::UnifiedHelpMessage)]
#[structopt(global_setting = AppSettings::DisableHelpSubcommand)]
#[structopt(global_setting = AppSettings::DeriveDisplayOrder)]
/// A utility for managing ADS servers.
struct Args {
    #[structopt(subcommand)]
    cmd: Cmd,
    /// Target for the command.
    ///
    /// This can be `hostname[:port]` or include an AMS address using
    /// `hostname[:port]/netid[:amsport]`, for example:
    ///
    /// localhost/5.23.91.23.1.1:851
    ///
    /// The IP port defaults to 0xBF02 (TCP) and 0xBF03 (UDP).
    ///
    /// An AMS address is required for `file`, `license`, `state`, `raw` and
    /// `var`.  If it's not present, it is queried via UDP from the given
    /// hostname, but only the connected router (normally `.1.1`) can be reached
    /// in that way.
    ///
    /// The default AMS port depends on the command: `file` and `state` default
    /// to the system service, `license` to the license service, while `raw and
    /// `var` default to the first PLC instance (port 851).
    target: Target,
}

#[derive(StructOpt, Debug)]
enum Cmd {
    Addroute(AddRouteArgs),
    File(FileAction),
    License(LicenseAction),
    Info,
    State(StateArgs),
    Raw(RawAction),
    Var(VarArgs),
}

#[derive(StructOpt, Debug)]
/// Add an ADS route to the remote TwinCAT system.
struct AddRouteArgs {
    /// hostname or IP address of the route's destionation
    addr: String,

    /// AMS NetId of the route's destination
    netid: ads::AmsNetId,

    /// name of the new route (defaults to `addr`)
    #[structopt(long)]
    routename: Option<String>,

    /// password for logging into the system (defaults to `1`)
    #[structopt(long, default_value = "1")]
    password: String,

    /// username for logging into the system (defaults to `Administrator`)
    #[structopt(long, default_value = "Administrator")]
    username: String,

    /// mark route as temporary?
    #[structopt(long)]
    temporary: bool,
}

#[derive(StructOpt, Debug)]
/// Execute operations on files on the TwinCAT system.
enum FileAction {
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
        #[structopt(long)]
        append: bool,
    },
    /// Delete a remote file.
    Delete {
        /// the file path
        path: String,
    },
}

#[derive(StructOpt, Debug)]
/// Query different license ids.
enum LicenseAction {
    /// Get the platform ID
    Platformid,
    /// Get the system ID
    Systemid,
    /// Get the volume number
    Volumeno,
}

#[derive(StructOpt, Debug)]
/// Read or write the ADS state of the device.
struct StateArgs {
    /// if given, the target state
    target_state: Option<ads::AdsState>,
}

#[derive(StructOpt, Debug)]
/// Raw read or write access for an indexgroup.
enum RawAction {
    /// Read some data from an index.  Specify either --length (to print raw
    /// bytes) or --type (to convert to a data type and print that).
    #[structopt(group = ArgGroup::with_name("spec").required(true))]
    Read {
        /// the index group, can be 0xABCD
        #[structopt(parse(try_from_str = parse))]
        index_group: u32,
        /// the index offset, can be 0xABCD
        #[structopt(parse(try_from_str = parse))]
        index_offset: u32,
        /// the length, can be 0xABCD
        #[structopt(long, parse(try_from_str = parse), group = "spec")]
        length: Option<usize>,
        /// the data type
        #[structopt(long, group = "spec")]
        r#type: Option<VarType>,
        /// whether to print integers as hex
        #[structopt(long)]
        hex: bool,
    },
    /// Write some data to an index.  Data is read from stdin.
    Write {
        /// the index group, can be 0xABCD
        #[structopt(parse(try_from_str = parse))]
        index_group: u32,
        /// the index offset, can be 0xABCD
        #[structopt(parse(try_from_str = parse))]
        index_offset: u32,
    },
    /// Write some data (read from stdin), then read data from an index.
    #[structopt(group = ArgGroup::with_name("spec").required(true))]
    WriteRead {
        /// the index group, can be 0xABCD
        #[structopt(parse(try_from_str = parse))]
        index_group: u32,
        /// the index offset, can be 0xABCD
        #[structopt(parse(try_from_str = parse))]
        index_offset: u32,
        /// the length to read, can be 0xABCD
        #[structopt(long, parse(try_from_str = parse), group = "spec")]
        length: Option<usize>,
        /// the data type to interpret the read data as
        #[structopt(long, group = "spec")]
        r#type: Option<VarType>,
        /// whether to print integers as hex
        #[structopt(long)]
        hex: bool,
    },
}

#[derive(StructOpt, Debug)]
/// Variable read or write access.
struct VarArgs {
    /// the variable type
    r#type: VarType,
    /// the variable name
    name: String,
    /// the new value, if given, to write
    value: Option<String>,
    /// whether to print integers as hex
    #[structopt(long)]
    hex: bool,
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
            VarType::Bool |
            VarType::Byte | VarType::Sint   => 1,
            VarType::Word | VarType::Int    => 2,
            VarType::Real |
            VarType::Dword | VarType::Dint  => 4,
            VarType::Lreal |
            VarType::Lword | VarType::Lint  => 8,
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

const RX: &str = "(?P<host>[^:/]+)(:(?P<port>\\d+))?(/(?P<netid>[0-9.]+)(:(?P<amsport>\\d+))?)?$";

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
            })
        }
    }
}

fn main() {
    let args = Args::from_args();

    if let Err(e) = main_inner(args) {
        eprintln!("Error: {}", e);
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

fn main_inner(args: Args) -> Result<(), Error> {
    let target = args.target;
    let tcp_addr = (target.host.as_str(), target.port.unwrap_or(ads::PORT));
    let udp_addr = (target.host.as_str(), target.port.unwrap_or(ads::UDP_PORT));
    let get_netid = || match target.netid {
        Some(netid) => Ok(netid),
        None => ads::udp::get_netid((target.host.as_str(), ads::UDP_PORT)),
    };
    match args.cmd {
        Cmd::Addroute(subargs) => {
            ads::udp::add_route(udp_addr, subargs.netid, &subargs.addr,
                                subargs.routename.as_deref(),
                                Some(&subargs.username), Some(&subargs.password),
                                subargs.temporary)?;
            println!("Success.");
        }
        Cmd::Info => {
            let info = ads::udp::get_info(udp_addr)?;
            println!("NetID: {}", info.netid);
            println!("Hostname: {}", info.hostname);
            println!("TwinCAT version: {}.{}.{}",
                     info.twincat_version.0, info.twincat_version.1, info.twincat_version.2);
            println!("OS version: {} {}.{}.{} {}",
                     info.os_version.0, info.os_version.1, info.os_version.2,
                     info.os_version.3, info.os_version.4);
        }
        Cmd::File(subargs) => {
            use ads::file;
            let amsport = target.amsport.unwrap_or(ads::ports::SYSTEM_SERVICE);
            let amsaddr = ads::AmsAddr::new(get_netid()?, amsport);
            let client = ads::Client::new(tcp_addr, ads::Timeouts::none(), None)?;
            let dev = client.device(amsaddr);
            match subargs {
                FileAction::Read { path } => {
                    let mut file = file::File::open(dev, &path,
                                                    file::READ | file::BINARY | file::ENSURE_DIR)?;
                    std::io::copy(&mut file, &mut stdout())?;
                }
                FileAction::Write { path, append } => {
                    let flag = if append { ads::file::APPEND } else { ads::file::WRITE };
                    let mut file = file::File::open(dev, &path,
                                                    flag | file::BINARY | file::PLUS | file::ENSURE_DIR)?;
                    std::io::copy(&mut stdin(), &mut file)?;
                }
                FileAction::Delete { path } => {
                    file::File::delete(dev, &path, file::ENABLE_DIR)?;
                }
            }
        }
        Cmd::State(subargs) => {
            let amsport = target.amsport.unwrap_or(ads::ports::SYSTEM_SERVICE);
            let amsaddr = ads::AmsAddr::new(get_netid()?, amsport);
            let client = ads::Client::new(tcp_addr, ads::Timeouts::none(), None)?;
            let dev = client.device(amsaddr);
            let info = dev.get_info()?;
            println!("Device: {} {}.{}.{}", info.name, info.major, info.minor, info.version);
            let (state, dev_state) = dev.get_state()?;
            println!("Current state: {:?}", state);
            if let Some(newstate) = subargs.target_state {
                println!("Set new state: {:?}", newstate);
                dev.write_control(newstate, dev_state)?;
            }
        }
        Cmd::License(object) => {
            let amsport = target.amsport.unwrap_or(ads::ports::LICENSE_SERVER);
            let amsaddr = ads::AmsAddr::new(get_netid()?, amsport);
            let client = ads::Client::new(tcp_addr, ads::Timeouts::none(), None)?;
            let dev = client.device(amsaddr);
            match object {
                LicenseAction::Platformid => {
                    let mut id = [0; 2];
                    dev.read(ads::index::LICENSE, 2, &mut id)?;
                    println!("{}", u16::from_le_bytes(id));
                }
                LicenseAction::Systemid => {
                    let mut id = [0; 16];
                    dev.read(ads::index::LICENSE, 1, &mut id)?;
                    println!("{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
                              {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                             id[3], id[2], id[1], id[0], id[5], id[4], id[7], id[6], id[8], id[9],
                             id[10], id[11], id[12], id[13], id[14], id[15]);
                }
                LicenseAction::Volumeno => {
                    let mut no = [0; 4];
                    dev.read(ads::index::LICENSE, 5, &mut no)?;
                    println!("{}", u32::from_le_bytes(no));
                }
            }
        }
        Cmd::Raw(subargs) => {
            let amsport = target.amsport.unwrap_or(ads::ports::TC3_PLC_SYSTEM1);
            let amsaddr = ads::AmsAddr::new(get_netid()?, amsport);
            let client = ads::Client::new(tcp_addr, ads::Timeouts::none(), None)?;
            let dev = client.device(amsaddr);
            match subargs {
                RawAction::Read { index_group, index_offset, length, r#type, hex } => {
                    if let Some(length) = length {
                        let mut read_data = vec![0; length];
                        dev.read(index_group, index_offset, &mut read_data)?;
                        stdout().write_all(&read_data)?;
                    } else if let Some(typ) = r#type {
                        let mut read_data = vec![0; typ.size()];
                        dev.read(index_group, index_offset, &mut read_data)?;
                        print_read_value(typ, &read_data, hex);
                    }
                }
                RawAction::Write { index_group, index_offset } => {
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;
                    dev.write(index_group, index_offset, &write_data)?;
                }
                RawAction::WriteRead { index_group, index_offset, length, r#type, hex } => {
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;
                    if let Some(length) = length {
                        let mut read_data = vec![0; length];
                        dev.write_read(index_group, index_offset, &write_data, &mut read_data)?;
                        stdout().write_all(&read_data)?;
                    } else if let Some(typ) = r#type {
                        let mut read_data = vec![0; typ.size()];
                        dev.write_read(index_group, index_offset, &write_data, &mut read_data)?;
                        print_read_value(typ, &read_data, hex);
                    }
                }
            }
        }
        Cmd::Var(subargs) => {
            // Connect to the selected target, defaulting to the first PLC instance
            let amsport = target.amsport.unwrap_or(ads::ports::TC3_PLC_SYSTEM1);
            let amsaddr = ads::AmsAddr::new(get_netid()?, amsport);
            let client = ads::Client::new(tcp_addr, ads::Timeouts::none(), None)?;
            let dev = client.device(amsaddr);
            let handle = ads::symbol::Handle::new(dev, &subargs.name)?;
            let typ = subargs.r#type;

            // Write or read data?
            if let Some(value) = subargs.value {
                let write_data = get_write_value(typ, value)?;
                handle.write(&write_data)?;
            } else {
                let mut read_data = vec![0; typ.size()];
                handle.read(&mut read_data)?;
                print_read_value(typ, &read_data, subargs.hex);
            }
        }
    }
    Ok(())
}

fn get_write_value(typ: VarType, value: String) -> Result<Vec<u8>, Error> {
    let err = |_| Error::Str("expected integer".into());
    let float_err = |_| Error::Str("expected floating point number".into());
    Ok(match typ {
        VarType::String => value.into_bytes(),
        VarType::Bool => {
            if value == "TRUE" {
                vec![1]
            } else if value == "FALSE" {
                vec![0]
            } else {
                return Err(Error::Str("invalid BOOL value".into()));
            }
        }
        VarType::Byte  => parse::<u8>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Sint  => parse::<i8>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Word  => parse::<u16>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Int   => parse::<i16>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Dword => parse::<u32>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Dint  => parse::<i32>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Lword => parse::<u64>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Lint  => parse::<i64>(&value).map_err(err)?.to_le_bytes().into(),
        VarType::Real  => value.parse::<f32>().map_err(float_err)?.to_le_bytes().into(),
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
                n => println!("non-bool ({})", n),
            }
            return;
        }
        VarType::Real => {
            let v = f32::from_le_bytes(buf[..4].try_into().expect("size"));
            println!("{}", v);
            return;
        }
        VarType::Lreal => {
            let v = i64::from_le_bytes(buf[..8].try_into().expect("size"));
            println!("{}", v);
            return;
        }
        VarType::Byte  => buf[0] as i128,
        VarType::Sint  => buf[0] as i8 as i128,
        VarType::Word  => u16::from_le_bytes(buf[..2].try_into().expect("size")) as i128,
        VarType::Int   => i16::from_le_bytes(buf[..2].try_into().expect("size")) as i128,
        VarType::Dword => u32::from_le_bytes(buf[..4].try_into().expect("size")) as i128,
        VarType::Dint  => i32::from_le_bytes(buf[..4].try_into().expect("size")) as i128,
        VarType::Lword => u64::from_le_bytes(buf[..8].try_into().expect("size")) as i128,
        VarType::Lint  => i64::from_le_bytes(buf[..8].try_into().expect("size")) as i128,
    };
    // Only reaches here for integer types
    if hex {
        println!("{:#x}", value);
    } else {
        println!("{}", value);
    }
}
