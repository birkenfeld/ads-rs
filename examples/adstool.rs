//! Reproduces the functionality of "adstool" from the Beckhoff ADS C++ library.

use std::{io::{Read, Write, stdin, stdout}, str::FromStr};

use scopeguard::guard;
use structopt::{StructOpt, clap::AppSettings};
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
    /// This can be `hostname[:port]` or include an AMS address
    /// using `hostname[:port]/netid[:amsport]`, for example:
    ///
    /// localhost/5.23.91.23.1.1:851
    ///
    /// The IP port defaults to 0xBF02 (TCP) and 0xBF03 (UDP).
    ///
    /// The AMS address is required for `file`, `license`, `state`, `raw` and
    /// `var`.  The default AMS port depends on the command: `file` and `state`
    /// default to the system service, `license` to the license service,
    /// while `raw and `var` default to the first PLC instance (port 851).
    target: Target,
}

#[derive(StructOpt, Debug)]
enum Cmd {
    Addroute(AddRouteArgs),
    File(FileAction),
    License(LicenseAction),
    Netid,
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
    #[structopt(long, default_value="1")]
    password: String,

    /// username for logging into the system (defaults to `Administrator`)
    #[structopt(long, default_value="Administrator")]
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
    }
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
/// Query NetID of the remote router.
struct NetIdArgs {}

#[derive(StructOpt, Debug)]
/// Read or write the ADS state of the device.
struct StateArgs {
    /// if given, the target state
    target_state: Option<ads::tcp::AdsState>,
}

#[derive(StructOpt, Debug)]
/// Raw read or write access for an indexgroup.
enum RawAction {
    /// Read some data from an index.
    Read {
        /// the index group, can be 0xABCD
        index_group: HexInt,
        /// the index offset, can be 0xABCD
        index_offset: HexInt,
        /// the length, can be 0xABCD
        length: HexInt,
    },
    /// Write some data to an index.  Data is read from stdin.
    Write {
        /// the index group, can be 0xABCD
        index_group: HexInt,
        /// the index offset, can be 0xABCD
        index_offset: HexInt,
    },
    /// Write some data (read from stdin), then read data from an index.
    Readwrite {
        /// the index group, can be 0xABCD
        index_group: HexInt,
        /// the index offset, can be 0xABCD
        index_offset: HexInt,
        /// the length to read, can be 0xABCD
        read_length: HexInt,
    },
}

#[derive(Clone, Copy, Debug, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
enum VarType {
    Bool,
    Byte,
    Word,
    Dword,
    Lword,
    String,
}

impl VarType {
    fn size(&self) -> usize {
        match self {
            VarType::Bool => 1,
            VarType::Byte => 1,
            VarType::Word => 2,
            VarType::Dword => 4,
            VarType::Lword => 8,
            VarType::String => 255,
        }
    }
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
    hex: bool
}

/// A little helper that lets the user specify numbers as hex or dec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HexInt(u64);

impl FromStr for HexInt {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().or_else(|_| {
            let no_prefix = s.trim_start_matches("0x");
            u64::from_str_radix(no_prefix, 16)
        }).map(HexInt).map_err(|_| "decimal or hex integer required")
    }
}

/// Target spec: IP plus optional AMS adress.
#[derive(Debug)]
struct Target {
    host: String,
    port: Option<u16>,
    netid: Option<ads::AmsNetId>,
    amsport: Option<ads::AmsPort>
}

impl FromStr for Target {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rx = regex::Regex::new("(?P<host>[^:/]+)(:(?P<port>\\d+))?\
                                    (/(?P<netid>[0-9.]+)(:(?P<amsport>\\d+))?)?$").unwrap();
        match rx.captures(s) {
            None => Err("target format is host[:port][/netid[:amsport]]"),
            Some(cap) => Ok(Target {
                host: cap["host"].into(),
                port: cap.name("port").map(|p| p.as_str().parse().unwrap()),
                netid: cap.name("netid").map(|p| p.as_str().parse()).transpose()?,
                amsport: cap.name("amsport").map(|p| p.as_str().parse().unwrap()),
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
    let tcp_addr = (target.host.as_str(), target.port.unwrap_or(ads::ADS_PORT));
    let udp_addr = (target.host.as_str(), target.port.unwrap_or(ads::ADS_UDP_PORT));
    match args.cmd {
        Cmd::Addroute(subargs) => {
            let mut packet = ads::UdpMessage::new(ads::udp::ServiceId::AddRoute,
                                                  ads::AmsAddr::new(subargs.netid, 0));
            packet.add_bytes(ads::udp::Tag::NetID, &subargs.netid.0);
            packet.add_str(ads::udp::Tag::ComputerName, &subargs.addr);
            packet.add_str(ads::udp::Tag::UserName, &subargs.username);
            packet.add_str(ads::udp::Tag::Password, &subargs.password);
            packet.add_str(ads::udp::Tag::RouteName,
                           subargs.routename.as_ref().unwrap_or(&subargs.addr));
            if subargs.temporary {
                packet.add_u32(ads::udp::Tag::Options, 1);
            }

            let reply = packet.send_receive(udp_addr)?;

            println!("Return status: {}", reply.get_u32(ads::udp::Tag::Status).unwrap());
        }
        Cmd::Netid => {
            let packet = ads::UdpMessage::new(ads::udp::ServiceId::Identify,
                                              ads::AmsAddr::default());
            let reply = packet.send_receive(udp_addr)?;
            println!("{}", reply.get_source());
            // TODO: decode info further?
        }
        Cmd::File(subargs) => {
            use ads::file;
            let netid = target.netid.ok_or_else(|| Error::Str(format!("target must contain NetID")))?;
            let amsport = target.amsport.unwrap_or(ads::ports::SYSTEM_SERVICE);
            let amsaddr = ads::AmsAddr::new(netid, amsport);
            let mut dev = ads::Client::new(tcp_addr, None, None)?.device(amsaddr);
            match subargs {
                FileAction::Read { path } => {
                    let mut file = file::File::open(&mut dev, &path,
                                                    file::READ | file::BINARY | file::ENSURE_DIR)?;
                    std::io::copy(&mut file, &mut stdout())?;
                }
                FileAction::Write { path, append } => {
                    let flag = if append { ads::file::APPEND } else { ads::file::WRITE };
                    let mut file = file::File::open(&mut dev, &path,
                                                    flag | file::BINARY | file::PLUS | file::ENSURE_DIR)?;
                    std::io::copy(&mut stdin(), &mut file)?;
                }
                FileAction::Delete { path } => {
                    file::File::delete(&mut dev, &path, file::ENABLE_DIR)?;
                }
            }
        }
        Cmd::State(subargs) => {
            let netid = target.netid.ok_or_else(|| Error::Str(format!("target must contain NetID")))?;
            let amsport = target.amsport.unwrap_or(ads::ports::SYSTEM_SERVICE);
            let amsaddr = ads::AmsAddr::new(netid, amsport);
            let mut dev = ads::Client::new(tcp_addr, None, None)?.device(amsaddr);
            let (state, dev_state) = dev.get_state()?;
            println!("Current state: {:?}", state);
            if let Some(newstate) = subargs.target_state {
                println!("Set new state: {:?}", newstate);
                dev.write_control(newstate, dev_state)?;
            }
        }
        Cmd::License(object) => {
            let netid = target.netid.ok_or_else(|| Error::Str(format!("target must contain NetID")))?;
            let amsport = target.amsport.unwrap_or(ads::ports::LICENSE_SERVER);
            let amsaddr = ads::AmsAddr::new(netid, amsport);
            let mut dev = ads::Client::new(tcp_addr, None, None)?.device(amsaddr);
            match object {
                LicenseAction::Platformid => {
                    let mut id = [0; 2];
                    dev.read(ads::index::SYS_LICENSE, 2, &mut id)?;
                    println!("{}", u16::from_le_bytes(id));
                }
                LicenseAction::Systemid => {
                    let mut id = [0; 16];
                    dev.read(ads::index::SYS_LICENSE, 1, &mut id)?;
                    println!("{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
                              {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                             id[3], id[2], id[1], id[0], id[5], id[4], id[7], id[6], id[8], id[9],
                             id[10], id[11], id[12], id[13], id[14], id[15]);
                }
                LicenseAction::Volumeno => {
                    let mut no = [0; 4];
                    dev.read(ads::index::SYS_LICENSE, 5, &mut no)?;
                    println!("{}", u32::from_le_bytes(no));
                }
            }
        }
        Cmd::Raw(subargs) => {
            let netid = target.netid.ok_or_else(|| Error::Str(format!("target must contain NetID")))?;
            let amsport = target.amsport.unwrap_or(ads::ports::TC3_PLC_SYSTEM1);
            let amsaddr = ads::AmsAddr::new(netid, amsport);
            let mut dev = ads::Client::new(tcp_addr, None, None)?.device(amsaddr);
            match subargs {
                RawAction::Read { index_group, index_offset, length } => {
                    let mut read_data = vec![0; length.0 as usize];
                    dev.read(index_group.0 as u32, index_offset.0 as u32, &mut read_data)?;
                    stdout().write_all(&read_data)?;
                }
                RawAction::Write { index_group, index_offset } => {
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;
                    dev.write(index_group.0 as u32, index_offset.0 as u32, &write_data)?;
                }
                RawAction::Readwrite { index_group, index_offset, read_length } => {
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;
                    let mut read_data = vec![0; read_length.0 as usize];
                    dev.write_read(index_group.0 as u32, index_offset.0 as u32, &write_data, &mut read_data)?;
                    stdout().write_all(&read_data)?;
                }
            }
        }
        Cmd::Var(subargs) => {
            // Connect to the selected target, defaulting to the first PLC instance
            let netid = target.netid.ok_or_else(|| Error::Str(format!("target must contain NetID")))?;
            let amsport = target.amsport.unwrap_or(ads::ports::TC3_PLC_SYSTEM1);
            let amsaddr = ads::AmsAddr::new(netid, amsport);
            let mut dev = ads::Client::new(tcp_addr, None, None)?.device(amsaddr);

            // Get a handle to the given name
            let mut handle_bytes = [0; 4];
            dev.write_read(ads::index::SYS_GET_SYMHANDLE_BYNAME, 0,
                           subargs.name.as_bytes(), &mut handle_bytes)?;
            let handle = u32::from_le_bytes(handle_bytes);

            // Clean up the handle after we're done (error or not)
            let mut dev = guard(dev, |mut dev| {
                let _ = dev.write(ads::index::SYS_RELEASE_SYMHANDLE, 0, &handle_bytes);
            });

            if let Some(value) = subargs.value {
                // Write
                let buf = match subargs.r#type {
                    VarType::Bool => {
                        if value == "TRUE" {
                            vec![1]
                        } else if value == "FALSE" {
                            vec![0]
                        } else {
                            return Err(Error::Str(format!("invalid BOOL value")));
                        }
                    }
                    VarType::String => value.into_bytes(),
                    VarType::Byte => {
                        let v = HexInt::from_str(&value).map_err(|e| Error::Str(e.into()))?;
                        (v.0 as u8).to_le_bytes().into()
                    }
                    VarType::Word => {
                        let v = HexInt::from_str(&value).map_err(|e| Error::Str(e.into()))?;
                        (v.0 as u16).to_le_bytes().into()
                    },
                    VarType::Dword => {
                        let v = HexInt::from_str(&value).map_err(|e| Error::Str(e.into()))?;
                        (v.0 as u32).to_le_bytes().into()
                    },
                    VarType::Lword => {
                        let v = HexInt::from_str(&value).map_err(|e| Error::Str(e.into()))?;
                        (v.0 as u64).to_le_bytes().into()
                    },
                };

                dev.write(ads::index::SYS_RW_SYMVAL_BYHANDLE, handle, &buf)?;
            } else {
                // Read
                let mut buf = vec![0; subargs.r#type.size()];
                dev.read(ads::index::SYS_RW_SYMVAL_BYHANDLE, handle, &mut buf)?;
                let value = match subargs.r#type {
                    VarType::Bool => {
                        match buf[0] {
                            0 => println!("FALSE"),
                            1 => println!("TRUE"),
                            n => println!("non-bool ({})", n)
                        }
                        return Ok(());
                    }
                    VarType::String => {
                        println!("{}", String::from_utf8_lossy(&buf).split("\x00").next().unwrap());
                        return Ok(());
                    }
                    VarType::Byte => buf[0] as u64,
                    VarType::Word => u16::from_le_bytes(buf[..2].try_into().unwrap()) as u64,
                    VarType::Dword => u32::from_le_bytes(buf[..4].try_into().unwrap()) as u64,
                    VarType::Lword => u64::from_le_bytes(buf[..8].try_into().unwrap()),
                };
                if subargs.hex {
                    println!("{:#x}", value);
                } else {
                    println!("{}", value);
                }
            }
        }
    }
    Ok(())
}
