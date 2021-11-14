//! Reproduces the functionality of "adstool" from the Beckhoff ADS C++ library.

use std::{io::{Read, Write, stdin, stdout}, str::FromStr};

use argh::FromArgs;

#[derive(FromArgs, PartialEq, Debug)]
/// A utility for managing ADS servers.
struct Args {
    #[argh(positional)]
    /// hostname[:port] to connect to
    target: String,
    #[argh(option)]
    /// AMS address (required for most subcommands)
    ams: Option<ads::AmsAddr>,
    #[argh(subcommand)]
    cmd: Cmd,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Cmd {
    AddRoute(AddRouteArgs),
    File(FileArgs),
    License(LicenseArgs),
    NetId(NetIdArgs),
    State(StateArgs),
    Raw(RawArgs),
    // Var(VarArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Add an ADS route to the remote TwinCAT system.
#[argh(subcommand, name = "addroute")]
struct AddRouteArgs {
    #[argh(option)]
    /// hostname or IP address of the route's destionation
    addr: String,
    #[argh(option)]
    /// AMS NetId of the route's destination
    netid: ads::AmsNetId,
    #[argh(option)]
    /// name of the new route (defaults to `addr`)
    routename: Option<String>,
    #[argh(option, default="\"1\".into()")]
    /// password for logging into the system (defaults to `1`)
    password: String,
    #[argh(option, default="\"Administrator\".into()")]
    /// username for logging into the system (defaults to `Administrator`)
    username: String,
    #[argh(switch)]
    /// mark route as temporary?
    temporary: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Execute operations on files on the TwinCAT system.
///
/// Content (for write) is read from stdin.
#[argh(subcommand, name = "file")]
struct FileArgs {
    #[argh(positional)]
    /// the action (read/write/delete)
    action: String,
    #[argh(switch)]
    /// whether to append to the file when writing
    append: bool,
    #[argh(positional)]
    /// the file path
    path: String,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Query different license ids.
#[argh(subcommand, name = "license")]
struct LicenseArgs {
    #[argh(positional)]
    /// the object (platformid/systemid/volumeno)
    object: String,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Query NetID of the remote router.
#[argh(subcommand, name = "netid")]
struct NetIdArgs {}

#[derive(FromArgs, PartialEq, Debug)]
/// Read or write the ADS state of the device.
#[argh(subcommand, name = "state")]
struct StateArgs {
    #[argh(positional)]
    /// if given, the target state
    target_state: Option<ads::tcp::AdsState>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Raw read or write access for an indexgroup.
#[argh(subcommand, name = "raw")]
struct RawArgs {
    #[argh(positional)]
    /// the action (read/write/readwrite)
    action: String,
    #[argh(positional)]
    /// the index group
    index_group: HexInt,
    #[argh(positional)]
    /// the index offset
    index_offset: HexInt,
    #[argh(option)]
    /// the amount of bytes to read
    read: Option<HexInt>,
}

/// A little helper that lets the user specify numbers as hex or dec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HexInt(u32);

impl FromStr for HexInt {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().or_else(|_| {
            let no_prefix = s.trim_start_matches("0x");
            u32::from_str_radix(no_prefix, 16)
        }).map(HexInt).map_err(|_| "decimal or hex integer required")
    }
}

fn main() {
    let args: Args = argh::from_env();

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

fn err<T>(s: String) -> Result<T, Error> {
    Err(Error::Str(s))
}

fn main_inner(args: Args) -> Result<(), Error> {
    match args.cmd {
        Cmd::AddRoute(subargs) => {
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

            let reply = packet.send_receive(&args.target)?;

            println!("Return status: {}", reply.get_u32(ads::udp::Tag::Status).unwrap());
        }
        Cmd::NetId(_) => {
            let packet = ads::UdpMessage::new(ads::udp::ServiceId::Identify,
                                              ads::AmsAddr::default());
            let reply = packet.send_receive(&args.target)?;
            println!("{}", reply.get_source());
            // TODO: decode info further?
        }
        Cmd::File(subargs) => {
            use ads::file;
            let mut amsaddr = args.ams.ok_or_else(|| Error::Str(format!("--ams is required")))?;
            amsaddr.set_port(ads::ports::SYSTEM_SERVICE);
            let mut dev = ads::Client::new(&args.target, None, None)?.device(amsaddr);
            match &*subargs.action {
                "read" => {
                    let mut file = file::File::open(&mut dev, &subargs.path,
                                                    file::READ | file::BINARY | file::ENSURE_DIR)?;
                    std::io::copy(&mut file, &mut stdout())?;
                }
                "write" => {
                    let flag = if subargs.append { ads::file::APPEND } else { ads::file::WRITE };
                    let mut file = file::File::open(&mut dev, &subargs.path,
                                                    flag | file::BINARY | file::PLUS | file::ENSURE_DIR)?;
                    std::io::copy(&mut stdin(), &mut file)?;
                }
                "delete" => {
                    file::File::delete(&mut dev, &subargs.path, file::ENABLE_DIR)?;
                }
                x => return err(format!("action must be read/write/delete, not {}", x)),
            }
        }
        Cmd::License(subargs) => {
            let mut amsaddr = args.ams.ok_or_else(|| Error::Str(format!("--ams is required")))?;
            amsaddr.set_port(ads::ports::LICENSE_SERVER);
            let mut dev = ads::Client::new(&args.target, None, None)?.device(amsaddr);
            match &*subargs.object {
                "platformid" => {
                    let mut id = [0; 2];
                    dev.read(ads::index::SYS_LICENSE, 2, &mut id)?;
                    println!("{}", u16::from_le_bytes(id));
                }
                "systemid" => {
                    let mut id = [0; 16];
                    dev.read(ads::index::SYS_LICENSE, 1, &mut id)?;
                    println!("{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
                              {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                             id[3], id[2], id[1], id[0], id[5], id[4], id[7], id[6], id[8], id[9],
                             id[10], id[11], id[12], id[13], id[14], id[15]);
                }
                "volumeno" => {
                    let mut no = [0; 4];
                    dev.read(ads::index::SYS_LICENSE, 5, &mut no)?;
                    println!("{}", u32::from_le_bytes(no));
                }
                x => return err(format!("action must be platformid/systemid/volumeno, not {}", x)),
            }
        }
        Cmd::State(subargs) => {
            let amsaddr = args.ams.ok_or_else(|| Error::Str(format!("--ams is required")))?;
            let mut dev = ads::Client::new(&args.target, None, None)?.device(amsaddr);
            let (state, dev_state) = dev.get_state()?;
            println!("Current state: {:?}", state);
            if let Some(newstate) = subargs.target_state {
                println!("Set new state: {:?}", newstate);
                dev.write_control(newstate, dev_state)?;
            }
        }
        Cmd::Raw(subargs) => {
            let amsaddr = args.ams.ok_or_else(|| Error::Str(format!("--ams is required")))?;
            let mut dev = ads::Client::new(&args.target, None, None)?.device(amsaddr);
            match &*subargs.action {
                "read" => {
                    match subargs.read {
                        Some(amount) => {
                            let mut read_data = vec![0; amount.0 as usize];
                            dev.read(subargs.index_group.0, subargs.index_group.0, &mut read_data)?;
                            stdout().write_all(&read_data)?;
                        }
                        None => return err(format!("need a --read=N amount")),
                    }
                }
                "write" => {
                    if subargs.read.is_some() {
                        return err(format!("--read is not allowed when only writing"));
                    }
                    let mut write_data = Vec::new();
                    stdin().read_to_end(&mut write_data)?;
                    dev.write(subargs.index_group.0, subargs.index_group.0, &write_data)?;
                }
                "readwrite" => {
                    match subargs.read {
                        Some(amount) => {
                            let mut write_data = Vec::new();
                            stdin().read_to_end(&mut write_data)?;
                            let mut read_data = vec![0; amount.0 as usize];
                            dev.write_read(subargs.index_group.0, subargs.index_group.0,
                                           &write_data, &mut read_data)?;
                            stdout().write_all(&read_data)?;
                        }
                        None => return err(format!("need a --read=N amount")),
                    }
                }
                x => return err(format!("action must be read/write/readwrite, not {}", x)),
            }
        }
    }
    Ok(())
}
