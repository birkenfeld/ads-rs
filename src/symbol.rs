//! Wrappers for symbol operations and symbol handles.

use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;

use byteorder::{ByteOrder, ReadBytesExt, LE};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::errors::{ErrContext, Error};
use crate::index;
use crate::{Device, Result};

/// A handle to a variable within the ADS device.
///
/// The handle is released automatically on drop.
#[derive(Debug)]
pub struct Handle<'c> {
    device: Device<'c>,
    handle: u32,
}

impl<'c> Handle<'c> {
    /// Create a new handle to a single symbol.
    pub fn new(device: Device<'c>, symbol: &str) -> Result<Self> {
        let mut handle_bytes = [0; 4];
        device.write_read_exact(index::GET_SYMHANDLE_BYNAME, 0, symbol.as_bytes(), &mut handle_bytes)?;
        Ok(Self { device, handle: u32::from_le_bytes(handle_bytes) })
    }

    /// Return the raw handle.
    pub fn raw(&self) -> u32 {
        self.handle
    }

    /// Read data from the variable (returned data must match size of buffer).
    pub fn read(&self, buf: &mut [u8]) -> Result<()> {
        self.device.read_exact(index::RW_SYMVAL_BYHANDLE, self.handle, buf)
    }

    /// Write data to the variable.
    pub fn write(&self, buf: &[u8]) -> Result<()> {
        self.device.write(index::RW_SYMVAL_BYHANDLE, self.handle, buf)
    }

    /// Read data of given type.
    ///
    /// Any type that supports `zerocopy::FromBytes` can be read.  You can also
    /// derive that trait on your own structures and read structured data
    /// directly from the symbol.
    ///
    /// Note: to be independent of the host's byte order, use the integer types
    /// defined in `zerocopy::byteorder`.
    pub fn read_value<T: Default + IntoBytes + FromBytes>(&self) -> Result<T> {
        self.device.read_value(index::RW_SYMVAL_BYHANDLE, self.handle)
    }

    /// Write data of given type.
    ///
    /// See `read_value` for details.
    pub fn write_value<T: IntoBytes + Immutable>(&self, value: &T) -> Result<()> {
        self.device.write_value(index::RW_SYMVAL_BYHANDLE, self.handle, value)
    }
}

impl Drop for Handle<'_> {
    fn drop(&mut self) {
        let _ = self.device.write(index::RELEASE_SYMHANDLE, 0, &self.handle.to_le_bytes());
    }
}

/// Get symbol size by name.
pub fn get_size(device: Device<'_>, symbol: &str) -> Result<usize> {
    let mut buf = [0; 12];
    device.write_read_exact(index::GET_SYMINFO_BYNAME, 0, symbol.as_bytes(), &mut buf)?;
    Ok(u32::from_le_bytes(buf[8..].try_into().expect("size")) as usize)
}

/// Get symbol location (index group and index offset) by name.
pub fn get_location(device: Device<'_>, symbol: &str) -> Result<(u32, u32)> {
    let mut buf = [0; 12];
    device.write_read_exact(index::GET_SYMINFO_BYNAME, 0, symbol.as_bytes(), &mut buf)?;
    Ok((
        u32::from_le_bytes(buf[0..4].try_into().expect("size")),
        u32::from_le_bytes(buf[4..8].try_into().expect("size")),
    ))
}

/// Represents a symbol in the PLC memory.
pub struct Symbol {
    /// Hierarchical name of the symbol.
    pub name: String,
    /// Index group of the symbol location.
    pub ix_group: u32,
    /// Index offset of the symbol location.
    pub ix_offset: u32,
    /// Type name of the symbol.
    pub typ: String,
    /// Total size of the symbol, in bytes.
    pub size: usize,
    /// Base type:
    /// - 0 - void
    /// - 2 - INT (i16)
    /// - 3 - DINT (i32)
    /// - 4 - REAL (f32)
    /// - 5 - LREAL (f64)
    /// - 16 - SINT (i8)
    /// - 17 - USINT/BYTE (u8)
    /// - 18 - UINT/WORD (u16)
    /// - 19 - UDINT/DWORD (u32)
    /// - 20 - LINT (i64)
    /// - 21 - ULINT/LWORD (u64)
    /// - 30 - STRING
    /// - 31 - WSTRING
    /// - 32 - REAL80 (f80)
    /// - 33 - BOOL (u1)
    /// - 65 - Other/Compound type
    pub base_type: u32,
    /// Symbol flags:
    /// - 0x01 - Persistent
    /// - 0x02 - Bit value
    /// - 0x04 - Reference to
    /// - 0x08 - Type GUID present
    /// - 0x10 - TComInterfacePtr
    /// - 0x20 - Read only
    /// - 0x40 - ITF method access
    /// - 0x80 - Method deref
    /// - 0x0F00 - Context mask
    /// - 0x1000 - Attributes present
    /// - 0x2000 - Static
    /// - 0x4000 - Init on reset
    /// - 0x8000 - Extended flags present
    pub flags: u32,
}

/// Represents a type in the PLC's type inventory.
#[derive(Debug)]
pub struct Type {
    /// Name of the type.
    pub name: String,
    /// Underlying type name (e.g. the alias target).
    pub type_name: String,
    /// Comment attached to the type.
    pub comment: String,
    /// Total size of the type, in bytes.
    pub size: usize,
    /// If the type is an array, (lower, upper) index bounds for all dimensions.
    pub array: Vec<(i32, i32)>,
    /// If the type is a struct, all fields it contains.
    pub fields: Vec<Field>,
    /// Base type (see [`Symbol::base_type`]).
    pub base_type: u32,
    /// Type flags:
    /// - 0x01 - Data type
    /// - 0x02 - Data item
    /// - 0x04 - Reference to
    /// - 0x08 - Method deref
    /// - 0x10 - Oversample
    /// - 0x20 - Bit values
    /// - 0x40 - Prop item
    /// - 0x80 - Type GUID present
    /// - 0x0100 - Persistent
    /// - 0x0200 - Copy mask
    /// - 0x0400 - TComInterfacePtr
    /// - 0x0800 - Method infos present
    /// - 0x1000 - Attributes present
    /// - 0x2000 - Enum infos present
    /// - 0x010000 - Aligned
    /// - 0x020000 - Static
    /// - 0x040000 - Contains/Has Sp levels present
    /// - 0x080000 - Ignore persistent data
    /// - 0x100000 - Any size array
    /// - 0x200000 - Persistent datatype
    /// - 0x400000 - Init on reset
    /// - 0x800000 - Is/Contains PLC pointer type
    /// - 0x01000000 - Refactor infos present
    pub flags: u32,
    /// Type GUID, if present (flag 0x80).
    pub guid: Option<String>,
    /// RPC methods, if present (flag 0x0800).
    pub methods: Option<Vec<RpcMethod>>,
    /// Attributes, if present (flag 0x1000).
    pub attributes: Option<Vec<Attribute>>,
    /// Enum variant info, if present (flag 0x2000).
    pub enum_info: Option<Vec<EnumInfo>>,
}

/// Represents a field of a structure type.
#[derive(Debug)]
pub struct Field {
    /// Name of the field.
    pub name: String,
    /// Type name of the field.
    pub typ: String,
    /// Offset of the field in the structure.  If `None`, the field is defined
    /// in some other memory block and not inline to the structure.
    pub offset: Option<u32>,
    /// Size of the field, in bytes.
    pub size: usize,
    /// If the field is an array, (lower, upper) index bounds for all dimensions.
    pub array: Vec<(i32, i32)>,
    /// Base type (see [`Symbol::base_type`]).
    pub base_type: u32,
    /// Type flags (see [`Type::flags`]).
    pub flags: u32,
    /// Comment attached to the field.
    pub comment: String,
    /// Attributes, if present (flag 0x1000).
    pub attributes: Option<Vec<Attribute>>,
}

/// A PLC type attribute (pragma annotation).
#[derive(Debug, Clone)]
pub struct Attribute {
    /// Attribute name.
    pub name: String,
    /// Attribute value.
    pub value: String,
}

/// An enum variant name and numeric value.
#[derive(Debug, Clone)]
pub struct EnumInfo {
    /// Variant name.
    pub name: String,
    /// Numeric value (i64 to accommodate all base types including LINT/ULINT).
    pub value: i64,
}

/// An RPC method exposed by a function block.
#[derive(Debug, Clone)]
pub struct RpcMethod {
    /// Method name.
    pub name: String,
    /// Return type name.
    pub return_type: String,
    /// Return value size in bytes.
    pub return_size: usize,
    /// Comment attached to the method.
    pub comment: String,
    /// Method parameters.
    pub parameters: Vec<RpcMethodParameter>,
    /// Attributes on the method.
    pub attributes: Vec<Attribute>,
}

/// A parameter of an RPC method.
#[derive(Debug, Clone)]
pub struct RpcMethodParameter {
    /// Parameter name.
    pub name: String,
    /// Type name of the parameter.
    pub typ: String,
    /// Size in bytes.
    pub size: usize,
    /// Parameter flags (e.g. 0x01 = input, 0x02 = output).
    pub flags: u32,
    /// Comment attached to the parameter.
    pub comment: String,
    /// Attributes on the parameter.
    pub attributes: Vec<Attribute>,
}

// Type flag constants.
const TYPE_FLAG_GUID: u32 = 0x080;
const TYPE_FLAG_COPY_MASK: u32 = 0x200;
const TYPE_FLAG_METHOD_INFOS: u32 = 0x800;
const TYPE_FLAG_ATTRIBUTES: u32 = 0x1000;
const TYPE_FLAG_ENUM_INFOS: u32 = 0x2000;

// RPC internal flags for attribute presence.
const RPC_METHOD_ATTRIBUTE_FLAG: u32 = 0x08;
const RPC_PARAM_ATTRIBUTE_FLAG: u32 = 0x40;


fn parse_guid(ptr: &mut &[u8]) -> Result<String> {
    let ctx = "parsing GUID";
    let mut g = [0u8; 16];
    ptr.read_exact(&mut g).ctx(ctx)?;
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15],
    ))
}

fn skip_copy_mask(ptr: &mut &[u8], size: usize) -> Result<()> {
    let ctx = "skipping copy mask";
    let mut mask = vec![0u8; size];
    ptr.read_exact(&mut mask).ctx(ctx)?;
    Ok(())
}

fn parse_attributes(ptr: &mut &[u8]) -> Result<Vec<Attribute>> {
    let ctx = "parsing attributes";
    let count = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let mut attrs = Vec::with_capacity(count);
    let mut buf = [0u8; 256];
    for _ in 0..count {
        let name_len = ptr.read_u8().ctx(ctx)? as usize;
        let value_len = ptr.read_u8().ctx(ctx)? as usize;
        ptr.read_exact(&mut buf[..name_len + 1]).ctx(ctx)?;
        let name = String::from_utf8_lossy(&buf[..name_len]).into_owned();
        ptr.read_exact(&mut buf[..value_len + 1]).ctx(ctx)?;
        let value = String::from_utf8_lossy(&buf[..value_len]).into_owned();
        attrs.push(Attribute { name, value });
    }
    Ok(attrs)
}

fn parse_enum_infos(ptr: &mut &[u8], size: usize, base_type: u32) -> Result<Vec<EnumInfo>> {
    let ctx = "parsing enum infos";
    let count = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let mut enums = Vec::with_capacity(count);
    let mut buf = [0u8; 256];
    for _ in 0..count {
        let name_len = ptr.read_u8().ctx(ctx)? as usize;
        ptr.read_exact(&mut buf[..name_len + 1]).ctx(ctx)?;
        let name = String::from_utf8_lossy(&buf[..name_len]).into_owned();
        let mut raw = vec![0u8; size];
        ptr.read_exact(&mut raw).ctx(ctx)?;
        let value: i64 = match base_type {
            2 => i16::from_le_bytes(raw[..2].try_into().unwrap_or([0; 2])) as i64,
            3 => i32::from_le_bytes(raw[..4].try_into().unwrap_or([0; 4])) as i64,
            4 => f32::from_le_bytes(raw[..4].try_into().unwrap_or([0; 4])) as i64,
            5 => f64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8])) as i64,
            16 => raw[0] as i8 as i64,
            17 => raw[0] as i64,
            18 => u16::from_le_bytes(raw[..2].try_into().unwrap_or([0; 2])) as i64,
            19 => u32::from_le_bytes(raw[..4].try_into().unwrap_or([0; 4])) as i64,
            20 => i64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8])),
            21 => u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8])) as i64,
            _ => match size {
                1 => raw[0] as i64,
                2 => i16::from_le_bytes(raw[..2].try_into().unwrap_or([0; 2])) as i64,
                4 => i32::from_le_bytes(raw[..4].try_into().unwrap_or([0; 4])) as i64,
                8 => i64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8])),
                _ => -99,
            },
        };
        enums.push(EnumInfo { name, value });
    }
    Ok(enums)
}

fn parse_method_infos(ptr: &mut &[u8]) -> Result<Vec<RpcMethod>> {
    let ctx = "parsing method infos";
    let count = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let mut methods = Vec::with_capacity(count);
    for _ in 0..count {
        let entry_len = ptr.read_u32::<LE>().ctx(ctx)? as usize;
        if entry_len < 4 {
            return Err(Error::Reply(ctx, "invalid method entry length", entry_len as u32));
        }
        let (method_data, rest) = ptr.split_at(entry_len - 4);
        methods.push(parse_rpc_method(method_data)?);
        *ptr = rest;
    }
    Ok(methods)
}

fn parse_rpc_method(mut ptr: &[u8]) -> Result<RpcMethod> {
    let ctx = "parsing RPC method";
    let mut buf = [0u8; 2048];

    let _version = ptr.read_u32::<LE>().ctx(ctx)?;
    let _v_table_index = ptr.read_u32::<LE>().ctx(ctx)?;
    let return_size = ptr.read_u32::<LE>().ctx(ctx)? as usize;
    let _return_align_size = ptr.read_u32::<LE>().ctx(ctx)?;
    let _reserved = ptr.read_u32::<LE>().ctx(ctx)?;
    // Return type GUID (16 bytes).
    let mut guid_bytes = [0u8; 16];
    ptr.read_exact(&mut guid_bytes).ctx(ctx)?;
    let _return_ads_data_type = ptr.read_u32::<LE>().ctx(ctx)?;
    let flags = ptr.read_u32::<LE>().ctx(ctx)?;
    let name_len = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let return_type_len = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let comment_len = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let param_count = ptr.read_u16::<LE>().ctx(ctx)? as usize;

    ptr.read_exact(&mut buf[..name_len + 1]).ctx(ctx)?;
    let name = String::from_utf8_lossy(&buf[..name_len]).into_owned();
    ptr.read_exact(&mut buf[..return_type_len + 1]).ctx(ctx)?;
    let return_type = String::from_utf8_lossy(&buf[..return_type_len]).into_owned();
    ptr.read_exact(&mut buf[..comment_len + 1]).ctx(ctx)?;
    let comment = String::from_utf8_lossy(&buf[..comment_len]).into_owned();

    let mut parameters = Vec::with_capacity(param_count);
    for _ in 0..param_count {
        let entry_len = ptr.read_u32::<LE>().ctx(ctx)? as usize;
        if entry_len < 4 {
            return Err(Error::Reply(ctx, "invalid parameter entry length", entry_len as u32));
        }
        let (param_data, rest) = ptr.split_at(entry_len - 4);
        parameters.push(parse_rpc_method_parameter(param_data)?);
        ptr = rest;
    }

    let mut attributes = Vec::new();
    if flags & RPC_METHOD_ATTRIBUTE_FLAG != 0 {
        attributes = parse_attributes(&mut ptr)?;
    }

    Ok(RpcMethod { name, return_type, return_size, comment, parameters, attributes })
}

fn parse_rpc_method_parameter(mut ptr: &[u8]) -> Result<RpcMethodParameter> {
    let ctx = "parsing RPC method parameter";
    let mut buf = [0u8; 2048];

    let size = ptr.read_u32::<LE>().ctx(ctx)? as usize;
    let _align_size = ptr.read_u32::<LE>().ctx(ctx)?;
    let _ads_data_type = ptr.read_u32::<LE>().ctx(ctx)?;
    let flags = ptr.read_u32::<LE>().ctx(ctx)?;
    let _reserved = ptr.read_u32::<LE>().ctx(ctx)?;
    // Type GUID (16 bytes).
    let mut guid_bytes = [0u8; 16];
    ptr.read_exact(&mut guid_bytes).ctx(ctx)?;
    let _length_is_param_index = ptr.read_u16::<LE>().ctx(ctx)?;
    let name_len = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let type_len = ptr.read_u16::<LE>().ctx(ctx)? as usize;
    let comment_len = ptr.read_u16::<LE>().ctx(ctx)? as usize;

    ptr.read_exact(&mut buf[..name_len + 1]).ctx(ctx)?;
    let name = String::from_utf8_lossy(&buf[..name_len]).into_owned();
    ptr.read_exact(&mut buf[..type_len + 1]).ctx(ctx)?;
    let typ = String::from_utf8_lossy(&buf[..type_len]).into_owned();
    ptr.read_exact(&mut buf[..comment_len + 1]).ctx(ctx)?;
    let comment = String::from_utf8_lossy(&buf[..comment_len]).into_owned();

    let mut attributes = Vec::new();
    if flags & RPC_PARAM_ATTRIBUTE_FLAG != 0 {
        attributes = parse_attributes(&mut ptr)?;
    }

    Ok(RpcMethodParameter { name, typ, size, flags, comment, attributes })
}

fn parse_type_flags(
    ptr: &mut &[u8], typ: &mut Type,
) -> Result<()> {
    if typ.flags & TYPE_FLAG_GUID != 0 {
        typ.guid = Some(parse_guid(ptr)?);
    }

    if typ.flags & TYPE_FLAG_COPY_MASK != 0 {
        skip_copy_mask(ptr, typ.size)?;
    }

    if typ.flags & TYPE_FLAG_METHOD_INFOS != 0 {
        typ.methods = Some(parse_method_infos(ptr)?);
    }

    if typ.flags & TYPE_FLAG_ATTRIBUTES != 0 {
        typ.attributes = Some(parse_attributes(ptr)?);
    }

    if typ.flags & TYPE_FLAG_ENUM_INFOS != 0 {
        typ.enum_info = Some(parse_enum_infos(ptr, typ.size, typ.base_type)?);
    }

    Ok(())
}

fn parse_field_attributes(
    ptr: &mut &[u8], flags: u32, size: usize,
) -> Result<Option<Vec<Attribute>>> {
    if flags & TYPE_FLAG_GUID != 0 {
        parse_guid(ptr)?;
    }
    if flags & TYPE_FLAG_COPY_MASK != 0 {
        skip_copy_mask(ptr, size)?;
    }
    if flags & TYPE_FLAG_METHOD_INFOS != 0 {
        parse_method_infos(ptr)?;
    }
    if flags & TYPE_FLAG_ATTRIBUTES != 0 {
        Ok(Some(parse_attributes(ptr)?))
    } else {
        Ok(None)
    }
}

/// A mapping from type name to type.
pub type TypeMap = HashMap<String, Type>;

/// Get and decode symbol and type information from the PLC.
pub fn get_symbol_info(device: Device<'_>) -> Result<(Vec<Symbol>, TypeMap)> {
    // Query the sizes of symbol and type info.
    let mut read_data = [0; 64];
    device.read_exact(index::SYM_UPLOAD_INFO2, 0, &mut read_data)?;
    let symbol_len = LE::read_u32(&read_data[4..]) as usize;
    let types_len = LE::read_u32(&read_data[12..]) as usize;

    // Query the type info.
    let mut type_data = vec![0; types_len];
    device.read_exact(index::SYM_DT_UPLOAD, 0, &mut type_data)?;

    // Query the symbol info.
    let mut symbol_data = vec![0; symbol_len];
    device.read_exact(index::SYM_UPLOAD, 0, &mut symbol_data)?;

    decode_symbol_info(symbol_data, type_data)
}

/// Decode symbol and type information from the PLC.
///
/// The data must come from the `SYM_UPLOAD` and `SYM_DT_UPLOAD` queries,
/// respectively.
///
/// Returns a list of symbols, and a map of type names to types.
pub fn decode_symbol_info(symbol_data: Vec<u8>, type_data: Vec<u8>) -> Result<(Vec<Symbol>, TypeMap)> {
    // Decode the type info.
    let mut buf = [0; 1024];
    let mut data_ptr = type_data.as_slice();
    let mut type_map = HashMap::new();

    fn decode_type_info(mut ptr: &[u8], parent: Option<&mut Type>) -> Result<Option<Type>> {
        let ctx = "decoding type info";

        let mut buf = [0; 1024];
        let version = ptr.read_u32::<LE>().ctx(ctx)?;
        if version != 1 {
            return Err(Error::Reply(ctx, "unknown type info version", version));
        }
        let _subitem_index = ptr.read_u16::<LE>().ctx(ctx)?;
        let _plc_interface_id = ptr.read_u16::<LE>().ctx(ctx)?;
        let _reserved = ptr.read_u32::<LE>().ctx(ctx)?;
        let size = ptr.read_u32::<LE>().ctx(ctx)? as usize;
        let offset = ptr.read_u32::<LE>().ctx(ctx)?;
        let base_type = ptr.read_u32::<LE>().ctx(ctx)?;
        let flags = ptr.read_u32::<LE>().ctx(ctx)?;
        let len_name = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let len_type = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let len_comment = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let array_dim = ptr.read_u16::<LE>().ctx(ctx)?;
        let sub_items = ptr.read_u16::<LE>().ctx(ctx)?;
        ptr.read_exact(&mut buf[..len_name + 1]).ctx(ctx)?;
        let name = String::from_utf8_lossy(&buf[..len_name]).into_owned();
        ptr.read_exact(&mut buf[..len_type + 1]).ctx(ctx)?;
        let type_name = String::from_utf8_lossy(&buf[..len_type]).into_owned();
        ptr.read_exact(&mut buf[..len_comment + 1]).ctx(ctx)?;
        let comment = String::from_utf8_lossy(&buf[..len_comment]).into_owned();

        let mut array = vec![];
        for _ in 0..array_dim {
            let lower = ptr.read_i32::<LE>().ctx(ctx)?;
            let total = ptr.read_i32::<LE>().ctx(ctx)?;
            array.push((lower, lower + total - 1));
        }

        if let Some(parent) = parent {
            assert_eq!(sub_items, 0);
            let attributes = parse_field_attributes(&mut ptr, flags, size)?;
            // Offset -1 marks that the field is placed somewhere else in memory
            // (e.g. AT %Mxx).
            let offset = if offset == 0xFFFF_FFFF { None } else { Some(offset) };
            parent.fields.push(Field {
                name,
                typ: type_name,
                offset,
                size,
                array,
                base_type,
                flags,
                comment,
                attributes,
            });
            Ok(None)
        } else {
            assert_eq!(offset, 0);
            let mut typinfo = Type {
                name,
                type_name,
                comment,
                size,
                array,
                base_type,
                flags,
                fields: Vec::new(),
                guid: None,
                methods: None,
                attributes: None,
                enum_info: None,
            };

            for _ in 0..sub_items {
                let sub_size = ptr.read_u32::<LE>().ctx(ctx)? as usize;
                let (sub_ptr, rest) = ptr.split_at(sub_size - 4);
                decode_type_info(sub_ptr, Some(&mut typinfo))?;
                ptr = rest;
            }

            parse_type_flags(&mut ptr, &mut typinfo)?;

            Ok(Some(typinfo))
        }
    }

    while !data_ptr.is_empty() {
        let entry_size = data_ptr.read_u32::<LE>().ctx("decoding type info")? as usize;
        let (entry_ptr, rest) = data_ptr.split_at(entry_size - 4);
        let typ = decode_type_info(entry_ptr, None)?.expect("base type");
        type_map.insert(typ.name.clone(), typ);
        data_ptr = rest;
    }

    // Decode the symbol info.
    let mut symbols = Vec::new();
    let mut data_ptr = symbol_data.as_slice();
    let ctx = "decoding symbol info";
    while !data_ptr.is_empty() {
        let entry_size = data_ptr.read_u32::<LE>().ctx(ctx)? as usize;
        let (mut entry_ptr, rest) = data_ptr.split_at(entry_size - 4);
        let ix_group = entry_ptr.read_u32::<LE>().ctx(ctx)?;
        let ix_offset = entry_ptr.read_u32::<LE>().ctx(ctx)?;
        let size = entry_ptr.read_u32::<LE>().ctx(ctx)? as usize;
        let base_type = entry_ptr.read_u32::<LE>().ctx(ctx)?;
        let flags = entry_ptr.read_u16::<LE>().ctx(ctx)? as u32;
        let _legacy_array_dim = entry_ptr.read_u16::<LE>().ctx(ctx)?;
        let len_name = entry_ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let len_type = entry_ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let _len_comment = entry_ptr.read_u16::<LE>().ctx(ctx)? as usize;
        entry_ptr.read_exact(&mut buf[..len_name + 1]).ctx(ctx)?;
        let name = String::from_utf8_lossy(&buf[..len_name]).into_owned();
        entry_ptr.read_exact(&mut buf[..len_type + 1]).ctx(ctx)?;
        let typ = String::from_utf8_lossy(&buf[..len_type]).into_owned();
        // following fields (variable length), which we jump over:
        // - comment with \0
        // - type GUID if flags has Type GUID
        // - # of attributes and attribute entries if flags has Attributes
        // - flags2 if flags has Extended flags
        // - if flags2 has Old names

        symbols.push(Symbol { name, ix_group, ix_offset, typ, size, base_type, flags });

        data_ptr = rest;
    }

    Ok((symbols, type_map))
}

/// Query a single type by name using `GET_TYPEINFO_BYNAME_EX` (0xF011).
///
/// Returns a fully parsed [`Type`] including GUID, attributes, enum infos,
/// and RPC methods when present.
pub fn get_type_info_by_name(device: Device<'_>, type_name: &str) -> Result<Type> {
    let mut read_data = vec![0u8; 4096];
    let n = device.write_read(index::GET_TYPEINFO_BYNAME_EX, 0, type_name.as_bytes(), &mut read_data)?;
    let data = &read_data[..n];
    if data.len() < 4 {
        return Err(Error::Reply("get type info by name", "response too short", data.len() as u32));
    }
    let entry_length = u32::from_le_bytes(data[..4].try_into().expect("entry length")) as usize;
    let body_end = entry_length.min(data.len());
    decode_type_info_by_name(&data[4..body_end])
}

/// Decode a type info response from `GET_TYPEINFO_BYNAME_EX` (0xF011).
///
/// The `data` must be the body bytes *after* the leading u32 entry-length
/// field.  The header differs from the bulk `SYM_DT_UPLOAD` format: the
/// second and third u32 fields are `hash` and `type_hash` instead of
/// `subitem_index`/`plc_interface_id`/`reserved`.
fn decode_type_info_by_name(data: &[u8]) -> Result<Type> {
    fn decode_entry(mut ptr: &[u8], parent: Option<&mut Type>) -> Result<Option<Type>> {
        let ctx = "decoding type info by name";
        let mut buf = [0u8; 1024];

        let _version = ptr.read_u32::<LE>().ctx(ctx)?;
        let _hash = ptr.read_u32::<LE>().ctx(ctx)?;
        let _type_hash = ptr.read_u32::<LE>().ctx(ctx)?;
        let size = ptr.read_u32::<LE>().ctx(ctx)? as usize;
        let offset = ptr.read_u32::<LE>().ctx(ctx)?;
        let base_type = ptr.read_u32::<LE>().ctx(ctx)?;
        let flags = ptr.read_u32::<LE>().ctx(ctx)?;
        let len_name = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let len_type = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let len_comment = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let array_dim = ptr.read_u16::<LE>().ctx(ctx)? as usize;
        let sub_item_count = ptr.read_u16::<LE>().ctx(ctx)? as usize;

        ptr.read_exact(&mut buf[..len_name + 1]).ctx(ctx)?;
        let name = String::from_utf8_lossy(&buf[..len_name]).into_owned();
        ptr.read_exact(&mut buf[..len_type + 1]).ctx(ctx)?;
        let type_name = String::from_utf8_lossy(&buf[..len_type]).into_owned();
        ptr.read_exact(&mut buf[..len_comment + 1]).ctx(ctx)?;
        let comment = String::from_utf8_lossy(&buf[..len_comment]).into_owned();

        let mut array = vec![];
        for _ in 0..array_dim {
            let lower = ptr.read_i32::<LE>().ctx(ctx)?;
            let total = ptr.read_i32::<LE>().ctx(ctx)?;
            array.push((lower, lower + total - 1));
        }

        if let Some(parent) = parent {
            let attributes = parse_field_attributes(&mut ptr, flags, size)?;
            let offset = if offset == 0xFFFF_FFFF { None } else { Some(offset) };
            parent.fields.push(Field {
                name,
                typ: type_name,
                offset,
                size,
                array,
                base_type,
                flags,
                comment,
                attributes,
            });
            Ok(None)
        } else {
            let mut typinfo = Type {
                name,
                type_name,
                comment,
                size,
                array,
                base_type,
                flags,
                fields: Vec::new(),
                guid: None,
                methods: None,
                attributes: None,
                enum_info: None,
            };

            for _ in 0..sub_item_count {
                let sub_size = ptr.read_u32::<LE>().ctx(ctx)? as usize;
                if sub_size < 4 {
                    return Err(Error::Reply(ctx, "invalid sub-item entry length", sub_size as u32));
                }
                let (sub_ptr, rest) = ptr.split_at(sub_size - 4);
                decode_entry(sub_ptr, Some(&mut typinfo))?;
                ptr = rest;
            }

            parse_type_flags(&mut ptr, &mut typinfo)?;

            Ok(Some(typinfo))
        }
    }

    decode_entry(data, None)?.ok_or(Error::Other("expected top-level type"))
}
