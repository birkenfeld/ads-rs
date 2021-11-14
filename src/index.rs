//! Well-known index groups as defined
//! [here](https://infosys.beckhoff.com/content/1033/tc3_ads_intro/117241867.html?id=1944752650545554679).

/// PLC: Read/write PLC memory (%M fields).
pub const PLC_RW_M: u32 = 0x4020;
/// PLC: Read/write PLC memory as bits (%MX fields).  Offset is (byte*8 + bit) address.
pub const PLC_RW_MX: u32 = 0x4021;
/// PLC: Read byte length of %M area (only offset 0).
pub const PLC_SIZE_M: u32 = 0x4025;
/// PLC: Read/write retain data area.
pub const PLC_RW_RB: u32 = 0x4030;
/// PLC: Read byte length of the retain data area (only offset 0).
pub const PLC_SIZE_RB: u32 = 0x4035;
/// PLC: Read/write data area.
pub const PLC_RW_DB: u32 = 0x4040;
/// PLC: Read byte length of data area (only offset 0).
pub const PLC_SIZE_DB: u32 = 0x4045;

/// System service: Get u32 handle to the name in the write data.  Index offset is 0.
/// Use with a `write_read` transaction.
pub const SYS_GET_SYMHANDLE_BYNAME: u32 = 0xF003;
/// System service: Read/write data for a symbol by handle.
/// Use the handle as the index offset.
pub const SYS_RW_SYMVAL_BYHANDLE: u32 = 0xF005;
/// System service: Relase a symbol handle.  Index offset is 0.
pub const SYS_RELEASE_SYMHANDLE: u32 = 0xF006;

/// System service: Read/write process image of physical inputs (%I fields).
pub const SYS_RW_I: u32 = 0xF020;
/// System service: Read/write process image of physical inputs as bits (%IX fields).
pub const SYS_RW_IX: u32 = 0xF021;
/// System service: Read byte length of the physical inputs (only offset 0).
pub const SYS_SIZE_I: u32 = 0xF025;

/// System service: Read/write process image of physical outputs (%Q fields).
pub const SYS_RW_Q: u32 = 0xF030;
/// System service: Read/write process image of physical outputs as bits (%QX fields).
pub const SYS_RW_QX: u32 = 0xF031;
/// System service: Read byte length of the physical outputs (only offset 0).
pub const SYS_SIZE_Q: u32 = 0xF035;

/// System service: Combine multiple index group/offset reads.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_READ: u32 = 0xF080;
/// System service: Combine multiple index group/offset writes.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_WRITE: u32 = 0xF081;
/// System service: Combine multiple index group/offset write+reads.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_READWRITE: u32 = 0xF082;
/// System service: Combine multiple index group/offset reads.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_READ_EX: u32 = 0xF083;
/// System service: Combine multiple index group/offset reads.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_READ_EX_2: u32 = 0xF084;
/// System service: Combine multiple device notification adds.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_ADDDEVNOTE: u32 = 0xF085;
/// System service: Combine multiple device notification deletes.
/// See Beckhoff docs for the format of the data.
pub const SYS_SUMUP_DELDEVNOTE: u32 = 0xF086;

// undocumented; from AdsDef.h
pub const SYS_SYMTAB: u32 = 0xF000;
pub const SYS_SYMNAME: u32 = 0xF001;
pub const SYS_SYMVAL: u32 = 0xF002;
pub const SYS_GET_SYMVAL_BYNAME: u32 = 0xF004;
pub const SYS_GET_SYMINFO_BYNAME: u32 = 0xF007;
pub const SYS_GET_SYMVERSION: u32 = 0xF008;
pub const SYS_GET_SYMINFO_BYNAME_EX: u32 = 0xF009;
pub const SYS_SYM_DOWNLOAD: u32 = 0xF00A;
pub const SYS_SYM_UPLOAD: u32 = 0xF00B;
pub const SYS_SYM_UPLOAD_INFO: u32 = 0xF00C;
pub const SYS_SYM_DOWNLOAD2: u32 = 0xF00D;
pub const SYS_SYM_DT_UPLOAD: u32 = 0xF00E;
pub const SYS_SYM_UPLOAD_INFO2: u32 = 0xF00F;
pub const SYS_SYM_NOTE: u32 = 0xF010;
pub const SYS_CLEAR_I: u32 = 0xF040;
pub const SYS_CLEAR_O: u32 = 0xF050;
pub const SYS_RW_IOB: u32 = 0xF060;

/// File service index groups.
pub const SYS_FILE_OPEN: u32 = 120;
pub const SYS_FILE_CLOSE: u32 = 121;
pub const SYS_FILE_READ: u32 = 122;
pub const SYS_FILE_WRITE: u32 = 123;
pub const SYS_FILE_DELETE: u32 = 131;

/// Index group for license queries.
pub const SYS_LICENSE: u32 = 0x01010004;
