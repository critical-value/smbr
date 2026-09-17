use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use std::time::{Duration, UNIX_EPOCH};

use smb2::{ClientConfig, Error, ErrorKind, FileInfo, SmbClient, Tree};
use tokio::runtime::{Builder, Runtime};

#[repr(C)]
pub struct SmbrContext {
    runtime: Runtime,
    client: Option<SmbClient>,
    tree: Option<Tree>,
    username: String,
    password: String,
    workgroup: String,
    server: String,
    share: String,
}

#[repr(C)]
pub struct SmbrEntry {
    pub name: *mut c_char,
    pub type_code: c_int,
    pub size: u64,
    pub created: f64,
    pub modified: f64,
}

#[repr(C)]
pub struct SmbrDirResult {
    pub entries: *mut SmbrEntry,
    pub len: usize,
}

#[repr(C)]
pub struct SmbrStatResult {
    pub size: u64,
    pub is_directory: c_int,
    pub created: f64,
    pub modified: f64,
    pub accessed: f64,
}

#[repr(C)]
pub struct SmbrBytesResult {
    pub data: *mut c_uchar,
    pub len: usize,
}

fn set_error(error: *mut *mut c_char, message: impl Into<String>) {
    if error.is_null() {
        return;
    }
    let message = message.into();
    let value = CString::new(message).unwrap_or_else(|_| CString::new("SMB2 error").unwrap());
    unsafe { *error = value.into_raw() };
}

fn clear_error(error: *mut *mut c_char) {
    if !error.is_null() {
        unsafe { *error = ptr::null_mut() };
    }
}

fn input(value: *const c_char, name: &str) -> Result<String, String> {
    if value.is_null() {
        return Err(format!("{name} must not be null"));
    }
    unsafe {
        CStr::from_ptr(value)
            .to_str()
            .map(str::to_owned)
            .map_err(|_| format!("{name} must be valid UTF-8"))
    }
}

struct ParsedUrl {
    server: String,
    share: String,
    path: String,
}

fn parse_url(value: *const c_char) -> Result<ParsedUrl, String> {
    let value = input(value, "url")?;
    if !value
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("smb://"))
    {
        return Err("url must begin with smb://".to_string());
    }
    let rest = &value[6..];
    let mut parts = rest.splitn(3, '/');
    let server = parts.next().unwrap_or_default();
    let share = parts.next().unwrap_or_default();
    if server.is_empty() || share.is_empty() {
        return Err("url must include a server and share".to_string());
    }
    let path = parts
        .next()
        .unwrap_or_default()
        .trim_matches('/')
        .to_string();
    Ok(ParsedUrl {
        server: server.to_string(),
        share: share.to_string(),
        path,
    })
}

fn address(server: &str) -> String {
    if server.starts_with('[') {
        if server.contains("]:") {
            server.to_string()
        } else {
            format!("{server}:445")
        }
    } else {
        match server.matches(':').count() {
            0 => format!("{server}:445"),
            1 => server.to_string(),
            _ => format!("[{server}]:445"),
        }
    }
}

fn unix_time(value: smb2::pack::FileTime) -> f64 {
    value
        .to_system_time()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as f64 + f64::from(duration.subsec_nanos()) / 1e9)
        .unwrap_or(f64::NAN)
}

fn copy_file_info(info: &FileInfo) -> SmbrStatResult {
    SmbrStatResult {
        size: info.size,
        is_directory: i32::from(info.is_directory),
        created: unix_time(info.created),
        modified: unix_time(info.modified),
        accessed: unix_time(info.accessed),
    }
}

fn ensure_connection(context: &mut SmbrContext, parsed: &ParsedUrl) -> Result<(), Error> {
    if context.client.is_some()
        && context.tree.is_some()
        && context.server.eq_ignore_ascii_case(&parsed.server)
        && context.share.eq_ignore_ascii_case(&parsed.share)
    {
        return Ok(());
    }

    context.tree = None;
    context.client = None;
    let config = ClientConfig {
        addr: address(&parsed.server),
        timeout: Duration::from_secs(15),
        username: context.username.clone(),
        password: context.password.clone(),
        domain: context.workgroup.clone(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
        dfs_target_overrides: Default::default(),
        connect_options: None,
    };
    let (client, tree) = context.runtime.block_on(async {
        let mut client = SmbClient::connect(config).await?;
        let tree = client.connect_share(&parsed.share).await?;
        Ok::<_, Error>((client, tree))
    })?;
    context.client = Some(client);
    context.tree = Some(tree);
    context.server = parsed.server.clone();
    context.share = parsed.share.clone();
    Ok(())
}

fn fail(error: *mut *mut c_char, message: impl Into<String>) -> c_int {
    set_error(error, message);
    -1
}

fn operation<T>(error: *mut *mut c_char, result: Result<T, Error>) -> Result<T, c_int> {
    result.map_err(|value| {
        set_error(error, value.to_string());
        -1
    })
}

#[no_mangle]
pub extern "C" fn smbr_connect(
    username: *const c_char,
    password: *const c_char,
    workgroup: *const c_char,
    server: *const c_char,
    share: *const c_char,
    _debug: c_int,
    out: *mut *mut SmbrContext,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if out.is_null() {
        return fail(error, "output context must not be null");
    }
    unsafe { *out = ptr::null_mut() };
    let values = (|| {
        Ok::<_, String>((
            input(username, "username")?,
            input(password, "password")?,
            input(workgroup, "workgroup")?,
            input(server, "server")?,
            input(share, "share")?,
        ))
    })();
    let (username, password, workgroup, server, share) = match values {
        Ok(values) => values,
        Err(message) => return fail(error, message),
    };

    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(value) => return fail(error, format!("unable to create async runtime: {value}")),
    };
    let _ = (server, share);
    let context = Box::new(SmbrContext {
        runtime,
        client: None,
        tree: None,
        username,
        password,
        workgroup,
        server: String::new(),
        share: String::new(),
    });
    unsafe { *out = Box::into_raw(context) };
    0
}

#[no_mangle]
pub extern "C" fn smbr_disconnect(context: *mut SmbrContext) {
    if !context.is_null() {
        unsafe { drop(Box::from_raw(context)) };
    }
}

#[no_mangle]
pub extern "C" fn smbr_free_error(error: *mut c_char) {
    if !error.is_null() {
        unsafe { drop(CString::from_raw(error)) };
    }
}

#[no_mangle]
pub extern "C" fn smbr_dir(
    context: *mut SmbrContext,
    url: *const c_char,
    out: *mut SmbrDirResult,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() || out.is_null() {
        return fail(error, "context and output must not be null");
    }
    unsafe {
        (*out).entries = ptr::null_mut();
        (*out).len = 0;
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    let client = context.client.as_mut().unwrap();
    let tree = context.tree.as_mut().unwrap();
    let entries = match operation(
        error,
        context
            .runtime
            .block_on(client.list_directory(tree, &parsed.path)),
    ) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut values: Vec<SmbrEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = match CString::new(entry.name) {
            Ok(value) => value.into_raw(),
            Err(_) => {
                for value in values.drain(..) {
                    unsafe { drop(CString::from_raw(value.name)) };
                }
                return fail(error, "directory entry name contained a NUL byte");
            }
        };
        values.push(SmbrEntry {
            name,
            type_code: i32::from(entry.is_directory),
            size: entry.size,
            created: unix_time(entry.created),
            modified: unix_time(entry.modified),
        });
    }
    let mut values = values.into_boxed_slice();
    unsafe {
        (*out).len = values.len();
        (*out).entries = values.as_mut_ptr();
    }
    std::mem::forget(values);
    0
}

#[no_mangle]
pub extern "C" fn smbr_free_dir(result: *mut SmbrDirResult) {
    if result.is_null() {
        return;
    }
    unsafe {
        let result = &mut *result;
        if !result.entries.is_null() {
            let values = std::slice::from_raw_parts_mut(result.entries, result.len);
            for value in values.iter_mut() {
                if !value.name.is_null() {
                    drop(CString::from_raw(value.name));
                    value.name = ptr::null_mut();
                }
            }
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                result.entries,
                result.len,
            )));
        }
        result.entries = ptr::null_mut();
        result.len = 0;
    }
}

#[no_mangle]
pub extern "C" fn smbr_stat(
    context: *mut SmbrContext,
    url: *const c_char,
    out: *mut SmbrStatResult,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() || out.is_null() {
        return fail(error, "context and output must not be null");
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    let client = context.client.as_mut().unwrap();
    let tree = context.tree.as_mut().unwrap();
    let info = match operation(
        error,
        context.runtime.block_on(client.stat(tree, &parsed.path)),
    ) {
        Ok(value) => value,
        Err(status) => return status,
    };
    unsafe { *out = copy_file_info(&info) };
    0
}

#[no_mangle]
pub extern "C" fn smbr_exists(
    context: *mut SmbrContext,
    url: *const c_char,
    out: *mut c_int,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() || out.is_null() {
        return fail(error, "context and output must not be null");
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    let client = context.client.as_mut().unwrap();
    let tree = context.tree.as_mut().unwrap();
    match context.runtime.block_on(client.stat(tree, &parsed.path)) {
        Ok(_) => unsafe { *out = 1 },
        Err(value) if value.kind() == ErrorKind::NotFound => unsafe { *out = 0 },
        Err(value) => return fail(error, value.to_string()),
    }
    0
}

#[no_mangle]
pub extern "C" fn smbr_read(
    context: *mut SmbrContext,
    url: *const c_char,
    out: *mut SmbrBytesResult,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() || out.is_null() {
        return fail(error, "context and output must not be null");
    }
    unsafe {
        (*out).data = ptr::null_mut();
        (*out).len = 0;
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    let client = context.client.as_mut().unwrap();
    let tree = context.tree.as_mut().unwrap();
    let data = match operation(
        error,
        context
            .runtime
            .block_on(client.read_file_pipelined(tree, &parsed.path)),
    ) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut data = data.into_boxed_slice();
    unsafe {
        (*out).len = data.len();
        (*out).data = data.as_mut_ptr();
    }
    std::mem::forget(data);
    0
}

#[no_mangle]
pub extern "C" fn smbr_free_bytes(result: *mut SmbrBytesResult) {
    if result.is_null() {
        return;
    }
    unsafe {
        let result = &mut *result;
        if !result.data.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                result.data,
                result.len,
            )));
        }
        result.data = ptr::null_mut();
        result.len = 0;
    }
}

#[no_mangle]
pub extern "C" fn smbr_write(
    context: *mut SmbrContext,
    url: *const c_char,
    data: *const c_uchar,
    len: usize,
    mode: *const c_char,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() {
        return fail(error, "context must not be null");
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let mode = match input(mode, "mode") {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let data = if len == 0 {
        &[]
    } else if data.is_null() {
        return fail(error, "data must not be null when len is non-zero");
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    let result = context.runtime.block_on(async {
        if mode.starts_with('a') {
            let client = context.client.as_mut().unwrap();
            let tree = context.tree.as_mut().unwrap();
            let offset = match client.stat(tree, &parsed.path).await {
                Ok(info) => info.size,
                Err(value) if value.kind() == ErrorKind::NotFound => 0,
                Err(value) => return Err(value),
            };
            let mut writer = context
                .client
                .as_ref()
                .unwrap()
                .create_file_writer_at(context.tree.as_ref().unwrap(), &parsed.path, offset)
                .await?;
            writer.write_chunk(data).await?;
            writer.finish().await.map(|_| ())
        } else if mode.starts_with('w') {
            context
                .client
                .as_mut()
                .unwrap()
                .write_file_pipelined(context.tree.as_mut().unwrap(), &parsed.path, data)
                .await
                .map(|_| ())
        } else {
            Err(Error::InvalidData {
                message: "mode must start with w or a".to_string(),
            })
        }
    });
    match operation(error, result) {
        Ok(()) => 0,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn smbr_mkdir(
    context: *mut SmbrContext,
    url: *const c_char,
    _mode: c_int,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() {
        return fail(error, "context must not be null");
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    match operation(
        error,
        context.runtime.block_on(
            context
                .client
                .as_mut()
                .unwrap()
                .create_directory(context.tree.as_mut().unwrap(), &parsed.path),
        ),
    ) {
        Ok(()) => 0,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn smbr_delete(
    context: *mut SmbrContext,
    url: *const c_char,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() {
        return fail(error, "context must not be null");
    }
    let parsed = match parse_url(url) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &parsed) {
        return fail(error, value.to_string());
    }
    let result = context.runtime.block_on(
        context
            .client
            .as_mut()
            .unwrap()
            .delete_file(context.tree.as_mut().unwrap(), &parsed.path),
    );
    if result.is_ok() {
        return 0;
    }
    let value = result.unwrap_err();
    if value.kind() == ErrorKind::IsADirectory {
        let result = context.runtime.block_on(
            context
                .client
                .as_mut()
                .unwrap()
                .delete_directory(context.tree.as_mut().unwrap(), &parsed.path),
        );
        return match operation(error, result) {
            Ok(()) => 0,
            Err(status) => status,
        };
    }
    fail(error, value.to_string())
}

#[no_mangle]
pub extern "C" fn smbr_rename(
    context: *mut SmbrContext,
    from: *const c_char,
    to: *const c_char,
    error: *mut *mut c_char,
) -> c_int {
    clear_error(error);
    if context.is_null() {
        return fail(error, "context must not be null");
    }
    let from = match parse_url(from) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    let to = match parse_url(to) {
        Ok(value) => value,
        Err(message) => return fail(error, message),
    };
    if !from.server.eq_ignore_ascii_case(&to.server) || !from.share.eq_ignore_ascii_case(&to.share)
    {
        return fail(
            error,
            "rename requires both paths to use the same server and share",
        );
    }
    let context = unsafe { &mut *context };
    if let Err(value) = ensure_connection(context, &from) {
        return fail(error, value.to_string());
    }
    match operation(
        error,
        context
            .runtime
            .block_on(context.client.as_mut().unwrap().rename(
                context.tree.as_mut().unwrap(),
                &from.path,
                &to.path,
            )),
    ) {
        Ok(()) => 0,
        Err(status) => status,
    }
}
