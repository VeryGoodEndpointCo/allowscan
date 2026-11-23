//! Win32 pieces: Authenticode verification, signer certificate extraction, catalog lookup.
//! Everything here is plain windows-sys FFI - no wrappers, no COM.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
    CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_NAME_ISSUER_FLAG, CERT_NAME_RDN_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE, CERT_SHA1_HASH_PROP_ID,
    CERT_X500_NAME_STR, CMSG_SIGNER_CERT_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertGetCertificateContextProperty, CertGetNameStringW, CryptMsgClose,
    CryptMsgGetParam, CryptQueryObject, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;
const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;

/// NUL-terminated UTF-16 for Win32.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// \\?\ prefix for long paths so the Win32 calls don't stop at MAX_PATH.
pub fn native_path(p: &str) -> String {
    if p.len() < 250 || p.starts_with(r"\\?\") {
        p.to_owned()
    } else if let Some(rest) = p.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{rest}")
    } else {
        format!(r"\\?\{p}")
    }
}

/// A signable file type with no signature (as opposed to a type Windows can't sign at all).
pub fn is_no_signature(hr: i32) -> bool {
    hr == TRUST_E_NOSIGNATURE
}

pub fn is_unsigned(hr: i32) -> bool {
    matches!(hr, TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN)
}

/// Verify an embedded Authenticode signature with no revocation checks and no network access.
pub fn verify_embedded(wpath: &[u16]) -> i32 {
    unsafe {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wpath.as_ptr(),
            hFile: null_mut(),
            pgKnownSubject: null_mut(),
        };
        let mut data: WINTRUST_DATA = zeroed();
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let no_ui = INVALID_HANDLE_VALUE as HWND;
        let hr = WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void);

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void);
        hr
    }
}

#[derive(Clone, Debug, Default)]
pub struct CertInfo {
    pub publisher: String,
    pub subject: String,
    pub issuer: String,
    pub thumbprint: String,
}

/// Signer certificate from an embedded signature or a .cat file (same as .NET's CreateFromSignedFile).
pub fn signer_cert(wpath: &[u16]) -> Option<CertInfo> {
    unsafe {
        let mut enc = 0;
        let mut content = 0;
        let mut format = 0;
        let mut store: HCERTSTORE = null_mut();
        let mut msg: *mut c_void = null_mut();

        let ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wpath.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            &mut enc,
            &mut content,
            &mut format,
            &mut store,
            &mut msg,
            null_mut(),
        );
        if ok == 0 {
            return None;
        }

        let result = if msg.is_null() || store.is_null() { None } else { signer_from(store, msg) };

        if !msg.is_null() {
            CryptMsgClose(msg);
        }
        if !store.is_null() {
            CertCloseStore(store, 0);
        }
        result
    }
}

unsafe fn signer_from(store: HCERTSTORE, msg: *mut c_void) -> Option<CertInfo> {
    unsafe {
        // CMSG_SIGNER_CERT_INFO_PARAM gives a CERT_INFO with the signer's issuer + serial filled in.
        let mut cb = 0u32;
        if CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, null_mut(), &mut cb) == 0 || cb == 0 {
            return None;
        }
        let mut buf = vec![0u64; (cb as usize).div_ceil(8)]; // u64 => correctly aligned for the struct
        if CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.as_mut_ptr() as *mut c_void, &mut cb) == 0 {
            return None;
        }

        let ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            buf.as_ptr() as *const c_void,
            null(),
        );
        if ctx.is_null() {
            return None;
        }

        let x500 = CERT_X500_NAME_STR;
        let x500_ptr = &x500 as *const _ as *const c_void;
        let info = CertInfo {
            publisher: name_string(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null()),
            subject: name_string(ctx, CERT_NAME_RDN_TYPE, 0, x500_ptr),
            issuer: name_string(ctx, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, x500_ptr),
            thumbprint: thumbprint(ctx),
        };
        CertFreeCertificateContext(ctx);
        Some(info)
    }
}

unsafe fn name_string(ctx: *const CERT_CONTEXT, kind: u32, flags: u32, para: *const c_void) -> String {
    unsafe {
        let n = CertGetNameStringW(ctx, kind, flags, para, null_mut(), 0);
        if n <= 1 {
            return String::new();
        }
        let mut buf = vec![0u16; n as usize];
        CertGetNameStringW(ctx, kind, flags, para, buf.as_mut_ptr(), n);
        String::from_utf16_lossy(&buf[..n as usize - 1])
    }
}

unsafe fn thumbprint(ctx: *const CERT_CONTEXT) -> String {
    unsafe {
        let mut hash = [0u8; 20];
        let mut cb = hash.len() as u32;
        if CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, hash.as_mut_ptr() as *mut c_void, &mut cb) == 0 {
            return String::new();
        }
        crate::hex(&hash[..cb as usize]).to_uppercase()
    }
}

/// Per-thread catalog admin contexts (SHA256 catalogs first, then legacy SHA1).
pub struct Catalogs {
    sha256: isize,
    sha1: isize,
}

impl Catalogs {
    pub fn new() -> Self {
        Self { sha256: acquire("SHA256"), sha1: acquire("SHA1") }
    }

    /// Returns the path of the installed .cat that contains this file's hash, if any.
    pub fn find(&self, wpath: &[u16]) -> Option<String> {
        lookup(self.sha256, wpath).or_else(|| lookup(self.sha1, wpath))
    }
}

impl Drop for Catalogs {
    fn drop(&mut self) {
        unsafe {
            if self.sha256 != 0 {
                CryptCATAdminReleaseContext(self.sha256, 0);
            }
            if self.sha1 != 0 {
                CryptCATAdminReleaseContext(self.sha1, 0);
            }
        }
    }
}

fn acquire(alg: &str) -> isize {
    let alg = wide(alg);
    let mut h = 0isize;
    unsafe {
        if CryptCATAdminAcquireContext2(&mut h, null(), alg.as_ptr(), null(), 0) == 0 {
            return 0;
        }
    }
    h
}

fn lookup(admin: isize, wpath: &[u16]) -> Option<String> {
    if admin == 0 {
        return None;
    }
    unsafe {
        let h = CreateFileW(
            wpath.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let r = lookup_handle(admin, h);
        CloseHandle(h);
        r
    }
}

unsafe fn lookup_handle(admin: isize, h: HANDLE) -> Option<String> {
    unsafe {
        let mut cb = 0u32;
        CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut cb, null_mut(), 0);
        if cb == 0 {
            return None;
        }
        let mut hash = vec![0u8; cb as usize];
        if CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut cb, hash.as_mut_ptr(), 0) == 0 {
            return None;
        }

        let ctx = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), cb, 0, null_mut());
        if ctx == 0 {
            return None;
        }

        let mut info: CATALOG_INFO = zeroed();
        info.cbStruct = size_of::<CATALOG_INFO>() as u32;
        let ok = CryptCATCatalogInfoFromContext(ctx, &mut info, 0) != 0;
        CryptCATAdminReleaseCatalogContext(admin, ctx, 0);

        ok.then(|| {
            let len = info.wszCatalogFile.iter().position(|&c| c == 0).unwrap_or(info.wszCatalogFile.len());
            String::from_utf16_lossy(&info.wszCatalogFile[..len])
        })
    }
}

/// Stops Windows sleeping while a scan runs (screen-off and lock still happen).
/// Windows ties this to the calling thread, so hold it on the main thread; dropping it restores normal power behaviour.
pub struct KeepAwake;

impl KeepAwake {
    pub fn new() -> Self {
        use windows_sys::Win32::System::Power::{ES_CONTINUOUS, ES_SYSTEM_REQUIRED, SetThreadExecutionState};
        unsafe { SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) };
        KeepAwake
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Power::{ES_CONTINUOUS, SetThreadExecutionState};
        unsafe { SetThreadExecutionState(ES_CONTINUOUS) };
    }
}

/// When double-clicked, Windows gives the exe its own console: drop it so only the window shows.
/// Started from a terminal, the console is shared and stays.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn hide_console_if_owned() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut ids = [0u32; 2];
    unsafe {
        if GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) == 1 {
            FreeConsole();
        }
    }
}
