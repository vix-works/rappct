//! AppContainer profile management.
//!
//! Provides create/open/delete lifecycle helpers, deterministic SID derivation,
//! profile folder resolution, and named-object namespace discovery.

#[cfg(windows)]
use crate::ffi::{mem::LocalAllocGuard, sid::OwnedSid, wstr::WideString};
use crate::sid::AppContainerSid;
use crate::{AcError, Result};
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

/// An AppContainer profile with its name and derived package SID.
#[derive(Clone, Debug)]
pub struct AppContainerProfile {
    /// The profile name passed to `CreateAppContainerProfile`.
    pub name: String,
    /// The package SID derived from the profile name.
    pub sid: AppContainerSid,
}

impl AppContainerProfile {
    /// Create or open profile idempotently.
    pub fn ensure(_name: &str, _display: &str, _description: Option<&str>) -> Result<Self> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
            use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
            use windows::core::{HRESULT, PCWSTR, PWSTR};

            #[link(name = "Userenv")]
            unsafe extern "system" {
                fn CreateAppContainerProfile(
                    pszAppContainerName: PCWSTR,
                    pszDisplayName: PCWSTR,
                    pszDescription: PCWSTR,
                    pCapabilities: *mut core::ffi::c_void,
                    dwCapabilityCount: u32,
                    ppSidAppContainerSid: *mut *mut core::ffi::c_void,
                ) -> HRESULT;
                fn DeriveAppContainerSidFromAppContainerName(
                    pszAppContainerName: PCWSTR,
                    ppSidAppContainerSid: *mut *mut core::ffi::c_void,
                ) -> HRESULT;
            }

            // SAFETY: Pass stable PCWSTR buffers and receive owned SIDs; wrap pointers in RAII guards.
            unsafe {
                // Prepare wide strings using stable WideString buffers
                let name_w = WideString::from_str(_name);
                let display_w = WideString::from_str(_display);
                // CreateAppContainerProfile rejects a NULL pszDescription with
                // E_INVALIDARG (0x80070057), so fall back to the display name.
                let desc_w = WideString::from_str(_description.unwrap_or(_display));
                let desc_ptr = desc_w.as_pcwstr();

                let mut sid_ptr = std::ptr::null_mut();
                // Attempt to create
                let hr: HRESULT = CreateAppContainerProfile(
                    name_w.as_pcwstr(),
                    display_w.as_pcwstr(),
                    desc_ptr,
                    std::ptr::null_mut(),
                    0,
                    &mut sid_ptr,
                );

                let already_exists = HRESULT::from_win32(ERROR_ALREADY_EXISTS.0);
                let sid_owned = if hr.is_ok() {
                    OwnedSid::from_freesid_psid(sid_ptr)?
                } else if hr == already_exists {
                    // Fallback to derive SID when the profile already exists.
                    let mut sid2 = std::ptr::null_mut();
                    let hr2 =
                        DeriveAppContainerSidFromAppContainerName(name_w.as_pcwstr(), &mut sid2);
                    if !hr2.is_ok() {
                        return Err(AcError::Win32(format!(
                            "DeriveAppContainerSidFromAppContainerName failed: 0x{hr2_code:08X}",
                            hr2_code = hr2.0
                        )));
                    }
                    OwnedSid::from_freesid_psid(sid2)?
                } else {
                    return Err(AcError::Win32(format!(
                        "CreateAppContainerProfile failed: 0x{hr_code:08X}",
                        hr_code = hr.0
                    )));
                };

                // Convert to SDDL
                let mut sddl_ptr = PWSTR::null();
                // SAFETY: Convert a valid PSID to a LocalAlloc-managed SDDL string.
                ConvertSidToStringSidW(sid_owned.as_psid(), &mut sddl_ptr)
                    .map_err(|e| AcError::Win32(format!("ConvertSidToStringSidW failed: {e}")))?;
                // SAFETY: Wrap LocalAlloc PWSTR for proper free.
                let sddl_guard = LocalAllocGuard::<u16>::from_raw(sddl_ptr.0);
                let sddl = sddl_guard.to_string_lossy();

                Ok(Self {
                    name: _name.to_string(),
                    sid: AppContainerSid::from_sddl(sddl),
                })
            }
        }
        #[cfg(not(windows))]
        {
            Err(AcError::UnsupportedPlatform)
        }
    }
    /// Open an AppContainer profile by name, deriving its package SID from the profile name.
    ///
    /// This is intentionally lightweight and does not mutate the profile by itself.
    pub fn open(_name: &str) -> Result<Self> {
        let sid = derive_sid_from_name(_name)?;
        Ok(Self {
            name: _name.to_string(),
            sid,
        })
    }

    /// Deletes the AppContainer profile from the system.
    pub fn delete(self) -> Result<()> {
        #[cfg(windows)]
        {
            // No local imports needed here
            #[link(name = "Userenv")]
            unsafe extern "system" {
                fn DeleteAppContainerProfile(
                    pszAppContainerName: windows::core::PCWSTR,
                ) -> windows::core::HRESULT;
            }
            let name_w = WideString::from_str(&self.name);
            // SAFETY: Delete profile by its name using a stable PCWSTR buffer.
            unsafe {
                let hr = DeleteAppContainerProfile(name_w.as_pcwstr());
                if !hr.is_ok() {
                    return Err(AcError::Win32(format!(
                        "DeleteAppContainerProfile failed: 0x{hr_code:08X}",
                        hr_code = hr.0
                    )));
                }
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(AcError::UnsupportedPlatform)
        }
    }
    /// Returns the per-user folder path for this AppContainer profile.
    pub fn folder_path(&self) -> Result<std::path::PathBuf> {
        #[cfg(windows)]
        {
            use std::path::PathBuf;
            #[link(name = "Userenv")]
            unsafe extern "system" {
                fn GetAppContainerFolderPath(
                    pszAppContainerSid: windows::core::PCWSTR,
                    ppszPath: *mut windows::core::PWSTR,
                ) -> windows::core::HRESULT;
            }
            use windows::core::PWSTR;
            // SAFETY: Query by a stable, NUL-terminated SDDL SID string. The returned path uses
            // CoTaskMem allocation and is wrapped immediately on success.
            unsafe {
                let sid_w = WideString::from_str(self.sid.as_string());
                let mut out: PWSTR = PWSTR::null();
                let hr = GetAppContainerFolderPath(sid_w.as_pcwstr(), &mut out);
                if hr.is_ok() {
                    if out.is_null() {
                        return Err(AcError::Win32(
                            "GetAppContainerFolderPath succeeded but returned null path".into(),
                        ));
                    }
                    // Convert returned PWSTR to PathBuf
                    let path = {
                        // SAFETY: `out` is a CoTaskMem PWSTR; guard ensures single free.
                        let guard = crate::ffi::mem::CoTaskMem::<u16>::from_raw(out.0);
                        let mut len = 0usize;
                        // SAFETY: Walk until NUL; pointer validity per API contract.
                        while *guard.as_ptr().add(len) != 0 {
                            len += 1;
                        }
                        // SAFETY: Slice over initialized UTF-16 code units.
                        let slice = std::slice::from_raw_parts(guard.as_ptr(), len);
                        let os = std::ffi::OsString::from_wide(slice);
                        PathBuf::from(os)
                    };
                    Ok(path)
                } else {
                    if !out.is_null() {
                        // SAFETY: Defensive cleanup for APIs that may return a partial CoTaskMem
                        // buffer even when HRESULT indicates failure.
                        let _ = crate::ffi::mem::CoTaskMem::<u16>::from_raw(out.0);
                    }
                    Err(AcError::Win32(format!(
                        "GetAppContainerFolderPath failed: 0x{hr_code:08X}",
                        hr_code = hr.0
                    )))
                }
            }
        }
        #[cfg(not(windows))]
        {
            Err(AcError::UnsupportedPlatform)
        }
    }
    /// Returns the named-object namespace path for this AppContainer profile.
    pub fn named_object_path(&self) -> Result<String> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
            use windows::core::PWSTR;
            #[link(name = "Userenv")]
            unsafe extern "system" {
                fn GetAppContainerNamedObjectPath(
                    token: windows::Win32::Foundation::HANDLE,
                    appcontainersid: *mut core::ffi::c_void,
                    length: u32,
                    path: windows::core::PWSTR,
                    returnlength: *mut u32,
                ) -> i32;
            }
            // SAFETY: Convert SID to PSID; size-probe and fetch named object path.
            unsafe {
                // Convert SDDL to PSID
                let sddl_w = WideString::from_str(self.sid.as_string());
                let mut psid = windows::Win32::Security::PSID(std::ptr::null_mut());
                if ConvertStringSidToSidW(sddl_w.as_pcwstr(), &mut psid).is_err() {
                    return Err(AcError::Win32("ConvertStringSidToSidW failed".into()));
                }
                let psid_guard = LocalAllocGuard::<std::ffi::c_void>::from_raw(psid.0);
                let mut needed: u32 = 0;
                // First call to get required length (chars including NUL)
                let _ = GetAppContainerNamedObjectPath(
                    HANDLE::default(),
                    psid_guard.as_ptr(),
                    0,
                    PWSTR::null(),
                    &mut needed,
                );
                if needed == 0 {
                    return Err(AcError::Win32(
                        "GetAppContainerNamedObjectPath size query failed".into(),
                    ));
                }
                let mut buf: Vec<u16> = vec![0u16; needed as usize];
                let mut retlen: u32 = 0;
                let ok = GetAppContainerNamedObjectPath(
                    HANDLE::default(),
                    psid_guard.as_ptr(),
                    needed,
                    PWSTR(buf.as_mut_ptr()),
                    &mut retlen,
                );
                if ok == 0 {
                    return Err(AcError::Win32(
                        "GetAppContainerNamedObjectPath failed".into(),
                    ));
                }
                // Convert to String without trailing NUL
                let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                let s = String::from_utf16_lossy(&buf[..len]);
                Ok(s)
            }
        }
        #[cfg(not(windows))]
        {
            Err(AcError::UnsupportedPlatform)
        }
    }
}

/// Derives an AppContainer package SID from a profile name without creating the profile.
pub fn derive_sid_from_name(name: &str) -> Result<AppContainerSid> {
    let _ = name;
    #[cfg(windows)]
    {
        #[link(name = "Userenv")]
        unsafe extern "system" {
            fn DeriveAppContainerSidFromAppContainerName(
                name: windows::core::PCWSTR,
                sid: *mut *mut core::ffi::c_void,
            ) -> windows::core::HRESULT;
        }
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::core::PWSTR;
        // SAFETY: Derive AppContainer SID from name and convert to SDDL string via LocalAlloc PWSTR.
        unsafe {
            let name_w = WideString::from_str(name);
            let mut sid_ptr = std::ptr::null_mut();
            let hr = DeriveAppContainerSidFromAppContainerName(name_w.as_pcwstr(), &mut sid_ptr);
            if !hr.is_ok() {
                return Err(AcError::Win32(format!(
                    "DeriveAppContainerSidFromAppContainerName failed: 0x{hr_code:08X}",
                    hr_code = hr.0
                )));
            }
            let sid_owned = OwnedSid::from_freesid_psid(sid_ptr)?;
            let mut sddl_ptr = PWSTR::null();
            // SAFETY: Convert valid PSID to SDDL string; LocalAlloc PWSTR returned.
            if ConvertSidToStringSidW(sid_owned.as_psid(), &mut sddl_ptr).is_err() {
                return Err(AcError::Win32("ConvertSidToStringSidW failed".into()));
            }
            let sddl_guard = LocalAllocGuard::<u16>::from_raw(sddl_ptr.0);
            let sddl = sddl_guard.to_string_lossy();
            Ok(AppContainerSid::from_sddl(sddl))
        }
    }
    #[cfg(not(windows))]
    {
        Err(AcError::UnsupportedPlatform)
    }
}
