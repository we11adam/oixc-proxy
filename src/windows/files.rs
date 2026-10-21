//! Atomic private-file creation and fail-closed DACL validation.
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::null_mut;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) {
        bail!("Windows path/argument contains NUL");
    }
    value.push(0);
    Ok(value)
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn current_sid() -> Result<String> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("open process identity");
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length);
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("read process identity");
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error()).context("format process identity");
    }
    let allocation = Local(text.cast());
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })?;
    drop(allocation);
    Ok(result)
}

pub struct Security(Local);
impl Security {
    pub fn private() -> Result<Self> {
        let administrators = wide(OsStr::new("S-1-5-32-544"))?;
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(administrators.as_ptr(), &mut sid) } == 0 {
            return Err(std::io::Error::last_os_error()).context("parse Administrators SID");
        }
        let sid = Local(sid);
        let mut administrator = 0;
        if unsafe { CheckTokenMembership(null_mut(), sid.0, &mut administrator) } == 0 {
            return Err(std::io::Error::last_os_error()).context("check administrative identity");
        }
        // An elevated administrator's files must also validate when later read
        // by the SYSTEM service. Do not add a redundant per-admin-user ACE.
        let user = if administrator != 0 {
            String::new()
        } else {
            format!("(A;OICI;FA;;;{})", current_sid()?)
        };
        // Do not inherit an Everyone/Users grant from ProgramData or a temp dir.
        Self::from_sddl(&format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){user}"))
    }

    fn from_sddl(sddl: &str) -> Result<Self> {
        let sddl = wide(OsStr::new(sddl))?;
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("create private security descriptor");
        }
        Ok(Self(Local(descriptor)))
    }

    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }
}

/// Existing files are never silently chmodded. The only permitted allow ACEs
/// belong to this user, SYSTEM and Administrators; unfamiliar ACEs fail closed.
pub fn validate_private(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("private path must be a regular file, not a reparse point");
    }
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(result as i32))
            .context("read private file ACL");
    }
    let _descriptor = Local(descriptor);
    if acl.is_null() {
        bail!("private file has an unrestricted DACL");
    }
    let mut trusted = Vec::new();
    for sid in [current_sid()?, "S-1-5-18".into(), "S-1-5-32-544".into()] {
        let text = wide(OsStr::new(&sid))?;
        let mut value = null_mut();
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut value) } == 0 {
            return Err(std::io::Error::last_os_error()).context("parse trusted identity");
        }
        trusted.push(Local(value));
    }
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = null_mut();
        if unsafe { GetAce(acl, u32::from(index), &mut ace) } == 0 {
            return Err(std::io::Error::last_os_error()).context("read private file ACL entry");
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match header.AceType {
            1 => continue, // ACCESS_DENIED_ACE only reduces access.
            0 => {
                let entry = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = (&entry.SidStart as *const u32).cast_mut().cast();
                if trusted
                    .iter()
                    .any(|allowed| unsafe { EqualSid(sid, allowed.0) } != 0)
                {
                    continue;
                }
            }
            _ => {}
        }
        bail!(
            "private file ACL grants access outside the service user, SYSTEM and Administrators; restrict it with icacls"
        );
    }
    Ok(())
}

/// Create with a private DACL in the same syscall, rejecting reparse points.
/// `exclusive` is CREATE_NEW; otherwise writable opens use OPEN_ALWAYS.
pub fn open_private(path: &Path, writable: bool, exclusive: bool) -> Result<File> {
    let path = wide(path.as_os_str())?;
    let security = Security::private()?;
    let attributes = security.attributes();
    let access = GENERIC_READ | if writable { GENERIC_WRITE } else { 0 };
    let disposition = if exclusive {
        CREATE_NEW
    } else if writable {
        OPEN_ALWAYS
    } else {
        OPEN_EXISTING
    };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("open private Windows file");
    }
    let file = unsafe { File::from_raw_handle(handle) };
    validate_private(&file)?;
    Ok(file)
}

pub fn lock(file: &File, exclusive: bool, nonblocking: bool) -> Result<()> {
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let flags = if exclusive {
        LOCKFILE_EXCLUSIVE_LOCK
    } else {
        0
    } | if nonblocking {
        LOCKFILE_FAIL_IMMEDIATELY
    } else {
        0
    };
    let mut overlap: OVERLAPPED = unsafe { std::mem::zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlap,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("lock traffic journal");
    }
    Ok(())
}

pub fn unlock(file: &File) -> Result<()> {
    let mut overlap = unsafe { std::mem::zeroed() };
    if unsafe { UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlap) } == 0 {
        return Err(std::io::Error::last_os_error()).context("unlock traffic journal");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_files_are_exclusive_and_public_acl_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private.txt");
        let file = open_private(&path, true, true).unwrap();
        validate_private(&file).unwrap();
        assert!(open_private(&path, true, true).is_err());
        let public = Security::from_sddl("D:P(A;;FA;;;WD)").unwrap();
        let name = wide(path.as_os_str()).unwrap();
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    name.as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    public.0.0,
                )
            },
            0
        );
        assert!(validate_private(&file).is_err());
        assert!(open_private(&path, false, false).is_err());
    }
}
