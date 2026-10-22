//! Windows security helpers: DPAPI for the files the app keeps
//! (NFR-SEC-12), and asking the signed-in owner to prove it is them before an
//! answer that lowers a finding (security review H5).
//!
//! Off Windows (development only) data is stored as-is and owner checks
//! succeed, so the rest of the app is testable anywhere.

/// Encrypted files start with this tag; anything else is read as legacy
/// plain JSON and rewritten encrypted on the next save.
pub const TAG: &[u8] = b"PSG-DPAPI-1\n";

#[cfg(windows)]
const ENTROPY: &[u8] = b"Phone Spy Guard local store v1";

/// Encrypt to the signed-in Windows user. Another account, or a copy of the
/// data folder on another PC, cannot read it.
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };
        let input = CRYPT_INTEGER_BLOB { cbData: plain.len() as u32, pbData: plain.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptProtectData(
                &input,
                windows::core::w!("Phone Spy Guard"),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|e| format!("Could not encrypt: {e}"))?;
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
            let mut tagged = TAG.to_vec();
            tagged.extend_from_slice(&bytes);
            Ok(tagged)
        }
    }
    #[cfg(not(windows))]
    {
        Ok(plain.to_vec())
    }
}

/// Decrypt a file written by [`protect`]. Untagged content is returned as is.
pub fn unprotect(stored: &[u8]) -> Result<Vec<u8>, String> {
    let Some(sealed) = stored.strip_prefix(TAG) else {
        return Ok(stored.to_vec());
    };
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };
        let input = CRYPT_INTEGER_BLOB { cbData: sealed.len() as u32, pbData: sealed.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptUnprotectData(&input, None, Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
                .map_err(|e| format!("Could not decrypt (was it copied from another account or PC?): {e}"))?;
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
            Ok(bytes)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = sealed;
        Err("This file was encrypted on Windows".into())
    }
}

/// Ask Windows to confirm the person at the keyboard is the account owner:
/// Windows Hello (PIN, face, fingerprint) when it is set up, otherwise the
/// account password. Returns Ok(false) if they cancel or fail.
///
/// This stops someone who walks up to an unlocked PC from quietly marking
/// their own tool as "I set this up". It cannot stop someone who knows the
/// owner's PIN or password; the answer is still written to the timeline.
pub fn verify_owner(hwnd: isize, message: &str) -> Result<bool, String> {
    #[cfg(windows)]
    {
        match hello(hwnd, message) {
            Ok(Some(ok)) => Ok(ok),
            Ok(None) | Err(_) => password(hwnd, message),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (hwnd, message);
        Ok(true)
    }
}

/// Windows Hello. Ok(None) when Hello is not set up on this PC.
#[cfg(windows)]
fn hello(hwnd: isize, message: &str) -> windows::core::Result<Option<bool>> {
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows_future::IAsyncOperation;

    if UserConsentVerifier::CheckAvailabilityAsync()?.join()? != UserConsentVerifierAvailability::Available {
        return Ok(None);
    }
    let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
        interop.RequestVerificationForWindowAsync(HWND(hwnd as _), &HSTRING::from(message))?
    };
    Ok(Some(op.join()? == UserConsentVerificationResult::Verified))
}

/// The account password, checked with LogonUser. Only the signed-in account
/// is offered, and the password is wiped from memory straight after.
#[cfg(windows)]
fn password(hwnd: isize, message: &str) -> Result<bool, String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
    use windows::Win32::Security::Credentials::{
        CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW, CREDUIWIN_ENUMERATE_CURRENT_USER,
        CREDUI_INFOW, CRED_PACK_FLAGS,
    };
    use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT};
    use windows::Win32::System::Com::CoTaskMemFree;

    const ERROR_CANCELLED: u32 = 1223;
    let text: Vec<u16> = message.encode_utf16().chain([0]).collect();
    let caption: Vec<u16> = "Phone Spy Guard".encode_utf16().chain([0]).collect();
    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: HWND(hwnd as _),
        pszMessageText: PCWSTR(text.as_ptr()),
        pszCaptionText: PCWSTR(caption.as_ptr()),
        hbmBanner: Default::default(),
    };
    let mut package = 0u32;
    let mut out: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut out_len = 0u32;
    let rc = unsafe {
        CredUIPromptForWindowsCredentialsW(
            Some(&info),
            0,
            &mut package,
            None,
            0,
            &mut out,
            &mut out_len,
            None,
            CREDUIWIN_ENUMERATE_CURRENT_USER,
        )
    };
    if rc == ERROR_CANCELLED {
        return Ok(false);
    }
    if rc != 0 {
        return Err(format!("Windows could not ask for the password (error {rc})"));
    }

    let mut user = vec![0u16; 514];
    let mut domain = vec![0u16; 338];
    let mut pass = vec![0u16; 1024];
    let (mut ul, mut dl, mut pl) = (user.len() as u32, domain.len() as u32, pass.len() as u32);
    let unpacked = unsafe {
        let r = CredUnPackAuthenticationBufferW(
            CRED_PACK_FLAGS(0),
            out,
            out_len,
            Some(PWSTR(user.as_mut_ptr())),
            &mut ul,
            Some(PWSTR(domain.as_mut_ptr())),
            Some(&mut dl),
            Some(PWSTR(pass.as_mut_ptr())),
            &mut pl,
        );
        std::ptr::write_bytes(out as *mut u8, 0, out_len as usize);
        CoTaskMemFree(Some(out));
        r
    };
    let result = match unpacked {
        Err(e) => Err(format!("Could not read the password prompt: {e}")),
        Ok(()) => {
            // The prompt returns "DOMAIN\user" or "user@domain" in the user field.
            let mut token = HANDLE::default();
            let ok = unsafe {
                LogonUserW(
                    PCWSTR(user.as_ptr()),
                    if domain[0] == 0 { PCWSTR::null() } else { PCWSTR(domain.as_ptr()) },
                    PCWSTR(pass.as_ptr()),
                    LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT,
                    &mut token,
                )
            }
            .is_ok();
            if ok {
                unsafe {
                    let _ = CloseHandle(token);
                }
            }
            Ok(ok)
        }
    };
    pass.iter_mut().for_each(|c| *c = 0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_content_reads_back_unchanged() {
        assert_eq!(unprotect(b"{\"a\":1}").unwrap(), b"{\"a\":1}");
    }

    #[cfg(not(windows))]
    #[test]
    fn a_windows_encrypted_file_is_refused_elsewhere() {
        let mut stored = TAG.to_vec();
        stored.extend_from_slice(b"sealed");
        assert!(unprotect(&stored).is_err());
    }
}
