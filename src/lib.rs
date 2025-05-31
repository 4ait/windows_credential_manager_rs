
use std::ptr;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Security::Credentials::{CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC};

pub struct CredentialManager;

impl CredentialManager {
    /// Сохранить токен в Windows Credential Manager
    pub fn store_token(target_name: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let target_name_wide: Vec<u16> = target_name.encode_utf16().chain(Some(0)).collect();
        let token_bytes = token.as_bytes();

        let credential = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_name_wide.as_ptr() as *mut u16),
            Comment: PWSTR::null(),
            LastWritten: Default::default(),
            CredentialBlobSize: token_bytes.len() as u32,
            CredentialBlob: token_bytes.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE, // Доступно для всех пользователей машины
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR::null(),
        };

        unsafe {
            CredWriteW(&credential, 0)?;
        }

        println!("Токен успешно сохранен в Credential Manager");
        Ok(())
    }

    /// Получить токен из Windows Credential Manager
    pub fn get_token(target_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let target_name_wide: Vec<u16> = target_name.encode_utf16().chain(Some(0)).collect();

        unsafe {
            let mut credential_ptr: *mut CREDENTIALW = ptr::null_mut();

            // Читаем credential
            CredReadW(
                PCWSTR(target_name_wide.as_ptr()),
                CRED_TYPE_GENERIC,
                None,
                &mut credential_ptr,
            )?;

            if credential_ptr.is_null() {
                return Err("Credential не найден".into());
            }

            let credential = &*credential_ptr;

            // Конвертируем blob обратно в строку
            let token_bytes = std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            );

            let token = String::from_utf8(token_bytes.to_vec())?;

            // Освобождаем память
            CredFree(credential_ptr as *const std::ffi::c_void);

            Ok(token)
        }
    }

    /// Удалить токен из Credential Manager
    pub fn delete_token(target_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let target_name_wide: Vec<u16> = target_name.encode_utf16().chain(Some(0)).collect();

        unsafe {
            CredDeleteW(
                PCWSTR(target_name_wide.as_ptr()),
                CRED_TYPE_GENERIC,
                None
            )?;
        }

        println!("Токен удален из Credential Manager");
        Ok(())
    }

    /// Проверить существование токена
    pub fn token_exists(target_name: &str) -> bool {
        Self::get_token(target_name).is_ok()
    }
}


