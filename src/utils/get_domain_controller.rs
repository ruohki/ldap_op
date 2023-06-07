use crate::prelude::*;

use windows::core::{ PCWSTR, PWSTR};
use windows::Win32::Networking::ActiveDirectory::{ DOMAIN_CONTROLLER_INFOW, DsGetDcNameW};
use windows::Win32::System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW};

pub fn get_domain_controller() -> Result<String> {
    unsafe {
        let mut domain_controller_info: *mut DOMAIN_CONTROLLER_INFOW
            = std::ptr::null_mut();
        let server_name: Option<&PCWSTR> = None;
        let site_name: Option<&PCWSTR> = None;

        let mut buffer: [u16; 256] = [0; 256];
        let domain_name = PWSTR::from_raw(buffer.as_mut_ptr());
        let mut buffer_size: u32 = 256;

        // Call GetComputerNameExW with the ComputerNameDnsDomain parameter
        GetComputerNameExW(
            ComputerNameDnsDomain,
            domain_name,
            &mut buffer_size,
        );
        let domain_name = PCWSTR::from_raw(domain_name.as_wide().as_ptr());
        let result = DsGetDcNameW(
            server_name,
            domain_name,
            None,
            site_name,
            0,
            &mut domain_controller_info,
        );
        if result != 0 {
            return Err(Error::Static("Error Retrieving the current Domain"));
        }

        (*domain_controller_info).DomainControllerName
            .to_string()
            .map(|str| str.replace("\\",""))
            .or_else(|_err| Err(Error::Static("Cannot get Domain Controller")))

    }
}
