use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::ptr;

use crate::messages::{Authenticate, Negotiate, Wire};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED},
        Security::{
            Authentication::Identity::{
                AcquireCredentialsHandleA, CompleteAuthToken, EnumerateSecurityPackagesA,
                FreeContextBuffer, InitSecurityInterfaceA, InitializeSecurityContextA, SecBuffer,
                SecBufferDesc, SecPkgInfoA, SecurityFunctionTableA, ISC_REQ_CONNECTION,
                ISC_REQ_INTEGRITY, ISC_REQ_STREAM, SECBUFFER_TOKEN, SECPKG_CRED_OUTBOUND,
                SECURITY_NATIVE_DREP,
            },
            Credentials::SecHandle,
        },
    },
};

const MAX_MESSAGE_SIZE: usize = 12000;

pub struct WinClient {
    credentials: SecHandle,
    context: Option<SecHandle>,
    target: CString,
    lifetime: i64,
    output_buffer: Vec<u8>,
}

const SECURITY_PACKAGE: &'static str = "Negotiate\0";

impl WinClient {
    pub fn new(target: impl AsRef<str>) -> anyhow::Result<Self> {
        let target = CString::new(target.as_ref())?;
        let mut credentials: MaybeUninit<SecHandle> = MaybeUninit::uninit();
        let mut lifetime = 0;

        unsafe {
            AcquireCredentialsHandleA(
                PCSTR::null(),
                PCSTR(SECURITY_PACKAGE.as_ptr().cast()),
                SECPKG_CRED_OUTBOUND,
                None,
                None,
                None,
                None,
                credentials.as_mut_ptr(),
                Some(ptr::addr_of_mut!(lifetime)),
            )?;
        }

        Ok(Self {
            credentials: unsafe { credentials.assume_init() },
            context: None,
            target,
            lifetime,
            output_buffer: Vec::with_capacity(MAX_MESSAGE_SIZE),
        })
    }

    fn initialize_security_context(&mut self, input: Option<&[u8]>) -> anyhow::Result<bool> {
        let flags = ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_STREAM;
        let mut input_sec_buffer = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let input_desc_buffer = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: ptr::addr_of_mut!(input_sec_buffer),
        };
        if let Some(buffer) = input {
            input_sec_buffer.cbBuffer = buffer.len() as u32;
            input_sec_buffer.pvBuffer = buffer.as_ptr() as *mut _;
        };
        self.output_buffer.clear();
        let mut output_sec_buffer = SecBuffer {
            cbBuffer: self
                .output_buffer
                .capacity()
                .try_into()
                .expect("Buffer is too big"),
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: self.output_buffer.as_mut_ptr().cast(),
        };
        let mut output_desc_buffer = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: ptr::addr_of_mut!(output_sec_buffer),
        };
        let mut context_attr = 0;

        let ret = if let Some(context) = self.context.as_mut() {
            unsafe {
                InitializeSecurityContextA(
                    Some(ptr::addr_of_mut!(self.credentials)),
                    Some(context as *mut _),
                    Some(self.target.as_ptr()),
                    flags,
                    0,
                    SECURITY_NATIVE_DREP,
                    input.map(|_| ptr::addr_of!(input_desc_buffer)),
                    0,
                    Some(context as *mut _),
                    Some(ptr::addr_of_mut!(output_desc_buffer)),
                    ptr::addr_of_mut!(context_attr),
                    Some(ptr::addr_of_mut!(self.lifetime)),
                )
            }
        } else {
            let mut new_context: MaybeUninit<SecHandle> = MaybeUninit::uninit();
            let ret = unsafe {
                InitializeSecurityContextA(
                    Some(ptr::addr_of_mut!(self.credentials)),
                    None,
                    Some(self.target.as_ptr()),
                    flags,
                    0,
                    SECURITY_NATIVE_DREP,
                    input.map(|_| ptr::addr_of!(input_desc_buffer)),
                    0,
                    Some(new_context.as_mut_ptr()),
                    Some(ptr::addr_of_mut!(output_desc_buffer)),
                    ptr::addr_of_mut!(context_attr),
                    Some(ptr::addr_of_mut!(self.lifetime)),
                )
            };
            self.context = Some(unsafe { new_context.assume_init() });
            ret
        };
        unsafe {
            self.output_buffer
                .set_len(output_sec_buffer.cbBuffer.try_into().unwrap());
        }

        if ret == SEC_I_COMPLETE_NEEDED || ret == SEC_I_COMPLETE_AND_CONTINUE {
            let context = self.context.as_ref().expect("A token should be present") as *const _;
            unsafe { CompleteAuthToken(context, ptr::addr_of!(output_desc_buffer))? };
        }

        Ok(!(ret == SEC_I_CONTINUE_NEEDED || ret == SEC_I_COMPLETE_AND_CONTINUE))
    }

    pub fn negotiate(&mut self) -> anyhow::Result<&[u8]> {
        let done = self.initialize_security_context(None)?;
        debug_assert!(!done);

        Ok(&self.output_buffer[..])
    }

    pub fn challenge(&mut self, message: &[u8]) -> anyhow::Result<&[u8]> {
        let done = self.initialize_security_context(Some(message))?;
        debug_assert!(done);
        Ok(&self.output_buffer[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_pkgs() {
        let mut clnt = WinClient::new("test").unwrap();
        let buf = clnt.negotiate().unwrap();
        let (_, n) = Negotiate::deserialize::<nom::error::VerboseError<&[u8]>>(buf).unwrap();
        eprintln!("{:#?}", n);

        let challenge = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x0c, 0x00, 0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x8a, 0xe2, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
            0x24, 0x00, 0x44, 0x00, 0x00, 0x00, 0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x02, 0x00,
            0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        ][..];

        let buf = clnt.challenge(challenge).unwrap();
        let (_, a) = Authenticate::deserialize::<nom::error::VerboseError<&[u8]>>(buf).unwrap();
        eprintln!("{:#?}", a);
    }
}
