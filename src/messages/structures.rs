use rand::{rngs::OsRng, RngCore};

mod filetime;
pub use filetime::FileTime;

mod single_host_data;
pub use single_host_data::SingleHostData;

mod avid;
pub use avid::{AvPair, MsvAvFlags};

mod lm_challenge;
pub use lm_challenge::{LmChallenge, Lmv1Challenge, Lmv2Challenge};

mod nt_challenge;
pub use nt_challenge::{NtChallenge, Ntv1Challenge, Ntv2Challenge};

mod encrypted_random_session_key;
pub use encrypted_random_session_key::EncryptedRandomSessionKey;

macro_rules! buffer_aliases {
    ($typename:ident, $name:literal, $size:expr) => {
        #[derive(Default, PartialEq, Eq, Clone)]
        pub struct $typename([u8; $size]);

        impl<'a> crate::messages::Wire<'a> for $typename {
            fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
            where
                W: std::io::Write,
            {
                writer.write_all(&self.0[..])?;
                Ok($size)
            }

            fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
            where
                E: crate::messages::NomError<'a>,
            {
                let mut data = Self::default();

                let (rest, content) =
                    nom::error::context($name, nom::bytes::complete::take($size))(input)?;
                data.0.copy_from_slice(content);

                Ok((rest, data))
            }
        }

        impl std::fmt::Debug for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                for b in &self.0[..] {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }

        impl std::ops::Deref for $typename {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0[..]
            }
        }

        impl std::ops::DerefMut for $typename {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0[..]
            }
        }

        impl From<[u8; $size]> for $typename {
            fn from(b: [u8; $size]) -> Self {
                Self(b)
            }
        }

        impl $typename {
            pub fn random() -> Self {
                let mut data = [0u8; $size];
                OsRng.fill_bytes(&mut data[..]);
                data.into()
            }
        }
    };
}

buffer_aliases!(ServerChallenge, "server_challenge", 8usize);
buffer_aliases!(ClientChallenge, "client_challenge", 8usize);
buffer_aliases!(SessionBaseKey, "session_base_key", 16usize);
buffer_aliases!(KeyExchangeKey, "key_exchange_key", 16usize);
buffer_aliases!(ExportedSessionKey, "exported_session_key", 16usize);
buffer_aliases!(NtProofStr, "nt_proof_str", 16usize);
buffer_aliases!(Response16, "response", 16usize);
buffer_aliases!(Response24, "response", 24usize);
