macro_rules! write_integer {
    ($name:ident, $type:ty) => {
        pub(super) fn $name(writer: &mut impl std::io::Write, n: $type) -> std::io::Result<usize> {
            let bytes = n.to_le_bytes();
            writer.write_all(&bytes[..])?;
            Ok(bytes.len())
        }
    };
}
write_integer!(write_u16, u16);
write_integer!(write_u32, u32);
write_integer!(write_u64, u64);
