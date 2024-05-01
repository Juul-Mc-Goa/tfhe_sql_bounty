//! Primitives for encoding and decoding various types to `u64` or `[u64; 4]`.

use std::fmt;
use std::str::FromStr;

use crate::{CellContent, CellType, TableHeaders};

/// Encodes a signed integer into a `u64`. This is done by first casting to an
/// `i64`, casting to `u64`, then inverting the MSB.
pub fn encode_signed<T>(u: T) -> u64
where
    T: Into<i64>,
{
    (<T as Into<i64>>::into(u) as u64) ^ (1 << 63)
}

/// Encodes a `String` into a vector of `u64`s. This is done by first casting it
/// to an array of bytes, then "repackaging" them into an array of `u64`s.
pub fn encode_string(s: String) -> Vec<u64> {
    let s_len = s.len();
    let s_bytes = s.as_bytes();
    let mut result: Vec<u64> = Vec::new();

    let get_or_zero = |j: usize| (if j < s_len { s_bytes[j] } else { 0u8 }) as u64;

    for i in 0..4 {
        let j = 8 * i;
        let b = [
            get_or_zero(j),
            get_or_zero(j + 1),
            get_or_zero(j + 2),
            get_or_zero(j + 3),
            get_or_zero(j + 4),
            get_or_zero(j + 5),
            get_or_zero(j + 6),
            get_or_zero(j + 7),
        ];
        let u64_from_bytes = (b[0] << 56)
            + (b[1] << 48)
            + (b[2] << 40)
            + (b[3] << 32)
            + (b[4] << 24)
            + (b[5] << 16)
            + (b[6] << 8)
            + (b[7]);
        result.push(u64_from_bytes);
    }
    result
}

/// Parses a String into an unsigned integer.
pub fn parse<T>(s: String) -> u64
where
    T: FromStr + Into<u64>,
    <T as FromStr>::Err: fmt::Debug,
{
    T::from_str(s.as_str()).unwrap().into()
}

/// Parses a String into an signed integer, then encode the result as an unsigned
/// integer.
pub fn parse_signed<T>(s: String) -> u64
where
    T: FromStr + Into<i64>,
    <T as FromStr>::Err: fmt::Debug,
{
    encode_signed(T::from_str(s.as_str()).unwrap().into())
}

/// Converts a vector of `u64`s into a String.
pub fn decode_u64_string(v: Vec<u64>) -> String {
    let mut vec_u8 = Vec::<u8>::new();
    for u in v {
        vec_u8.push(((u >> 56) % 256) as u8);
        vec_u8.push(((u >> 48) % 256) as u8);
        vec_u8.push(((u >> 40) % 256) as u8);
        vec_u8.push(((u >> 32) % 256) as u8);
        vec_u8.push(((u >> 24) % 256) as u8);
        vec_u8.push(((u >> 16) % 256) as u8);
        vec_u8.push(((u >> 8) % 256) as u8);
        vec_u8.push((u % 256) as u8);
    }
    std::str::from_utf8(&vec_u8)
        .expect("Could not create a str from a vector of bytes.")
        .trim_matches('\0')
        .into()
}

pub fn decode_cell(cell_type: CellType, encoded_cell: Vec<u64>) -> CellContent {
    let decode_i64 = |u: u64| {
        if u < (1 << 63) {
            -(u as i64)
        } else {
            (u - (1 << 63)) as i64
        }
    };
    match cell_type {
        CellType::Bool => CellContent::Bool(encoded_cell[0] != 0),
        CellType::U8 => CellContent::U8(encoded_cell[0] as u8),
        CellType::U16 => CellContent::U16(encoded_cell[0] as u16),
        CellType::U32 => CellContent::U32(encoded_cell[0] as u32),
        CellType::U64 => CellContent::U64(encoded_cell[0]),
        CellType::I8 => CellContent::I8(decode_i64(encoded_cell[0]) as i8),
        CellType::I16 => CellContent::I16(decode_i64(encoded_cell[0]) as i16),
        CellType::I32 => CellContent::I32(decode_i64(encoded_cell[0]) as i32),
        CellType::I64 => CellContent::I64(decode_i64(encoded_cell[0])),
        CellType::ShortString => CellContent::ShortString(decode_u64_string(encoded_cell)),
    }
}

#[allow(dead_code)]
pub fn decode_entry(
    headers: &TableHeaders,
    entry: Vec<u64>,
    projection: &[bool],
) -> Vec<CellContent> {
    let mut result: Vec<CellContent> = Vec::with_capacity(headers.0.len());
    for (i, (column_name, cell_type)) in headers.0.iter().enumerate() {
        if !projection[i] {
            continue;
        }
        let cell_index = headers.index_of(column_name.to_string()).unwrap() as usize;
        let cell_len = headers.type_of(column_name.to_string()).unwrap().len();
        let new_cellcontent = decode_cell(
            cell_type.clone(),
            entry[cell_index..(cell_index + cell_len)].to_vec(),
        );
        result.push(new_cellcontent);
    }
    result
}
