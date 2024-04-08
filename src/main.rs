//! Computes encrypted queries homomorphically.
//!
//! # Structure of the project
//! This project is divided in the following modules:
//! ### `query.rs`
//! Handles converting a `sqlparser::ast::Select` into an internal
//! representation of the syntax tree, as well as encoding it into a vector of
//! tuples `(bool, u8, bool u32, bool)`, and encrypting the result.
//!
//! ### `tables.rs`
//! Handles the representation of tables, entries, and cells. Also provides a
//! `TableQueryRunner` type for performing the FHE computations. Tables are stored as a
//! struct with two fields:
//! 1. `headers: Vec<CellType>`,
//! 2. `content: Vec<Vec<CellContent>>`.
//!
//! The type `CellType` is just an enum containing the different types allowed
//! in a cell.  The type `CellContent` is an enum with a variant for each type,
//! and a field holding the content.
//!
//! ### `cipher_structs.rs`
//! Contains the definition of a few structures handling encrypted data.
//! Here are the structures defined there:
//!
//! #### `EntryLUT`
//! A lookup table for handling FHE computations of functions `u8 -> u32`,
//!
//! #### `FheBool`
//! A wrapper for `Ciphertext` which implements the `Add, Mul, Not` traits,
//!
//! #### `QueryLUT`
//! A lookup table for handling FHE computations of functions `u8 -> FheBool`.
//! This requires rewriting quite a few methods from `tfhe::integer::WopbsKey`
//! and `tfhe::core_crypto` modules, and so has its own `hidden_function_lut`
//! submodule.
//!
//! # Query encoding and encryption
//! A query is internally represented by the `WhereSyntaxTree` structure. It's designed
//! to represent essentially two cases:
//! 1. an atom, which is a statement of the form `column_id op value` where
//!    `column_id` is an identifier, `op` is a comparison operator like `=, <,
//!    !=`.
//! 2. a node `n1 op n2` where bot `n1` and `n2` are of type `WhereSyntaxTree`,
//!    and `op` is one of `AND, NAND, OR, NOR`.
//!
//! The result of encoding such queries is a `Vec<EncodedInstruction>`, where
//! ```rust
//! type EncodedInstruction = (bool, u8, bool, u32, bool);
//! ```
//! Let `(is_node, left, which_op, right, negate) = instr` be an
//! `EncodedInstruction`. The boolean `is_node` is for specifying wether `instr`
//! encodes a node or an atom.
//!
//! ## Node encoding
//! A node is a boolean operator of arity two, where:
//! - `which_op` encodes the choice between `AND` (`true`) and `OR` (`false`),
//! - `negate` encodes negation of the resulting boolean, ie the choice between
//!   `AND` and `NAND`, or `OR` and `NOR`,
//! - its two arguments are encoded as two indices `i1` and `i2`, which refer to
//!   other encoded instructions in the vector.
//!
//! For example:
//! ```rust
//! let encoded_tree = vec![
//!   todo!(), // encoding of first atom
//!   todo!(), // encoding of second atom
//!   (true, 0, true, 1, false), // encoding of "encoded_tree[0] AND encoded_tree[1]"
//! ];
//! ```
//! Here the last element of `encoded_tree` refers to two atoms at index `0` and
//! `1` in `encoded_tree`.
//!
//! All in all, an `EncodedInstruction` of the form:
//! ```rust
//! (true, i1, which_op, i2, negate)
//! ```
//! encodes the following instruction:
//! ```
//! (encoded_tree[i1] which_op encoded_tree[i2]) XOR negate
//! ```
//!
//! ## Atom encoding
//! An atom is an expression of the form `column_id op value` where:
//! - `column_id: u8` is the index of a column in a table,
//! - `op` is one of `<, <=, =, >=, >, !=`,
//! - `value` is a value of type one of `bool, u8, i8, u16, i16, u32, i32,
//! ShortString`.
//!
//! ### Encoding `column_id`
//! To each column identifier is associated a single index of type `u8` (except
//! those of type `ShortString` which define eight indices). This is done by the
//! method `TableHeaders::index_of`.
//!
//! ### Encoding `op`
//! We define the boolean `which_op` to encode the choice between `<=` (`true`)
//! and `=` (`false`). We then use basic logical equivalences to encode `op`
//! with only two booleans `which_op, negate`:
//! - $a < b  \iff a \leq b-1$
//! - $a > b  \iff \neg(a \leq b)$
//! - $a =\not b \iff \neg(a = b)$
//! - $a \geq b \iff \neg(a \leq b-1)$
//!
//! We thus encode the pair `(op, value)` as a tuple `(which_op,
//! negate, encoded_val)` as follows:
//! ```rust
//! let (which_op, negate, encoded_val) = match op {
//!      "="  => (false, false, value),
//!      "!=" => (false, true,  value),
//!      "<=" => (true,  false, value),
//!      ">"  => (true,  true,  value),
//!      "<"  => (true,  false, value - 1),
//!      ">=" => (true,  true,  value - 1),
//! }
//! ```
//!
//! ### Encoding `value`
//! Every value in an encoded instruction is of type `u32`. Casting unsigned integers
//! and booleans to `u32` is straightforward.
//!
//! #### Encoding a `ShortString`
//! The type `ShortString` is a vector of 32 bytes, ie `[u8; 32]`. During
//! encoding, a value of type `ShortString` is cast as eight `u32`s, so as a
//! value of type `[u32; 8]`.
//!
//! #### Casting a signed integer to an `u32`
//! An `i32` can be cast to an `u32`, however such a casting is not compatible with
//! boolean expressions like `-1 < 0` (this evaluates to `true`, but `(-1 as u32) < 0_u32` doesn't).
//! So to obtain an embedding compatible with the order on signed and unsigned integers, we
//! simply negate the most significant bit:
//! ```rust
//! let cast_to_u32 = |i: i32| (i as u32) ^ (1 << 31);
//! ```
//!
//! ## Encrypting an `EncodedInstruction`
//! Just encrypt each element of the tuple. The output type is then:
//! ```rust
//! (Ciphertext, RadixCiphertext, Ciphertext, RadixCiphertext, Ciphertext)
//! ```
//!
//! # Hidden lookup tables
//! When performing a SQL query homomorphically, we run the encrypted query on
//! each entry. Let `n` be the length of the encoded query. The
//! `run_fhe_query_on_entry` function first creates a vector `query_lut:
//! Vec<Ciphertext>`, of size `n`, then write the (encrypted) result of each
//! instruction into it. As an instruction can refer to other instructions in
//! the encoded query, we need to homomorphically evaluate a function `u8 ->
//! Ciphertext`, also called a "hidden lookup table".  This is done in the
//! submodule `cipher_structs::hidden_function_lut`.
//!
//! # Replacing boolean operators with addition and multiplication mod 2
//! We note the following:
//! 1. Addition of ciphertexts is much faster than doing a PBS,
//! 2. Let $a,b \in \mathbb{Z}/2\mathbb{Z}$. Then:
//!     + $a+1 = \text{NOT } a$,
//!     + $a+b = a \text{ XOR } b$,
//!     + $a \times b = a \text{ AND } b$.
//!
//! However, `tfhe::FheBool` uses lookup tables for its implementation of
//! `BitXor` and `Not`. So we recreate our own `FheBool` in the `cipher_structs`
//! module. Then we rewrite:
//!
//! $(a \text{ OR } b) \rightarrow (a + b + a \times b)$
//!
//! and simplify the resulting formulas.
//! This reduces the number of PBS performed.
//!
//! ## Example
//! Let's  give the boolean formula for evaluating an instruction of the form:
//! ```rust
//! (true, i_l, which_op, i_r, negate)
//! ```
//! This thus encodes a node. Let `left, right` be the two booleans that `i_l, i_r` refer to.
//! The result boolean is then:
//! ```
//! (which_op AND (left AND right)) XOR ((NOT which_op) AND (left OR right)) XOR negate
//! ```
//! Which requires 7 PBS. When written using `+, *`, we obtain:
//! ```rust
//! which_op * (left * right) + ((1 + which_op) * (left + right + left * right)) + negate
//! ```
//! which simplifies to:
//! ```rust
//! left * right + (1 + which_op) * (left + right) + negate
//! ```
//! This requires two multiplications (thus 2 PBS), plus 4 additions.
//!

use std::path::PathBuf;
use tfhe::integer::gen_keys_radix;
use tfhe::integer::{wopbs::WopbsKey, RadixClientKey, ServerKey};
use tfhe::shortint::{Ciphertext, WopbsParameters};

mod cipher_structs;
mod query;
mod tables;

use query::*;
use tables::*;

// fn encrypt_query(query: sqlparser::ast::Select) -> EncryptedQuery;

/// # Inputs:
/// - sks: The server key to use
/// - input: your EncryptedQuery
/// - tables: the plain data you run the query on
///
/// # Output
/// - EncryptedResult
// fn run_fhe_query(
//     sks: &tfhe::integer::ServerKey,
//     input: &EncryptedQuery,
//     data: &Tables,
// ) -> EncryptedResult;

/// The output of this function should be a string using the CSV format
/// You should provide a way to compare this string with the output of
/// the clear DB system you use for comparison
// fn decrypt_result(clientk_key: &ClientKey, result: &EncryptedResult) -> String;

fn decode_entry(headers: TableHeaders, entry: Vec<u32>) -> Vec<CellContent> {
    let decode_i32 = |i: u32| {
        if i < (1 << 31) {
            -(i as i32)
        } else {
            (i - (1 << 31)) as i32
        }
    };
    let mut entry_index = 0;
    let mut result: Vec<CellContent> = Vec::with_capacity(headers.0.len());
    for (_column_name, cell_type) in headers.0 {
        let new_cellcontent = match cell_type {
            CellType::Bool => CellContent::Bool(entry[entry_index] != 0),
            CellType::U8 => CellContent::U8(entry[entry_index] as u8),
            CellType::U16 => CellContent::U16(entry[entry_index] as u16),
            CellType::U32 => CellContent::U32(entry[entry_index]),
            CellType::I8 => CellContent::I8(decode_i32(entry[entry_index]) as i8),
            CellType::I16 => CellContent::I16(decode_i32(entry[entry_index]) as i16),
            CellType::I32 => CellContent::I32(decode_i32(entry[entry_index])),
            CellType::ShortString => {
                entry_index += 3;
                CellContent::ShortString(decode_u32_string(
                    entry[(entry_index - 3)..(entry_index + 1)].to_vec(),
                ))
            }
        };
        result.push(new_cellcontent);
        entry_index += 1;
    }
    result
}

fn decode_u32_string(v: Vec<u32>) -> String {
    let mut vec_u8 = Vec::<u8>::new();
    for u in v {
        let (c0, c1, c2, c3) = (
            (u >> 24) as u8,
            ((u >> 16) % 256) as u8,
            ((u >> 8) % 256) as u8,
            (u % 256) as u8,
        );
        vec_u8.push(c0);
        vec_u8.push(c1);
        vec_u8.push(c2);
        vec_u8.push(c3);
    }
    std::str::from_utf8(&vec_u8)
        .expect("Could not create a str from a vector of bytes.")
        .trim_matches('\0')
        .into()
}

fn generate_keys() -> (RadixClientKey, ServerKey, WopbsKey, WopbsParameters) {
    // KeyGen...
    // (insert Waifu here)
    use tfhe::shortint::parameters::{
        parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    };
    let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 16);

    let wopbs_parameters = WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let wopbs_key = WopbsKey::new_wopbs_key(&ck, &sk, &wopbs_parameters);

    (ck, sk, wopbs_key, wopbs_parameters)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client_key, server_key, wopbs_key, wopbs_params) = generate_keys();

    // query::tests::encode_short_string();
    let query_path = PathBuf::from("query.txt");
    let query = build_where_syntax_tree(parse_query(query_path));

    println!("query: \n{}\n", query.to_string());

    let db_dir_path = "db_dir";
    let tables = load_tables(db_dir_path.into(), server_key.clone(), wopbs_key.clone())
        .expect("Failed to load DB at {db_dir_path}");
    let (_, table) = tables.tables[0].clone();
    let headers = table.headers.clone();

    let encrypted_query = query.encrypt(client_key.as_ref(), &headers);

    println!("\nencoded query:");
    query
        .encode(&headers)
        .iter()
        .for_each(|instr| println!("{instr:?}"));

    let query_runner = TableQueryRunner::new(
        table,
        client_key.as_ref(),
        &server_key,
        &wopbs_key,
        wopbs_params,
    );

    println!("\nencoded table:");
    query_runner
        .content
        .iter()
        .for_each(|entry| println!("{entry:?}"));

    let ct_result = query_runner.run_fhe_query(&encrypted_query);
    let clear_result = ct_result
        .into_iter()
        .map(|ct_bool: Ciphertext| client_key.decrypt_one_block(&ct_bool))
        .collect::<Vec<u64>>();

    println!("result: {clear_result:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_u8() {
        let (client_key, _server_key, _, _) = generate_keys();
        let client_key = client_key.as_ref();
        let content: u8 = 5;
        let cell: CellContent = CellContent::U8(content);
        println!("encrypting content: {cell:?}...");
        let encrypted_cell = cell.encrypt(client_key);
        println!("decrypting...");
        let decrypted_cell: u8 = client_key.decrypt_radix(&encrypted_cell[0]);
        assert_eq!(content, decrypted_cell);
    }

    #[test]
    fn encrypt_short_string() {
        let (client_key, _server_key, _, _) = generate_keys();
        let client_key = client_key.as_ref();
        let content: String = "test".into();
        let cell: CellContent = CellContent::ShortString(content.clone());
        println!("encrypting content: {cell:?}...");
        let encrypted_cell = cell.encrypt(client_key);
        println!("decrypting...");
        let decrypted_cell: Vec<u32> = encrypted_cell
            .iter()
            .map(|c| client_key.decrypt_radix::<u32>(c))
            .collect();
        let string_decrypted_cell = decode_u32_string(decrypted_cell);
        assert_eq!(content, string_decrypted_cell);
    }
}
