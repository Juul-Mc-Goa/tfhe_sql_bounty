//! Computes encrypted queries homomorphically.
//!
//! # Main logic
//!
//! ## Client
//! 1. A provided query is parsed and converted to a structure named
//! `U64SyntaxTree`. The only type handled by this structure is `u64`: strings
//! are considered to be of type `[u8; 32]`, and are converted to `[u64; 4]`.
//! See [Encoding `value`](#encoding-value) for more details.
//! 2. The query is then optimized using the
//! [`egg`](https://egraphs-good.github.io/) crate, so as to remove
//! "pathological" queries such as `some_uint < 0`.
//! 3. The result is encoded into a vector `Vec<EncodedInstruction>`, which
//! transforms binary operators like `<, =, >=, !=` into formulas where only
//! the two operators `=, <=` are used. See [Encoding `op`](#encoding-op) for more.
//! 4. The output vector is then encrypted and sent to the server.
//!
//! ## Server
//! A provided database is handled as a structure `Tables`. It is then used to
//! build a `TableQueryRunner`, which provides the `run_fhe_query` method. This
//! method uses several structures defined in the module `cipher_structs`.
//!
//! ## Documentation
//! As much of this project's logic is dictated by how a query is encrypted and
//! how computations over booleans are handled, both are described here. See
//! the paragraphs:
//! + [Query encoding and encryption](#query-encoding-and-encryption), and
//! + [Evaluating an encrypted syntax tree](#evaluating-an-encrypted-syntax-tree),
//!
//! respectively.
//!
//! # Structure of the project
//! This project is divided in the following modules:
//!
//! ### [`query`]
//! Handles converting a `sqlparser::ast::Select` into an internal
//! representation of the syntax tree, as well as encoding it into a vector of
//! tuples:
//! ```rust
//! type EncodedInstruction = (bool, u8, bool u64, bool)
//! ```
//! and encrypting the result.
//!
//! ### [`simplify_query`]
//! Defines a simple `QueryLanguage` to be used by the `egg` crate. Also adds
//! methods to `U64SyntaxTree` to convert it to an instance of `QueryLanguage`,
//! and to convert it back to the initial type.
//!
//! ### [`tables`]
//! Handles the representation of tables, entries, and cells. Also provides a
//! [`TableQueryRunner`](`tables::TableQueryRunner`) type for performing the FHE
//! computations. Tables are stored as a struct with two fields:
//! 1. `headers: Vec<CellType>`,
//! 2. `content: Vec<Vec<CellContent>>`.
//!
//! The type `CellType` is just an enum containing the different types allowed
//! in a cell.  The type `CellContent` is an enum with a variant for each type,
//! and a field holding the content.
//!
//! ### [`cipher_structs`]
//! Contains the definition of a few structures handling encrypted data.
//! Here are the structures defined there:
//!
//! #### [`EntryLUT`](cipher_structs::EntryLUT)
//! A lookup table for handling FHE computations of functions `u8 -> u64`,
//!
//! #### [`FheBool`](cipher_structs::FheBool)
//! A wrapper for `Ciphertext` which implements the `Add, Mul, Not` traits,
//!
//! #### [`QueryLUT`](cipher_structs::QueryLUT)
//! A lookup table for handling FHE computations of functions `u8 -> FheBool`.
//! This requires rewriting quite a few methods from `tfhe::integer::WopbsKey`
//! and `tfhe::core_crypto` modules. The modified methods from `WobsKey` are
//! put in the [`query_lut`](cipher_structs::query_lut) module, while those from
//! `core_crypto` are put in the
//! [`recursive_cmux_tree`](cipher_structs::recursive_cmux_tree) module.
//!
//! # Query encoding and encryption
//! A query is internally represented by the `U64SyntaxTree` structure. It's designed
//! to represent essentially two cases:
//! 1. an atom, which is a statement of the form `column_id op value` where
//!    `column_id` is an identifier, `op` is a comparison operator like `=, <,
//!    !=`, and `value` is of type `u64`.
//! 2. a node `n1 op n2` where bot `n1` and `n2` are of type `U64SyntaxTree`,
//!    and `op` is one of `AND, NAND, OR, NOR`.
//!
//! The result of encoding such queries is a `Vec<EncodedInstruction>`, where
//! ```rust
//! type EncodedInstruction = (bool, u8, bool, u64, bool);
//! ```
//! Let `(is_node, left, which_op, right, negate) = instr` be an
//! `EncodedInstruction`. The boolean `is_node` is for specifying wether `instr`
//! encodes a node or an atom.
//!
//! ## Node encoding
//! A node is a boolean operator of arity two, where:
//! - `which_op` encodes the choice between `OR` (`true`) and `AND` (`false`),
//! - `negate` encodes negation of the resulting boolean, ie the choice between
//!   `AND` and `NAND`, or `OR` and `NOR`,
//! - its two arguments are encoded as two indices `i1` and `i2`, which refer to
//!   other encoded instructions in the vector.
//!
//! For example:
//! ```rust
//! let encoded_query = vec![
//!   todo!(), // encoding of first atom
//!   todo!(), // encoding of second atom
//!   (true, 0, true, 1, false), // encoding of "encoded_query[0] OR encoded_query[1]"
//! ];
//! ```
//! Here the last element of `encoded_query` refers to two atoms at index `0` and
//! `1` in `encoded_query`.
//!
//! All in all, an `EncodedInstruction` of the form:
//! ```rust
//! (true, i1, which_op, i2, negate)
//! ```
//! encodes the following instruction:
//! ```
//! (encoded_query[i1] OP encoded_query[i2]) XOR negate
//! ```
//! where `OP` is either `AND` or `OR` depending on `which_op`.
//!
//! ## Atom encoding
//! An atom is an expression of the form `column_id op value` where:
//! - `column_id: u8` is the index of a column in a table,
//! - `op` is one of `<, <=, =, >=, >, !=`,
//! - `value` is a value of type one of `bool, u8, u16, u32, u64, i8, i16, i32,
//! i64, ShortString`.
//!
//! ### Encoding `column_id`
//! To each column identifier is associated a single index of type `u8` (except
//! those of type `ShortString` which define four indices). This is done by the
//! method `TableHeaders::index_of`.
//!
//! ### Encoding `op`
//! We define the boolean `which_op` to encode the choice between `<=` (`true`)
//! and `=` (`false`). We then use basic logical equivalences to encode `op`
//! with only two booleans `which_op, negate`:
//! - $a < b  \iff a \leq b-1$
//! - $a > b  \iff \neg(a \leq b)$
//! - $a \not= b \iff \neg(a = b)$
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
//! <div class="warning">
//!
//! Modifying the `value` fails in essentially two corner cases:
//! 1. when processing `column_id < 0` where `column_id` is an unsigned
//! integer,
//! 2. when processing `column_id >= 0` where `column_id` is an unsigned
//! integer.
//!
//! Thus simplifying such trivial queries is required before encoding. See
//! [`simplify_query`].
//!
//! </div>
//!
//! ### Encoding `value`
//! Every value in an encoded instruction is of type `u64`. Casting unsigned integers
//! and booleans to `u64` is straightforward.
//!
//! #### Encoding a `ShortString`
//! The type `ShortString` is a vector of 32 bytes, ie `[u8; 32]`. During
//! encoding, a value of type `ShortString` is cast as four `u64`s, so as a
//! value of type `[u64; 4]`.
//!
//! #### Casting a signed integer to an `u64`
//! An `i64` can be cast to an `u64`, however such a casting is not compatible with
//! boolean expressions like `-1 < 0` (this evaluates to `true`, but `(-1 as u64) < 0_u64` doesn't).
//! So to obtain an embedding compatible with the order on signed and unsigned integers, we
//! simply negate the most significant bit:
//! ```rust
//! let cast_to_u64 = |i: i64| (i as u64) ^ (1 << 63);
//! ```
//!
//! ## Encrypting an `EncodedInstruction`
//! We just encrypt each element of the tuple. The output type is then:
//! ```rust
//! (Ciphertext, RadixCiphertext, Ciphertext, RadixCiphertext, Ciphertext)
//! ```
//! The first `RadixCiphertext` has 4 blocks, while the second has 32.
//!
//! # Evaluating an encrypted syntax tree
//! ## Hidden lookup tables
//! When performing a SQL query homomorphically, we run the encrypted query on
//! each entry.
//!
//! Let `n` be the length of the encoded query. The
//! [`TableQueryRunner::run_query_on_entry`](tables::TableQueryRunner::run_query_on_entry)
//! method first creates a vector `query_lut: Vec<Ciphertext>`, of size `n`,
//! then write the (encrypted) result of each instruction into it.
//! <div class="warning">
//!
//! Strictly speaking, `query_lut` is of type `QueryLUT`, and is kept throughout
//! entries (it is flushed at the end of each iteration).
//!
//! </div>
//!
//! As an instruction can refer to other
//! instructions in the encoded query, we need to homomorphically evaluate a
//! function `u8 -> Ciphertext`, also called a "hidden lookup table".  This is
//! done in the [`query_lut`](cipher_structs::query_lut) module.
//!
//! ## Replacing boolean operators with addition and multiplication mod 2
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
//! (which_op AND (left OR right)) XOR
//! ((NOT which_op) AND (left AND right)) XOR
//! negate
//! ```
//! Which requires 7 PBS. When written using `+, *`, we obtain:
//! ```rust
//! which_op * (left + right + left * right) +
//! (1 + which_op) * (left * right) +
//! negate
//! ```
//! which simplifies to:
//! ```rust
//! left * right + which_op * (left + right) + negate
//! ```
//! This requires two multiplications (thus 2 PBS), plus 3 additions.
//!
//! <div class="warning">
//!
//! This analysis is not complete, because some PBS weren't accounted for:
//! 1. two PBS are necessary to fetch the values of `left, right`,
//! 2. one PBS is necessary to process the boolean `is_node`,
//! 3. some more PBS are needed to handle the `is_node == false` case.
//!
//! See at [`run_query_on_entry`](tables::TableQueryRunner::run_query_on_entry)
//! for a full analysis.
//! </div>

use clap::Parser;
use sqlparser::ast::{SetExpr, Statement};
use std::path::PathBuf;
use std::time::Instant;

use tfhe::integer::gen_keys_radix;
use tfhe::integer::{wopbs::WopbsKey, ClientKey, RadixClientKey, ServerKey};
use tfhe::shortint::{Ciphertext, WopbsParameters};

mod cipher_structs;
mod encoding;
mod query;
mod simplify_query;
mod tables;

use encoding::decode_u64_string;
use query::*;
use tables::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// path to the database to load
    #[arg(long)]
    input_db: PathBuf,
    /// path to the query file
    #[arg(long)]
    query_file: PathBuf,
}

fn encrypt_query(
    query: sqlparser::ast::Select,
    client_key: &ClientKey,
    headers: &DatabaseHeaders,
) -> EncryptedQuery {
    query::parse_query(query, headers).encrypt(client_key)
}

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

#[allow(dead_code)]
fn decode_entry(headers: TableHeaders, entry: Vec<u64>) -> Vec<CellContent> {
    let decode_i64 = |i: u64| {
        if i < (1 << 63) {
            -(i as i64)
        } else {
            (i - (1 << 63)) as i64
        }
    };
    let mut entry_index = 0;
    let mut result: Vec<CellContent> = Vec::with_capacity(headers.0.len());
    for (_column_name, cell_type) in headers.0 {
        let new_cellcontent = match cell_type {
            CellType::Bool => CellContent::Bool(entry[entry_index] != 0),
            CellType::U8 => CellContent::U8(entry[entry_index] as u8),
            CellType::U16 => CellContent::U16(entry[entry_index] as u16),
            CellType::U32 => CellContent::U32(entry[entry_index] as u32),
            CellType::U64 => CellContent::U64(entry[entry_index]),
            CellType::I8 => CellContent::I8(decode_i64(entry[entry_index]) as i8),
            CellType::I16 => CellContent::I16(decode_i64(entry[entry_index]) as i16),
            CellType::I32 => CellContent::I32(decode_i64(entry[entry_index]) as i32),
            CellType::I64 => CellContent::I64(decode_i64(entry[entry_index])),
            CellType::ShortString => {
                entry_index += 3;
                CellContent::ShortString(decode_u64_string(
                    entry[(entry_index - 3)..(entry_index + 1)].to_vec(),
                ))
            }
        };
        result.push(new_cellcontent);
        entry_index += 1;
    }
    result
}

#[allow(dead_code)]
fn generate_keys() -> (RadixClientKey, ServerKey, WopbsKey, WopbsParameters) {
    // KeyGen...
    // (insert Waifu + 8-bit music here)
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
    let cli = Cli::parse();

    println!("KeyGen...");
    let (client_key, server_key, wopbs_key, wopbs_params) = generate_keys();
    println!("...done.");

    // parse cli args
    let db_dir_path = cli.input_db;
    let query_path = cli.query_file;

    // load db, parse query
    let db = load_tables(db_dir_path.into(), server_key.clone(), wopbs_key.clone())
        .expect("Failed to load DB at {db_dir_path}");
    let headers = db.headers();
    let query = parse_query_from_file(query_path, &headers);
    println!("query: \n{}\n", query.pretty());

    let (_, table) = db.tables[query.table_selection as usize].clone();

    let query_runner = TableQueryRunner::new(
        table,
        client_key.as_ref(),
        &server_key,
        &wopbs_key,
        wopbs_params,
    );

    let timer = Instant::now();
    let encrypted_query = query.encrypt(client_key.as_ref());

    let ct_result = query_runner.run_fhe_query(&encrypted_query.where_condition);
    let clear_result = ct_result
        .into_iter()
        .map(|ct_bool: Ciphertext| client_key.decrypt_one_block(&ct_bool))
        .collect::<Vec<u64>>();

    let total_time = timer.elapsed();

    println!(
        "Runtime: {}.{}s",
        total_time.as_secs(),
        total_time.subsec_millis() / 10
    );
    println!("Clear DB Result: TODO");
    println!("Encrypted DB Result: {clear_result:?}");
    println!("Results match: TODO");

    Ok(())
}

#[cfg(test)]
mod tests {
    // use super::*;
}
