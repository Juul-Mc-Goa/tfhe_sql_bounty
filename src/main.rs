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
//! transforms binary operators like `<, =, >=, !=` into formulas where only the
//! two operators `=, <=` are used. See [Encoding `op`](#encoding-op) for more.
//! 4. The output vector is then encrypted and sent to the server.
//! 5. When receiving the response from the server, the client decrypts only the
//! necessary entries and columns based on the two attributes
//! `encrypted_result.is_record_in_result` and `encrypted_result.projection`.
//! Then the initial (clear) query sent to the server is used to rearrange the
//! columns as requested by the query. See [`decrypt_result_to_hashmap`].
//!
//! ## Server
//! A provided database is handled as a structure [`Database`], which is a list of
//! [`Table`]s. Each table is then used to build a
//! [`TableQueryRunner`], which provides the `run_query` method. This method:
//! 1. runs the encrypted query on the table, ignoring the optional `DISTINCT` flag,
//! 2. post-process the result to make it compliant with that flag.
//!
//! This two-step process allows for parallel computation of each table record at
//! step 1.  Step 2 is mainly a cmux tree of depth equals to the number of
//! columns: the only other operations done during this step are computing sums
//! of ciphertexts, which should not be too expensive (in terms of cpu load).
//! See [`TableQueryRunner::is_record_already_in_result`].
//!
//! After each `TableQueryRunner` finished its computations, the result of which
//! is roughly stored as a `Vec<Vec<RadixCipherText>>`, they are combined into
//! one:
//! * each table result is resized to the maximum table length / maximum column
//! width,
//! * each of its element is multiplied by an encryption of `current_table ==
//! selected_table`,
//! * all `Vec<Vec<RadixCiphertext>>` are summed element-wise.
//!
//! See [`DbQueryRunner::run_query`].
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
//! ## Comments on the chosen architecture
//! ### Handling only `u64`s
//! One could choose to handle only `u256`s so that `ShortString` are simply
//! cast into that type.  However, every other types would also be cast into
//! `u256`, resulting in a big performance hit if most values are not
//! `ShortString`.
//!
//! On the other hand, casting `ShortString` as four `u64` means that conditions
//! like `some_str = "something"` are cast into
//! ```
//! s0 = "<something0>" AND s1 = ... AND s3 = "<something3>"
//! ```
//! which means evaluating 7 instructions:
//! * 1 for each `s0, ..., s3`, and
//! * 1 for each `AND`.
//!
//! Thus this choice is less performant when the database has mostly
//! `ShortString`s.
//!
//! ## Encoding the `WHERE` condition
//! This condition is a boolean formula, represented as a syntax tree. When
//! trying to encrypt such a syntax tree, one stumbles on a problem:
//! representing structured data in an encrypted form is hard.
//!
//! One could try to transform such data into a canonical, unstructured one
//! (like a Conjunctive/Disjunctive Normal Form), but such transformation can
//! [blow
//! up](https://en.wikipedia.org/wiki/Conjunctive_normal_form#Other_approaches)
//! the size of the query.
//!
//! One way around it is to define [new
//! variables](https://en.wikipedia.org/wiki/Tseytin_transformation), but this
//! is equivalent to storing the structured data and saving the output of each
//! boolean gate in a temporary register. This is the approach taken in this
//! project.
//!
//! Once again, if the queries are assumed to be "small" when written in
//! Conjunctive/Disjunctive Normal Form, then this choice is less performant,
//! and better otherwise.
//!
//! <div class="warning">
//!
//! ##### Notation
//! As performing arbitrary boolean circuit and using registers to store
//! values sounds a lot like a minimal processor, each element of an
//! `EncryptedSyntaxTree` is called an "instruction".
//!
//! </div>
//!
//! ## Storing indices as `u8`
//! In this project, every index is supposed to be smaller than 256. This restricts the size
//! of the following structures:
//! * [`EncodedInstruction`]: the second element of the tuple is an `u8`, which
//! means:
//!   - the number of columns in a table is less than 256,
//!   - the number of `EncodedInstruction`s is less than 256,
//! * [`ClearQuery`]: the attribute `table_selection` is an `u8`, so
//! the number of tables in a database is less than 256.
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
//! ### [`encoding`]
//! Primitives for encoding different types to `u64`, or `[u64; 4]`.
//!
//! ### [`tables`]
//! Handles the representation of tables, entries, and cells.
//!
//! ### [`runner`]
//! Provides the [`TableQueryRunner`] and [`DbQueryRunner`] types for running
//! the FHE query.
//!
//! ### [`distinct`]
//! Implements methods for handling the `DISTINCT` flag.
//!
//! ### [`cipher_structs`]
//! Contains the definition of a few structures handling encrypted data.
//! Here are the structures defined there:
//!
//! #### [`RecordLUT`](cipher_structs::RecordLUT)
//! A lookup table for handling FHE computations of functions `u8 -> u64`.
//!
//! #### [`FheBool`]
//! A wrapper for `Ciphertext` which implements the `Add, Mul, Not` traits. A
//! boolean is represented by an integer modulo 2, and as a `Ciphertext`
//! encrypts an integer modulo 4, we remove the degree checks on
//! addition/multiplication, but keep the noise checks. See [`FheBool`]
//! implementation of `add_assign` and its method
//! [`binary_smart_op_optimal_cleaning_strategy`](FheBool::binary_smart_op_optimal_cleaning_strategy).
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
//! each record.
//!
//! Let `n` be the length of the encoded query. The
//! [`TableQueryRunner::run_query_on_record`](TableQueryRunner::run_query_on_record)
//! method first creates a vector `query_lut: Vec<Ciphertext>`, of size `n`,
//! then write the (encrypted) result of each instruction into it.
//! <div class="warning">
//!
//! Strictly speaking, `query_lut` is of type `QueryLUT`.
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
//! `BitXor`. So we recreate our own `FheBool` in the `cipher_structs` module.
//! Then we rewrite:
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
//! (which_op       AND (left OR  right)) XOR
//! ((NOT which_op) AND (left AND right)) XOR
//! negate
//! ```
//! Which requires 7 PBS. When written using `+, *`, we obtain:
//! ```rust
//! which_op       * (left + right + left * right) +
//! (1 + which_op) * (left * right) +
//! negate
//! ```
//! which simplifies to:
//! ```rust
//! result = left * right + which_op * (left + right) + negate
//! ```
//! This requires two multiplications (thus 2 PBS), plus 3 additions.
//!
//! One can reduce to only one multiplication using de Morgan's law:
//!
//! $ a \text{ OR } b = \neg (\neg a \text{ AND } \neg b),$
//!
//! which can also be written as:
//!
//! $ a + b + ab = (a+1)(b+1) + 1 \thickspace (\text{mod } 2) $
//!
//! Replacing:
//! * $a$ by `left`,
//! * $b$ by`right`,
//! * $1$ by `which_op`,
//!
//! we get:
//! ```rust
//! result = (left + which_op) * (right + which_op) + which_op + negate
//! ```
//! which means 1 PBS, 4 additions.
//! This implicitly uses that:
//! ```
//! (which_op * which_op) = which_op    (mod 2)
//! ```
//!
//! <div class="warning">
//!
//! This analysis is not complete, because some PBS weren't accounted for:
//! 1. two PBS are necessary to fetch the values of `left, right`,
//! 2. one PBS is necessary to process the boolean `is_node`,
//! 3. some more PBS are needed to handle the `is_node == false` case.
//!
//! See at [`run_query_on_record`](TableQueryRunner::run_query_on_record)
//! for a full analysis.
//! </div>

use clap::Parser;
use sqlparser::ast::{Expr, SelectItem};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{gen_keys_radix, ClientKey, RadixClientKey, ServerKey};
use tfhe::shortint::{PBSParameters, ServerKey as ShortintSK, WopbsParameters};

mod cipher_structs;
mod clear;
mod distinct;
mod encoding;
mod query;
mod runner;
mod simplify_query;
mod tables;

use cipher_structs::FheBool;
use encoding::{decode_cell, decode_record};
use query::*;
use runner::{EncryptedResult, TableQueryRunner};
use tables::*;

use crate::runner::DbQueryRunner;

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

/// Encrypts a `sqlparser::ast::Select` query.
///
/// # Inputs
/// + a `query`,
/// + a `client_key`,
/// + a `shortint_sk` for initializing some (custom) [`FheBool`]s,
/// + a `headers` struct for turning column identifiers into indices.
#[allow(dead_code)]
fn encrypt_query<'a>(
    query: sqlparser::ast::Select,
    client_key: &'a ClientKey,
    shortint_sk: &'a ShortintSK,
    headers: &'a DatabaseHeaders,
) -> EncryptedQuery<'a> {
    query::parse_query(query, headers).encrypt(client_key, shortint_sk)
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

fn decrypt_result_to_hashmap(
    client_key: &RadixClientKey,
    result: &EncryptedResult,
    headers: DatabaseHeaders,
    query: ClearQuery,
) -> HashMap<String, u32> {
    let table_headers = headers.0[query.table_selection as usize].1.clone();

    let clear_projection = result
        .projection
        .iter()
        .map(|column_bool| (client_key.decrypt_one_block(column_bool) % 2) != 0)
        .collect::<Vec<bool>>();

    let record_in_result = result
        .is_record_in_result
        .iter()
        .map(|record_bool| (client_key.decrypt_one_block(record_bool) % 2) != 0)
        .collect::<Vec<bool>>();

    let mut hashmap: HashMap<String, u32> = HashMap::new();

    for (_, record) in result
        .content
        .iter()
        .enumerate()
        .filter(|(i, _)| record_in_result[*i])
    {
        let clear_record = record
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                if clear_projection[i] {
                    client_key.decrypt::<u64>(cell)
                } else {
                    0u64
                }
            })
            .collect::<Vec<_>>();

        let mut decoded_result: Vec<String> = Vec::new();

        for column_id in query.sql_projection.iter() {
            match column_id {
                SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                    let ident = id.value.clone();
                    let index = table_headers
                        .index_of(ident.clone())
                        .expect("Column identifier {ident} does not exist")
                        as usize;
                    let cell_type = table_headers.type_of(ident).unwrap();
                    let cell_len = cell_type.len();
                    let string_result =
                        decode_cell(cell_type, clear_record[index..(index + cell_len)].to_vec())
                        .to_string();
                    decoded_result.push(string_result);
                }
                SelectItem::Wildcard(_) => {
                    let string_result = clear_record_to_string(decode_record(
                        &table_headers,
                        clear_record,
                        vec![true; table_headers.len()].as_ref(),
                    ));
                    decoded_result = vec![string_result];
                    break;
                }
                s => panic!("Unsupported SelectItem: {s:?}"),
            }
        }

        let decoded_result = decoded_result.join(",");
        if let Some(u) = hashmap.get_mut(&decoded_result) {
            *u += 1;
        } else {
            hashmap.insert(decoded_result, 1);
        }
    }

    hashmap
}

fn result_hashmap_to_string(h: HashMap<String, u32>) -> String {
    let mut result_vec: Vec<String> = Vec::new();
    for (k, v) in h.iter() {
        // repeat the key as many times as it should appear in the result String
        result_vec.append(&mut vec![k.clone(); *v as usize]);
    }
    result_vec.join("\n")
}

/// The output of this function is a string using the CSV format.
#[allow(dead_code)]
fn decrypt_result(
    client_key: &RadixClientKey,
    result: &EncryptedResult,
    headers: DatabaseHeaders,
    query: ClearQuery,
) -> String {
    result_hashmap_to_string(decrypt_result_to_hashmap(
        client_key, result, headers, query,
    ))
}

#[allow(dead_code)]
fn default_cpu_parameters() -> PBSParameters {
    // uncomment the one you want to use
    use tfhe::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        // PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    };
    PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
    // PBSParameters::MultiBitPBS(PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS)
    // PBSParameters::MultiBitPBS(PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS)
}

/// Generates all necessary keys.
///
/// The integer `ServerKey` is cloned and turned into a shortint `ServerKey`.
#[allow(dead_code)]
fn generate_keys() -> (
    RadixClientKey,
    ServerKey,
    ShortintSK,
    WopbsKey,
    WopbsParameters,
) {
    // KeyGen...
    // (insert Waifu + 8-bit music here)
    let (ck, sk) = gen_keys_radix(default_cpu_parameters(), 16);
    // we will need access to the underlying shortint server key, which is
    // a private attribute, and can only be accessed by calling sk.into_raw_parts()
    let shortint_server_key = sk.clone().into_raw_parts();

    // WoPBS parameters for the lookup tables
    use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let wopbs_parameters = WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let wopbs_key = WopbsKey::new_wopbs_key(&ck, &sk, &wopbs_parameters);

    (ck, sk, shortint_server_key, wopbs_key, wopbs_parameters)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("KeyGen...");
    let (client_key, server_key, shortint_server_key, wopbs_key, wopbs_params) = generate_keys();
    println!("...done.\n");

    // parse cli args
    let db_dir_path = cli.input_db;
    let query_path = cli.query_file;

    // load db, parse query
    let db = load_tables(db_dir_path).expect("Failed to load DB at {db_dir_path}");
    let headers = db.headers();
    let query = parse_query_from_file(query_path, &headers);

    let query_runner = DbQueryRunner::new(
        &db,
        &server_key,
        &shortint_server_key,
        &wopbs_key,
        wopbs_params,
    );

    let encrypted_query = query.encrypt(client_key.as_ref(), &shortint_server_key);

    let timer = Instant::now();

    let ct_result = query_runner.run_query(&encrypted_query);
    let fhe_computation_result =
        decrypt_result_to_hashmap(&client_key, &ct_result, headers, query.clone());

    let total_time = timer.elapsed();

    println!(
        "Runtime: {}.{}s\n",
        total_time.as_secs(),
        total_time.subsec_millis() / 10
    );
    let clear_computation_hashmap = db.run_clear_query(query);
    println!(
        "Clear DB Result: \n{}\n",
        result_hashmap_to_string(clear_computation_hashmap.clone())
    );
    println!(
        "Encrypted DB Result:\n{}\n",
        result_hashmap_to_string(fhe_computation_result.clone())
    );

    println!(
        "Results match: {}",
        fhe_computation_result == clear_computation_hashmap
    );

    Ok(())
}
