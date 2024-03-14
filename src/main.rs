use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::{fs::read_to_string, path::PathBuf};
// use tfhe::boolean::client_key;
use tfhe::prelude::*;
use tfhe::shortint::PBSParameters;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint32};

mod query;
mod tables {
    //! This module holds various types related to the handling of SQL tables.
    //! They are represented as a vector of entries, which are themselves just a
    //! vector of `CellContent`s, which hold each value in that table.
    //!
    //! The main function is `load_tables`, which reads a database from disk.
    //!
    //! The type `CellContent` is also used in the `query` module, so some methods are defined
    //! to encrypt a `CellContent` with a `ClientKey`.
}

use query::WhereSyntaxTree;
use tables::*;

fn parse_query(path: PathBuf) -> Statement {
    let dialect = GenericDialect {};
    let str_query = read_to_string(path.clone()).expect(
        format!(
            "Could not load query file at {}",
            path.to_str().expect("invalid Unicode for {path:?}")
        )
        .as_str(),
    );
    let ast = Parser::parse_sql(&dialect, &str_query).unwrap();
    ast[0].clone()
}

fn build_where_syntax_tree(statement: Statement) -> WhereSyntaxTree {
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => WhereSyntaxTree::from(s.selection.clone().unwrap()),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}

fn default_cpu_parameters() -> PBSParameters {
    PBSParameters::PBS(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS)
}

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

fn vec_u32_to_string(v: Vec<u32>) -> String {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = default_cpu_parameters();
    let config = ConfigBuilder::default()
        .use_custom_parameters(params, None)
        .build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    // On the server side:
    set_server_key(server_keys);

    let query_path = PathBuf::from("query.txt");
    let query = build_where_syntax_tree(parse_query(query_path));
    let cnf = query.conjuntive_normal_form();

    println!("initial query: \n{}\n", query.to_string());
    println!("cnf query: \n{}\n", cnf.to_string());

    let db_dir_path = "db_dir";
    let tables = load_tables(db_dir_path.into()).expect("Failed to load DB at {db_dir_path}");
    let (_, table) = &tables.0[0];
    println!("headers: {:?}\n", &table.headers);

    let encrypted_query = cnf.encrypt(&client_key, &table.headers);

    println!("length: {:?}", encrypted_query.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use query::*;

    #[test]
    fn encrypt_u8() {
        println!("generating FHE keys...");
        let params = default_cpu_parameters();
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None)
            .build();

        // Key generation
        let (client_key, _server_keys) = generate_keys(config);
        println!("DONE");
        let content: u8 = 5;
        let cell: CellContent = CellContent::U8(content);
        println!("encrypting content: {cell:?}...");
        let encrypted_cell = cell.encrypt(&client_key);
        println!("decrypting...");
        let decrypted_cell: u8 = encrypted_cell[0].decrypt(&client_key);
        assert_eq!(content, decrypted_cell);
    }

    #[test]
    fn encrypt_short_string() {
        println!("generating FHE keys...");
        let params = default_cpu_parameters();
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None)
            .build();

        // Key generation
        let (client_key, _server_keys) = generate_keys(config);
        println!("DONE");
        let content: String = "test".into();
        let cell: CellContent = CellContent::ShortString(content.clone());
        println!("encrypting content: {cell:?}...");
        let encrypted_cell = cell.encrypt(&client_key);
        println!("decrypting...");
        let decrypted_cell: Vec<u32> = decrypt_vec(encrypted_cell, &client_key);
        let string_decrypted_cell = vec_u32_to_string(decrypted_cell);
        assert_eq!(content, string_decrypted_cell);
    }

    #[test]
    fn encrypt_atomic_condition() {
        println!("generating FHE keys...");
        let params = default_cpu_parameters();
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None)
            .build();
        // Key generation
        let (client_key, _server_keys) = generate_keys(config);
        println!("DONE");
        let headers = TableHeaders(vec![(String::from("age"), CellType::U32)]);
        let condition: AtomicCondition = AtomicCondition {
            ident: "age".into(),
            op: ComparisonOp::GreaterEqual,
            value: CellContent::U32(890),
        };
        println!("encrypting condition: {condition:?}...");
        let encrypted_cond = condition.encrypt(&client_key, &headers);
        // println!("decrypting...");
        // let decrypted_cond: Vec<u8> = decrypt_vec(encrypted_cond, &client_key);
    }

    #[test]
    fn load_db() {
        let db_dir_path = "db_dir";
        let tables = load_tables(db_dir_path.into()).expect("Failed to load DB at {db_dir_path}");
        let (name0, table0) = &tables.0[0];
        let (name1, table1) = &tables.0[1];
        println!("{name0}\n{table0:?}");
        println!("\n{name1}\n{table1:?}");
    }
}
