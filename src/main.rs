use std::path::PathBuf;
use tfhe::integer::gen_keys_radix;
use tfhe::integer::{wopbs::WopbsKey, RadixClientKey, ServerKey};
use tfhe::shortint::Ciphertext;

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

fn generate_keys() -> (RadixClientKey, ServerKey, WopbsKey) {
    // KeyGen...
    // (insert Waifu here)

    use tfhe::shortint::parameters::{
        parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    };
    let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 16);
    let wopbs_key = WopbsKey::new_wopbs_key(&ck, &sk, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    (ck, sk, wopbs_key)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let (mut client_key, mut server_key, mut wopbs_key) = generate_keys();

    // let query_path = PathBuf::from("query.txt");
    // let query = build_where_syntax_tree(parse_query(query_path));
    // let dnf = query.disjunctive_normal_form();

    // println!("initial query: \n{}\n", query.to_string());
    // println!("dnf query: \n{}\n", dnf.to_string());

    // let db_dir_path = "db_dir";
    // let tables = load_tables(db_dir_path.into(), &server_key, &wopbs_key)
    //     .expect("Failed to load DB at {db_dir_path}");
    // let (_, table) = tables.0[0].clone();
    // let headers = table.headers.clone();
    // println!("headers: {:?}\n", headers);

    // let encrypted_query = dnf.encrypt(&client_key, &headers);
    // let encoded_table = EncodedTable::from(table);

    // let ct_result = encoded_table.run_fhe_query(encrypted_query, &server_key, &wopbs_key);
    // let clear_result = ct_result
    //     .into_iter()
    //     .map(|ct_bool: Ciphertext| client_key.decrypt_one_block(&ct_bool))
    //     .collect::<Vec<bool>>();

    // println!("result: {clear_result:?}");

    Ok(())
}

#[cfg(test)]
mod tests {

    use tfhe::boolean::client_key;

    use super::*;
    // use query::*;

    // #[test]
    // fn test_switch_sign() {
    //     use tfhe::core_crypto::commons::traits::UnsignedInteger;
    //     let minus_one = -1i8;
    //     let unsigned = (minus_one as u32) ^ (1 << 31);
    //     println!("{}", unsigned.to_bits_string(4));
    //     assert!(false);
    // }

    #[test]
    fn encrypt_u8() {
        println!("generating FHE keys...");
        let (client_key, _server_key, _) = generate_keys();
        let client_key = client_key.as_ref();
        println!("DONE");
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
        println!("generating FHE keys...");
        let (client_key, _server_key, _) = generate_keys();
        let client_key = client_key.as_ref();
        println!("DONE");
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

    #[test]
    fn encrypt_atomic_condition() {
        println!("generating FHE keys...");
        let (client_key, _server_key, _) = generate_keys();
        let client_key = client_key.as_ref();
        println!("DONE");
        let headers = TableHeaders(vec![(String::from("age"), CellType::U32)]);
        let condition: AtomicCondition = AtomicCondition {
            ident: "age".into(),
            op: ComparisonOp::GreaterEqual,
            value: CellContent::U32(890),
        };
        println!("encrypting condition: {condition:?}...");
        let _encrypted_cond = condition.encrypt(client_key, &headers);
        // println!("decrypting...");
        // let decrypted_cond: Vec<u8> = decrypt_vec(encrypted_cond, client_key);
    }

    // #[test]
    // fn load_db() {
    //     let db_dir_path = "db_dir";
    //     let tables = load_tables(db_dir_path.into()).expect("Failed to load DB at {db_dir_path}");
    //     let (name0, table0) = &tables.0[0];
    //     let (name1, table1) = &tables.0[1];
    //     println!("{name0}\n{table0:?}");
    //     println!("\n{name1}\n{table1:?}");
    // }
}
