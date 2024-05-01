Computes encrypted queries homomorphically.

# Main logic

## Client
1. A provided query is parsed and converted to a structure named
`U64SyntaxTree`. The only type handled by this structure is `u64`: strings
are considered to be of type `[u8; 32]`, and are converted to `[u64; 4]`.
See [Encoding `value`](#encoding-value) for more details.
2. The query is then optimized using the
[`egg`](https://egraphs-good.github.io/) crate, so as to remove
"pathological" queries such as `some_uint < 0`.
3. The result is encoded into a vector `Vec<EncodedInstruction>`, which
transforms binary operators like `<, =, >=, !=` into formulas where only
the two operators `=, <=` are used. See [Encoding `op`](#encoding-op) for more.
4. The output vector is then encrypted and sent to the server.

## Server
A provided database is handled as a structure `Database`, which is a list of
`Table`s. Each table is then used to build a
`TableQueryRunner`, which provides the `run_fhe_query` method. This method:
1. runs the encrypted query on the table, ignoring the optional `DISTINCT` flag,
2. post-process the result to make it compliant with that flag.

This two-step process allows for parallel computation of each table entry at
step 1.  Step 2 is mainly a cmux tree of depth equals to the number of
columns: the only other operations done during this step are computing sums
of ciphertexts, which should not be too expensive (in terms of cpu load).
See the docs for `TableQueryRunner::is_entry_already_in_result`.

## Documentation
As much of this project's logic is dictated by how a query is encrypted and
how computations over booleans are handled, both are described here. See
the paragraphs:
+ [Query encoding and encryption](#query-encoding-and-encryption), and
+ [Evaluating an encrypted syntax tree](#evaluating-an-encrypted-syntax-tree),

respectively.

## Comments on the chosen architecture
### Handling only `u64`s
One could choose to handle only `u256`s so that `ShortString` are simply
cast into that type.  However, every other types would also be cast into
`u256`, resulting in a big performance hit if most values are not
`ShortString`.

On the other hand, casting `ShortString` as four `u64` means that conditions
like `some_str = "something"` are cast into
```
s0 = "<something0>" AND s1 = ... AND s3 = "<something3>"
```
which means evaluating 7 instructions:
* 1 for each `s0, ..., s3`, and
* 1 for each `AND`.

Thus this choice is less performant when the database has mostly
`ShortString`s.

## Encoding the `WHERE` condition
This condition is a boolean formula, represented as a syntax tree. When
trying to encrypt such a syntax tree, one stumbles on a problem:
representing structured data in an encrypted form is hard.

One could try to transform such data into a canonical, unstructured one
(like a Conjunctive/Disjunctive Normal Form), but such transformation can
[blow
up](https://en.wikipedia.org/wiki/Conjunctive_normal_form#Other_approaches)
the size of the query.

One way around it is to define [new
variables](https://en.wikipedia.org/wiki/Tseytin_transformation), but this
is equivalent to storing the structured data and saving the output of each
boolean gate in a temporary register. This is the approach taken in this
project.

Once again, if the queries are assumed to be "small" when written in
Conjunctive/Disjunctive Normal Form, then this choice is less performant,
and better otherwise.

> [!NOTE]
> **Notation**
> As performing arbitrary boolean circuit and using registers to store
> values sounds a lot like a minimal processor, each element of an
> `EncryptedSyntaxTree` is called an "instruction".

# Structure of the project
This project is divided in the following modules:

### `query`
Handles converting a `sqlparser::ast::Select` into an internal
representation of the syntax tree, as well as encoding it into a vector of
tuples:
```rust
type EncodedInstruction = (bool, u8, bool u64, bool)
```
and encrypting the result.

### `simplify_query`
Defines a simple `QueryLanguage` to be used by the `egg` crate. Also adds
methods to `U64SyntaxTree` to convert it to an instance of `QueryLanguage`,
and to convert it back to the initial type.

### `encoding`
Primitives for encoding different types to `u64`, or `[u64; 4]`.

### `tables`
Handles the representation of tables, entries, and cells.

### `runner`
Provides the `TableQueryRunner` and `DbQueryRunner` types for running
the FHE query.

### `distinct`
Implements methods for handling the `DISTINCT` flag.

### `cipher_structs`
Contains the definition of a few structures handling encrypted data.
Here are the structures defined there:

#### `EntryLUT`
A lookup table for handling FHE computations of functions `u8 -> u64`.

#### `FheBool`
A wrapper for `Ciphertext` which implements the `Add, Mul, Not` traits. A
boolean is represented by an integer modulo 2, and as a `Ciphertext`
encrypts an integer modulo 4, we remove the degree checks on
addition/multiplication, but keep the noise checks. See `FheBool`
implementation of `add_assign` and its method
`binary_smart_op_optimal_cleaning_strategy`.

#### `QueryLUT`
A lookup table for handling FHE computations of functions `u8 -> FheBool`.
This requires rewriting quite a few methods from `tfhe::integer::WopbsKey`
and `tfhe::core_crypto` modules. The modified methods from `WobsKey` are
put in the `query_lut` module, while those from
`core_crypto` are put in the
`recursive_cmux_tree` module.

# Query encoding and encryption
A query is internally represented by the `U64SyntaxTree` structure. It's designed
to represent essentially two cases:
1. an atom, which is a statement of the form `column_id op value` where
   `column_id` is an identifier, `op` is a comparison operator like `=, <,
   !=`, and `value` is of type `u64`.
2. a node `n1 op n2` where bot `n1` and `n2` are of type `U64SyntaxTree`,
   and `op` is one of `AND, NAND, OR, NOR`.

The result of encoding such queries is a `Vec<EncodedInstruction>`, where
```rust
type EncodedInstruction = (bool, u8, bool, u64, bool);
```
Let `(is_node, left, which_op, right, negate) = instr` be an
`EncodedInstruction`. The boolean `is_node` is for specifying wether `instr`
encodes a node or an atom.

## Node encoding
A node is a boolean operator of arity two, where:
- `which_op` encodes the choice between `OR` (`true`) and `AND` (`false`),
- `negate` encodes negation of the resulting boolean, ie the choice between
  `AND` and `NAND`, or `OR` and `NOR`,
- its two arguments are encoded as two indices `i1` and `i2`, which refer to
  other encoded instructions in the vector.

For example:
```rust
let encoded_query = vec![
  todo!(), // encoding of first atom
  todo!(), // encoding of second atom
  (true, 0, true, 1, false), // encoding of "encoded_query[0] OR encoded_query[1]"
];
```
Here the last element of `encoded_query` refers to two atoms at index `0` and
`1` in `encoded_query`.

All in all, an `EncodedInstruction` of the form:
```rust
(true, i1, which_op, i2, negate)
```
encodes the following instruction:
```
(encoded_query[i1] OP encoded_query[i2]) XOR negate
```
where `OP` is either `AND` or `OR` depending on `which_op`.

## Atom encoding
An atom is an expression of the form `column_id op value` where:
- `column_id: u8` is the index of a column in a table,
- `op` is one of `<, <=, =, >=, >, !=`,
- `value` is a value of type one of `bool, u8, u16, u32, u64, i8, i16, i32,
i64, ShortString`.

### Encoding `column_id`
To each column identifier is associated a single index of type `u8` (except
those of type `ShortString` which define four indices). This is done by the
method `TableHeaders::index_of`.

### Encoding `op`
We define the boolean `which_op` to encode the choice between `<=` (`true`)
and `=` (`false`). We then use basic logical equivalences to encode `op`
with only two booleans `which_op, negate`:
- $a < b  \iff a \leq b-1$
- $a > b  \iff \neg(a \leq b)$
- $a \not= b \iff \neg(a = b)$
- $a \geq b \iff \neg(a \leq b-1)$

We thus encode the pair `(op, value)` as a tuple `(which_op, negate,
encoded_val)` as follows:
```rust
let (which_op, negate, encoded_val) = match op {
     "="  => (false, false, value),
     "!=" => (false, true,  value),
     "<=" => (true,  false, value),
     ">"  => (true,  true,  value),
     "<"  => (true,  false, value - 1),
     ">=" => (true,  true,  value - 1),
}
```

> [!WARNING]
> Modifying the `value` fails in essentially two corner cases:
> 1. when processing `column_id < 0` where `column_id` is an unsigned
> integer,
> 2. when processing `column_id >= 0` where `column_id` is an unsigned
> integer.
> 
> Thus simplifying such trivial queries is required before encoding. See
> [`simplify_query`].

### Encoding `value`
Every value in an encoded instruction is of type `u64`. Casting unsigned integers
and booleans to `u64` is straightforward.

#### Encoding a `ShortString`
The type `ShortString` is a vector of 32 bytes, ie `[u8; 32]`. During
encoding, a value of type `ShortString` is cast as four `u64`s, so as a
value of type `[u64; 4]`.

#### Casting a signed integer to an `u64`
An `i64` can be cast to an `u64`, however such a casting is not compatible with
boolean expressions like `-1 < 0` (this evaluates to `true`, but `(-1 as u64) < 0_u64` doesn't).
So to obtain an embedding compatible with the order on signed and unsigned integers, we
simply negate the most significant bit:
```rust
let cast_to_u64 = |i: i64| (i as u64) ^ (1 << 63);
```

## Encrypting an `EncodedInstruction`
We just encrypt each element of the tuple. The output type is then:
```rust
(Ciphertext, RadixCiphertext, Ciphertext, RadixCiphertext, Ciphertext)
```
The first `RadixCiphertext` has 4 blocks, while the second has 32.

# Evaluating an encrypted syntax tree
## Hidden lookup tables
When performing a SQL query homomorphically, we run the encrypted query on
each entry.

Let `n` be the length of the encoded query. The
`TableQueryRunner::run_query_on_entry`
method first creates a vector `query_lut: Vec<Ciphertext>`, of size `n`,
then write the (encrypted) result of each instruction into it.

> [!WARNING]
> Strictly speaking, `query_lut` is of type `QueryLUT`.

As an instruction can refer to other
instructions in the encoded query, we need to homomorphically evaluate a
function `u8 -> Ciphertext`, also called a "hidden lookup table".  This is
done in the `query_lut` module.

## Replacing boolean operators with addition and multiplication mod 2
We note the following:
1. Addition of ciphertexts is much faster than doing a PBS,
2. Let $a,b \in \mathbb{Z}/2\mathbb{Z}$. Then:
    + $a+1 = \text{NOT } a$,
    + $a+b = a \text{ XOR } b$,
    + $a \times b = a \text{ AND } b$.

However, `tfhe::FheBool` uses lookup tables for its implementation of
`BitXor` and `Not`. So we recreate our own `FheBool` in the `cipher_structs`
module. Then we rewrite:

$(a \text{ OR } b) \rightarrow (a + b + a \times b)$

and simplify the resulting formulas.
This reduces the number of PBS performed.

## Example
Let's  give the boolean formula for evaluating an instruction of the form:
```rust
(true, i_l, which_op, i_r, negate)
```
This thus encodes a node. Let `left, right` be the two booleans that `i_l, i_r` refer to.
The result boolean is then:
```
(which_op       AND (left OR  right)) XOR
((NOT which_op) AND (left AND right)) XOR
negate
```
Which requires 7 PBS. When written using `+, *`, we obtain:
```rust
which_op       * (left + right + left * right) +
(1 + which_op) * (left * right) +
negate
```
which simplifies to:
```rust
result = left * right + which_op * (left + right) + negate
```
This requires two multiplications (thus 2 PBS), plus 3 additions.

One can reduce to only one multiplication using de Morgan's law:

``` math
a \text{ OR } b = \neg (\neg a \text{ AND } \neg b),
```

which can also be written as:

``` math
 a + b + ab = (a+1)(b+1) + 1 \thickspace (\text{mod } 2)
```

Replacing:
* $a$ by `left`,
* $b$ by`right`,
* $1$ by `which_op`,

we get:
```rust
result = (left + which_op) * (right + which_op) + which_op + negate
```
which means 1 PBS, 4 additions.
This implicitly uses that:
```math
\texttt{which_op} * \texttt{which_op} = \texttt{which_op}    (mod \; 2)
```

> [!WARNING]
> This analysis is not complete, because some PBS weren't accounted for:
> 1. two PBS are necessary to fetch the values of `left, right`,
> 2. one PBS is necessary to process the boolean `is_node`,
> 3. some more PBS are needed to handle the `is_node == false` case.

See the docs at `run_query_on_entry` for a full analysis.
