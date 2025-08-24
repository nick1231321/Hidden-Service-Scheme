# Anonymous Server Project

This project contains multiple Rust binaries that can be built using Cargo.  

## Binaries
- `anonymous_server`
- `authority_server`
- `client`

## Building

To compile each binary, run:

```bash
cargo build --bin anonymous_server
cargo build --bin authority_server
cargo build --bin client
```

For optimized release builds:

```bash
cargo build --release --bin anonymous_server
cargo build --release --bin authority_server
cargo build --release --bin anonymous
```

The resulting binaries will be placed in `target/release`.

## Running

You can run the binaries directly with Cargo:

```bash
cargo run --bin anonymous_server
cargo run --bin authority_server
cargo run --bin anonymous
```

## Troubleshooting

### Error: `the trait bound 'SURB: Clone' is not satisfied`

If you see an error like this when building:

```
error[E0277]: the trait bound `SURB: Clone` is not satisfied
   --> common/nymsphinx/anonymous-replies/src/reply_surb.rs:59:5
    |
57  | #[derive(Debug, Clone)]
    |                ^^^^^ the trait `Clone` is not implemented for `SURB`
```

**Fix:**
1. Locate the file `sphinx-packet-0.6.0.zip` inside the project **SDK** folder.
2. Extract it into your Cargo registry folder:
   - **Linux/macOS:**  
     `~/.cargo/registry/`
   - **Windows:**  
     `C:\Users\<your-username>\.cargo\registry\`
3. Make sure the extracted folder is named exactly:  
   `sphinx-packet-0.6.0`

After extraction, re-run the build commands.

## Demo Video

A video of running the scheme can be seen here:  
[Watch on YouTube](https://www.youtube.com/watch?v=7HcXZiQ-IRs)

## Requirements
- [Rust](https://www.rust-lang.org/tools/install) (latest stable recommended)
- Cargo (comes with Rust)

---
