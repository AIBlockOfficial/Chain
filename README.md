# Notarised Append Only Memory (NAOM)

The NAOM repo contains all the code needed to set up and interact with a local instance of the Zenotta blockchain. 
Other language options can be found here:

- [Française](https://gitlab.com/zenotta/naom/-/blob/master/README.fr.md)
- [Afrikaans](https://gitlab.com/zenotta/naom/-/blob/master/README.af.md)

If you'd like to help with translations, or spot a mistake, feel free to open a new merge request.

..

## Getting Started

Running NAOM assumes you have Rust installed and are using a Unix system. You can clone this repo and run the `Makefile` to set everything up for a development environment:

```
make
cargo build
cargo test
```

..

## Use

Running `cargo run --bin main` will currently list all assets on the local instance. NAOM is not generally intended to be
used directly, and is instead intended to be used from other programs that require access to the blockchain data 
structure.