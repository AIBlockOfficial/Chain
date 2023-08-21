<div id="top"></div>

<!-- PROJECT LOGO -->
<br />

<div align="center">
  <a>
    <!-- <img src="https://github.com/ABlockOfficial/Chain/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px"> -->
  </a>

  <h2 align="center">A-Block Chain</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/ABlockOfficial/Chain/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  <img src="https://img.shields.io/crates/v/naom" alt="Cargo Crates Version" style="display:inline-block" />
  </div>

  <p align="center">
    The OG dual double entry blockchain
    <br />
    <br />
    <a href="https://zenotta.io"><strong>Official documentation »</strong></a>
    <br />
    <br />
  </p>
</div>

The Blockchain repo contains all the code needed to set up and interact with a local instance of the A-Block blockchain.

[简体中文](https://github.com/ABlockOfficial/Chain/blob/develop/readmes/README.zhs.md) | [Español](https://github.com/ABlockOfficial/Chain/blob/develop/readmes/README.es.md) | [عربي ](https://github.com/ABlockOfficial/Chain/blob/develop/readmes/README.ar.md)| [Deutsch](https://github.com/ABlockOfficial/Chain/blob/develop/readmes/README.de.md) | [Français](https://github.com/ABlockOfficial/Chain/blob/develop/readmes/README.fr.md)

..

## Getting Started

Running Blockchain assumes you have Rust installed and are using a Unix system. You can clone this repo and run the `Makefile` to set everything up for a development environment:

```
make
cargo build
cargo test
```

..

## Use

Blockchain can be added to your project as a dependency by adding the following to your `Cargo.toml` file:

```toml
[dependencies]
naom = "0.1.0"
```

Or alternatively, via command line:

```
cargo add naom
```

Running `cargo run --bin main` from a repo clone will currently list all assets on the local instance. Blockchain is not generally intended to be
used directly though, and is instead intended to be used from other programs that require access to the blockchain data 
structure.

..

## References

- [BitML for A-Block](https://github.com/ABlockOfficial/Chain/blob/main/docs/BitML_for_Zenotta.pdf)
- [ZScript Standard Opcodes](https://github.com/ABlockOfficial/Chain/blob/main/docs/ZScript_Standard_Opcodes.pdf)
