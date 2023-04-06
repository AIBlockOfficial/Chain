<div id="top"></div>

<!-- PROJECT LOGO -->
<br />

<div align="center">
  <!-- <a>
    <img src="https://github.com/Zenotta/ZenottaJS/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a> -->

  <h2 align="center">Notarised Append Only Memory (NAOM)</h2>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/Zenotta/NAOM/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
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

The NAOM repo contains all the code needed to set up and interact with a local instance of the Zenotta blockchain.

[简体中文](https://github.com/Zenotta/NAOM/blob/develop/readmes/README.zhs.md) | [Español](https://github.com/Zenotta/NAOM/blob/develop/readmes/README.es.md) | [عربي ](https://github.com/Zenotta/NAOM/blob/develop/readmes/README.ar.md)| [Deutsch](https://github.com/Zenotta/NAOM/blob/develop/readmes/README.de.md) | [Français](https://github.com/Zenotta/NAOM/blob/develop/readmes/README.fr.md)

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

..

## References

- [BitML for Zenotta](https://github.com/Zenotta/NAOM/blob/main/docs/BitML_for_Zenotta.pdf)
- [ZScript Opcodes Reference](https://github.com/Zenotta/NAOM/blob/main/docs/ZScript_Opcodes_Reference.pdf)