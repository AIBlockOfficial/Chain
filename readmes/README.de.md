<div align="center">
  <!-- <a>
    <img src="https://github.com/AIBlockOfficial/Chain/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a> -->

  <h2 align="center">Two Way Chain (Blockchain)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/AIBlockOfficial/Chain/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  <img src="https://img.shields.io/crates/v/tw_chain" alt="Cargo Crates Version" style="display:inline-block" />
  </div>

  <p align="center">
    Die OG Dual Double Entry Blockchain
    <br />
    <br />
    <a href="https://a-block.io"><strong>Offizielle Dokumentation »</strong></a>
    <br />
    <br />
  </p>
</div>

Das Blockchain-Repo enthält den gesamten Code, der benötigt wird, um eine lokale Instanz der AIBlock-Blockchain einzurichten und mit ihr zu interagieren.

..

## Einstieg

Die Ausführung von Blockchain setzt voraus, dass Rust installiert ist und ein Unix-System verwendet wird. Sie können dieses Repository klonen und das `Makefile` ausführen, um alles für eine Entwicklungsumgebung einzurichten:

```
make
cargo build
cargo test
```

..

## Verwendung

Blockchain kann als Abhängigkeit zu Ihrem Projekt hinzugefügt werden, indem Sie Folgendes zu Ihrer `Cargo.toml`-Datei hinzufügen:

```toml
[dependencies]
tw_chain = "1.0.1"
```

Alternativ können Sie es auch über die Befehlszeile hinzufügen:

```
cargo add tw_chain
```

