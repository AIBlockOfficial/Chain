<div align="center">
  <a>
    <img src="https://github.com/AIBlockOfficial/Chain/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">Notarised Append Only Memory (Blockchain)</h2> <div style="height:30px"></div>

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
tw_chain = "0.1.0"
```

Alternativ können Sie es auch über die Befehlszeile hinzufügen:

```
cargo add tw_chain
```

Wenn Sie `cargo run --bin main` aus einem geklonten Repository ausführen, werden derzeit alle Vermögenswerte in der lokalen Instanz aufgelistet. Blockchain ist jedoch normalerweise nicht dafür vorgesehen, direkt verwendet zu werden, sondern soll von anderen Programmen genutzt werden, die Zugriff auf die Datenstruktur der Blockchain benötigen.
