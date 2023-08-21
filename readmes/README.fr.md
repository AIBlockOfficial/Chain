<div align="center">
  <a>
    <img src="https://github.com/ABlockOfficial/Chain/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">Notarised Append Only Memory (Blockchain)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/ABlockOfficial/Chain/rust.yml" alt="Pipeline Status" style="display:inline-block"/>

  <img src="https://img.shields.io/crates/v/naom" alt="Cargo Crates Version" style="display:inline-block" />
  </div>

  <p align="center">
    Le double double entrée blockchain OG
    <br />
    <br />
    <a href="https://zenotta.io"><strong>Documentation officielle »</strong></a>
    <br />
    <br />
  </p>
</div>

Le dépôt Blockchain contient tout le code nécessaire pour configurer et interagir avec une instance locale de la blockchain A-Block.

..

## Commencer

L'exécution de Blockchain suppose que vous avez installé Rust et que vous utilisez un système Unix. Vous pouvez cloner ce dépôt et exécuter le `Makefile` pour tout configurer pour un environnement de développement:

```
make
cargo build
cargo test
```

..

## Utilisation

Blockchain peut être ajouté à votre projet en tant que dépendance en ajoutant ce qui suit à votre fichier `Cargo.toml`:

```toml
[dependencies]
naom = "0.1.0"
```

Ou bien, via la ligne de commande :

```
cargo add naom
```

L'exécution de `cargo run --bin main` à partir d'un clone de référentiel répertorie actuellement tous les actifs de l'instance locale. Cependant, Blockchain n'est généralement pas destiné à être utilisé directement, mais plutôt à être utilisé à partir d'autres programmes qui nécessitent l'accès à la structure de données de la blockchain.

..

## Références

- [BitML pour A-Block](https://github.com/ABlockOfficial/Chain/blob/main/docs/BitML_for_Zenotta.pdf)
- [Référence des opcodes ZScript](https://github.com/ABlockOfficial/Chain/blob/main/docs/ZScript_Opcodes_Reference.pdf)