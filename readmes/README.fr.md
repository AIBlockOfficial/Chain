<div align="center">
  <a>
    <img src="https://github.com/Zenotta/NAOM/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">Notarised Append Only Memory (NAOM)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/Zenotta/NAOM/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
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

Le dépôt NAOM contient tout le code nécessaire pour configurer et interagir avec une instance locale de la blockchain Zenotta.

..

## Commencer

L'exécution de NAOM suppose que vous avez installé Rust et que vous utilisez un système Unix. Vous pouvez cloner ce dépôt et exécuter le `Makefile` pour tout configurer pour un environnement de développement:

```
make
cargo build
cargo test
```

..

## Utilisation

L'exécution de `cargo run --bin main` listera actuellement tous les actifs sur l'instance locale. NAOM n'est généralement pas destiné à être utilisé directement, mais plutôt à être utilisé par d'autres programmes qui nécessitent un accès à la structure de données blockchain.

..

## Références

- [BitML pour Zenotta](https://github.com/Zenotta/NAOM/blob/main/docs/BitML_for_Zenotta.pdf)
- [Référence des opcodes ZScript](https://github.com/Zenotta/NAOM/blob/main/docs/ZScript_Opcodes_Reference.pdf)