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
    Le double double entrée blockchain OG
    <br />
    <br />
    <a href="https://a-block.io"><strong>Documentation officielle »</strong></a>
    <br />
    <br />
  </p>
</div>

Le dépôt Blockchain contient tout le code nécessaire pour configurer et interagir avec une instance locale de la blockchain AIBlock.

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
tw_chain = "1.0.1"
```

Ou bien, via la ligne de commande :

```
cargo add tw_chain
```

