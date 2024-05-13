<div align="center">
  <a>
    <img src="https://github.com/AIBlockOfficial/Chain/blob/develop/assets/hero.jpg" alt="Logo" style="width:100%;max-width:700px">
  </a>

  <h2 align="center">Two Way Chain (Blockchain)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/AIBlockOfficial/Chain/rust.yml" alt="Estado del pipeline" style="display:inline-block"/>
  <img src="https://img.shields.io/crates/v/tw_chain" alt="Cargo Crates Version" style="display:inline-block" />
  </div>

  <p align="center">
    La cadena de bloques de doble entrada dual OG
    <br />
    <br />
    <a href="https://a-block.io"><strong>Documentación oficial »</strong></a>
    <br />
    <br />
  </p>
</div>

El repositorio de Blockchain contiene todo el código necesario para configurar e interactuar con una instancia local de la cadena de bloques AIBlock.

..

## Comenzando

La ejecución de Blockchain asume que tiene instalado Rust y está utilizando un sistema Unix. Puede clonar este repositorio y ejecutar el `Makefile` para configurar todo para un entorno de desarrollo:

```
make
cargo build
cargo test
```

..

## Uso

Blockchain puede ser añadido a tu proyecto como una dependencia añadiendo lo siguiente a tu archivo `Cargo.toml`:

```toml
[dependencies]
tw_chain = "1.1.2"
```

O alternativamente, a través de la línea de comandos:

```
cargo add tw_chain
```

