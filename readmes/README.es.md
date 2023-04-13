<div align="center">
  <a>
    <img src="https://github.com/Zenotta/NAOM/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">Notarised Append Only Memory (NAOM)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/Zenotta/NAOM/rust.yml" alt="Estado del pipeline" style="display:inline-block"/>
  </div>

  <p align="center">
    La cadena de bloques de doble entrada dual OG
    <br />
    <br />
    <a href="https://zenotta.io"><strong>Documentación oficial »</strong></a>
    <br />
    <br />
  </p>
</div>

El repositorio de NAOM contiene todo el código necesario para configurar e interactuar con una instancia local de la cadena de bloques Zenotta.

..

## Comenzando

La ejecución de NAOM asume que tiene instalado Rust y está utilizando un sistema Unix. Puede clonar este repositorio y ejecutar el `Makefile` para configurar todo para un entorno de desarrollo:

```
make
cargo build
cargo test
```

..

## Uso

La ejecución de `cargo run --bin main` actualmente mostrará todos los activos en la instancia local. No se pretende que NAOM se utilice directamente y, en su lugar, se pretende que se utilice desde otros programas que requieren acceso a la estructura de datos de la cadena de bloques.

..

## Referencias

- [BitML para Zenotta](https://github.com/Zenotta/NAOM/blob/main/docs/BitML_for_Zenotta.pdf)
- [Referencia de opcodes de ZScript](https://github.com/Zenotta/NAOM/blob/main/docs/ZScript_Opcodes_Reference.pdf)