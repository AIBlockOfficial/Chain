# Notarised Append Only Memory (NAOM)

Die NAOM repo bevat al die nodige kode om 'n plaaslike instansie van die Zenotta blockchain op te stel en te kommunikeer. 
Ander taalopsies kan hier gevind word:

- [English](https://gitlab.com/zenotta/naom/README.md)
- [Française](https://gitlab.com/zenotta/naom/README.fr.md)

As jy met vertalings wil help, of as jy 'n fout sien, open dan gerus 'n nuwe merge request.

..

## Aan die Gang Kom

Om aan die gang te kom met NAOM, kan jy hierdie repo kloon en die program uitvoer om alles vir 'n
ontwikkelingsomgewing in Unix te maak:

```
make
cargo build
cargo test
```

..

## Gebruik

As jy `cargo run` uitvoer, word tans alle bates in die plaaslike instansie gelys. NAOM is gewoonlik nie bedoel om direk te 
gebruik nie, en is eerder bedoel om gebruik te word van ander programme wat toegang tot die blockchain-datastruktuur benodig.