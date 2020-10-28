# Notarised Append Only Memory (NAOM)

Le repo NAOM contient tout le code nécessaire pour mettre en place et interagir avec une instance locale du blockchain Zenotta. 
D'autres options linguistiques peuvent être trouvées ici:

- [English](https://gitlab.com/zenotta/naom/README.md)
- [Afrikaans](https://gitlab.com/zenotta/naom/README.af.md)

Si vous souhaitez aider à la traduction, ou repérer une erreur, n'hésitez pas à ouvrir une nouvelle merge request.

..

## Pour Commencer

Afin de vous mettre au travail avec NAOM, vous pouvez cloner ce repo et exécuter le `Makefile` afin de tout mettre en place pour un environnement de développement sous Unix:

```
make
cargo build
cargo test
```

..

## Utilisez

L'exécution de `cargo run` permet de lister tous les actifs de l'instance locale. NAOM n'est généralement pas destiné à être 
utilisé directement, et est plutôt destiné à être utilisé à partir d'autres programmes qui nécessitent l'accès aux données de la blockchain structure.