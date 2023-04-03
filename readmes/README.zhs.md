<div align="center">
  <!-- <a>
    <img src="https://github.com/Zenotta/ZenottaJS/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a> -->

  <h2 align="center">公证追加存储器（Notarised Append Only Memory，NAOM）</h2>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/Zenotta/NAOM/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  </div>

  <p align="center">
    原始双重输入区块链
    <br />
    <br />
    <a href="https://zenotta.io"><strong>官方文档 »</strong></a>
    <br />
    <br />
  </p>
</div>

NAOM 存储库包含了设置和与 Zenotta 区块链本地实例交互所需的全部代码。

..

## 入门

运行 NAOM 假设您已经安装了 Rust 并正在使用 Unix 系统。您可以克隆此存储库并运行 `Makefile` 来为开发环境设置一切：

```
make
cargo build
cargo test
```

..

## 使用

运行 `cargo run --bin main` 将列出本地实例上的所有资产。NAOM 通常不打算直接使用，而是打算被其他需要访问区块链数据结构的程序使用。

..

## 参考

- [Zenotta 的 BitML](https://github.com/Zenotta/NAOM/blob/main/docs/BitML_for_Zenotta.pdf)
- [ZScript 操作码参考](https://github.com/Zenotta/NAOM/blob/main/docs/ZScript_Opcodes_Reference.pdf)