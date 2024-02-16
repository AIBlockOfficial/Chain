<div align="center">
  <a>
    <img src="https://github.com/ABlockOfficial/Chain/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">公证追加存储器（Notarised Append Only Memory，Blockchain）</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/ABlockOfficial/Chain/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  <img src="https://img.shields.io/crates/v/a_block_chain" alt="Cargo Crates Version" style="display:inline-block" />
  </div>

  <p align="center">
    原始双重输入区块链
    <br />
    <br />
    <a href="https://a-block.io"><strong>官方文档 »</strong></a>
    <br />
    <br />
  </p>
</div>

Blockchain 存储库包含了设置和与 A-Block 区块链本地实例交互所需的全部代码。

..

## 入门

运行 Blockchain 假设您已经安装了 Rust 并正在使用 Unix 系统。您可以克隆此存储库并运行 `Makefile` 来为开发环境设置一切：

```
make
cargo build
cargo test
```

..

## 使用

您可以通过在 `Cargo.toml` 文件中添加以下内容将Blockchain作为依赖项添加到您的项目中：

```toml
[dependencies]
a_block_chain = "0.1.0"
```

或者，通过命令行：

```
cargo add a_block_chain
```

从repo clone运行 `cargo run --bin main` 目前将列出本地实例中的所有资产。但Blockchain通常不会直接使用，而是旨在用于需要访问区块链数据结构的其他程序中
