<div align="center">
  <a>
    <img src="https://github.com/AIBlockOfficial/Chain/blob/develop/assets/hero.jpg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">双向链（Two Way Chain）</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/AIBlockOfficial/Chain/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  <img src="https://img.shields.io/crates/v/tw_chain" alt="Cargo Crates Version" style="display:inline-block" />
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

Blockchain 存储库包含了设置和与 AIBlock 区块链本地实例交互所需的全部代码。

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
tw_chain = "1.0.2"
```

或者，通过命令行：

```
cargo add tw_chain
```

