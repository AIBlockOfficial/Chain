<div align="center">
  <a>
    <img src="https://github.com/AIBlockOfficial/Chain/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">الذاكرة العاملة للملفات مع الإضافة الموثقة (Notarised Append Only Memory, Blockchain)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/AIBlockOfficial/Chain/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  <img src="https://img.shields.io/crates/v/tw_chain" alt="Cargo Crates Version" style="display:inline-block" />
  </div>

  <p align="center">
    سلسلة الكتل المزدوجة الأصلية
    <br />
    <br />
    <a href="https://a-block.io"><strong>التوثيق الرسمي »</strong></a>
    <br />
    <br />
  </p>
</div>

يحتوي مستودع Blockchain على جميع الأكواد اللازمة لإعداد والتفاعل مع نسخة محلية من سلسلة كتل AIBlock.

..

## البدء

يفترض تشغيل Blockchain أن لديك Rust مثبتًا وأنت تستخدم نظام Unix. يمكنك استنساخ هذا المستودع وتشغيل `Makefile` لإعداد كل شيء لبيئة تطوير:

```
make
cargo build
cargo test
```

..

## الاستخدام

يمكن إضافة Blockchain إلى مشروعك كتبعيّنة عن طريق إضافة ما يلي إلى ملف `Cargo.toml` الخاص بك:

```toml
[dependencies]
tw_chain = "0.1.0"
```

أو بديلًا ، عبر سطر الأوامر:

```
cargo add tw_chain
```

تشغيل `cargo run --bin main` من استنساخ مستودع سيستعرض حاليًا جميع الأصول الموجودة في النسخة المحلية. لا يتم تصميم Blockchain بشكل عام للاستخدام مباشرة ، ولكن من المقصود استخدامه من خلال برامج أخرى تتطلب الوصول إلى بنية بيانات سلسلة الكتل.