<div align="center">
  <a>
    <img src="https://github.com/Zenotta/NAOM/blob/develop/assets/hero.svg" alt="Logo" style="width: 350px">
  </a>

  <h2 align="center">الذاكرة العاملة للملفات مع الإضافة الموثقة (Notarised Append Only Memory, NAOM)</h2> <div style="height:30px"></div>

  <div>
  <img src="https://img.shields.io/github/actions/workflow/status/Zenotta/NAOM/rust.yml" alt="Pipeline Status" style="display:inline-block"/>
  </div>

  <p align="center">
    سلسلة الكتل المزدوجة الأصلية
    <br />
    <br />
    <a href="https://zenotta.io"><strong>التوثيق الرسمي »</strong></a>
    <br />
    <br />
  </p>
</div>

يحتوي مستودع NAOM على جميع الأكواد اللازمة لإعداد والتفاعل مع نسخة محلية من سلسلة كتل Zenotta.

..

## البدء

يفترض تشغيل NAOM أن لديك Rust مثبتًا وأنت تستخدم نظام Unix. يمكنك استنساخ هذا المستودع وتشغيل `Makefile` لإعداد كل شيء لبيئة تطوير:

```
make
cargo build
cargo test
```

..

## الاستخدام

يتم تشغيل `cargo run --bin main` حاليًا لإدراج جميع الأصول على النسخة المحلية. لا يُقصد استخدام NAOM مباشرةً ، وإنما يُقصد استخدامها من برامج أخرى تتطلب الوصول إلى بنية البيانات لسلسلة الكتل.

..

## المراجع

- [BitML for Zenotta](https://github.com/Zenotta/NAOM/blob/main/docs/BitML_for_Zenotta.pdf)
- [ZScript Opcodes Reference](https://github.com/Zenotta/NAOM/blob/main/docs/ZScript_Opcodes_Reference.pdf)