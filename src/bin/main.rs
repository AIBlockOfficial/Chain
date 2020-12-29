//! App using NOAM library.

//use naom::db::display::list_assets;
use naom::primitives::asset::TokenAmount;

fn main() {
    // list_assets();
    let x = TokenAmount(53040400);
    println!("X: {}", x);
}
