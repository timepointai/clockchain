// sqlx's migration macro tracks existing files, but Cargo must also notice new
// migrations. Without the directory dependency a cached feature build can omit
// a newly added table while another feature build includes it.
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
