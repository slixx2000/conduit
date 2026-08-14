// Release builds must not pop a console window behind the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    conduit_app_lib::run()
}
