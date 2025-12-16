use std::{fs::remove_file, io};

use crate::cli::app::App;

mod passwords;
mod encryption;
mod authentication;
mod cli;


fn main() -> io::Result<()> {
    let mut terminal = ratatui::init();
    let app_result = App::default().run(&mut terminal);
    ratatui::restore();
    app_result
}
