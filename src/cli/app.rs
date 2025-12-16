use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{DefaultTerminal, Frame, style::{Color, Modifier, Style, Stylize as _}, symbols::border, text::{Line, Text}, widgets::{Block, Paragraph, Widget}};

#[derive(Debug, Default)]
pub struct App {
    quit: bool
}



impl App {
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.quit {
            terminal.draw(|frame| self.draw(frame));
            self.handle_events();
        }
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_events(&mut self) -> io::Result<()> {
        match event::read()? {
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event);
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => {
                self.exit();
            }
            _ => {}
        }
    }

    fn exit(&mut self) {
        self.quit = true;
    }
}

impl Widget for &App {
    fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer) {
        let title = Line::from("Password Manager");
        let instructions = Line::from(vec![
            " Scroll Up ".into(),
            "<Up>".blue().bold(),
            " Scroll down ".into(),
            "<Down>".blue().bold(),
            " Scroll Left ".into(),
            "<Left>".blue().bold(),
            " Scroll Right ".into(),
            "<Right>".blue().bold(),
            " Select ".into(),
            "<Space>".blue().bold(),
            " Quit ".into(),
            "<Q> ".blue().bold(),
        ]);
        let block = Block::bordered()
            .title(title.centered())
            .title_bottom(instructions.centered())
            .border_set(border::THICK);
        let counter_text = Text::from("Hello world!");

        Paragraph::new(counter_text)
            .centered()
            .block(block)
            .render(area, buf);
    }
}