//! Process-wide styling for interactive prompts (inquire).

use inquire::ui::{Attributes, Color, RenderConfig, StyleSheet, Styled};

/// The prompt theme. Monochrome like the website: white on near-black
/// with gray secondary text, no color accents. The `▸` marker matches
/// the `min dash` TUI's selection cursor.
pub fn theme() -> RenderConfig<'static> {
    let mut config = RenderConfig::default()
        .with_prompt_prefix(Styled::new("▸").with_fg(Color::White))
        .with_highlighted_option_prefix(Styled::new("▸").with_fg(Color::White))
        .with_selected_option(Some(
            StyleSheet::new()
                .with_fg(Color::White)
                .with_attr(Attributes::BOLD),
        ))
        .with_option(StyleSheet::new().with_fg(Color::Grey))
        .with_answer(
            StyleSheet::new()
                .with_fg(Color::White)
                .with_attr(Attributes::BOLD),
        )
        .with_help_message(StyleSheet::new().with_fg(Color::Grey));
    config.placeholder = StyleSheet::new().with_fg(Color::Grey);
    config
}

/// Install the theme process-wide; every inquire prompt inherits it.
pub fn install() {
    inquire::set_global_render_config(theme());
}
