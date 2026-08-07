//! Crossterm event → [`Msg`] translation.

use crossterm::event::Event;

use crate::app::Msg;

/// Map a crossterm event to a model message. Key presses become
/// [`Msg::Key`]; resizes and other events return `None` (they only warrant
/// a redraw, which the event loop does on every wake anyway).
pub fn into_msg(event: Event) -> Option<Msg> {
    match event {
        Event::Key(key) => Some(Msg::Key(key)),
        _ => None,
    }
}
