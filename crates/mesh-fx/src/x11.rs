//! The X11 window a plugin editor embeds into (XWayland on Wayland).

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, CreateWindowAux, EventMask, WindowClass};
use x11rb::rust_connection::RustConnection;

pub struct Parent {
    conn: RustConnection,
    pub id: u32,
}

impl Parent {
    pub fn new(width: u16, height: u16) -> Result<Self, String> {
        let (conn, screen) = x11rb::connect(None).map_err(|e| format!("X11: {e}"))?;
        let root = conn.setup().roots[screen].root;
        let id = conn.generate_id().map_err(|e| e.to_string())?;
        let aux = CreateWindowAux::new().event_mask(EventMask::STRUCTURE_NOTIFY);
        conn.create_window(
            0,
            id,
            root,
            0,
            0,
            width,
            height,
            0,
            WindowClass::INPUT_OUTPUT,
            0,
            &aux,
        )
        .map_err(|e| e.to_string())?;
        conn.map_window(id).map_err(|e| e.to_string())?;
        conn.flush().map_err(|e| e.to_string())?;
        Ok(Self { conn, id })
    }

    /// Drains our window's events.
    pub fn pump(&self) {
        while let Ok(Some(_)) = self.conn.poll_for_event() {}
        let _ = self.conn.flush();
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        let _ = self.conn.destroy_window(self.id);
        let _ = self.conn.flush();
    }
}
