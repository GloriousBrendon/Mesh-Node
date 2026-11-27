//! The X11 window a plugin editor embeds into (XWayland on Wayland).

use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt, CreateWindowAux, EventMask, PropMode, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

pub struct Parent {
    conn: RustConnection,
    pub id: u32,
    /// WM_DELETE_WINDOW: the window manager's close button.
    delete: u32,
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
        let atom = |name: &[u8]| -> Result<u32, String> {
            Ok(conn
                .intern_atom(false, name)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?
                .atom)
        };
        let (protocols, delete) = (atom(b"WM_PROTOCOLS")?, atom(b"WM_DELETE_WINDOW")?);
        conn.change_property32(PropMode::REPLACE, id, protocols, AtomEnum::ATOM, &[delete])
            .map_err(|e| e.to_string())?;
        conn.change_property8(
            PropMode::REPLACE,
            id,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            b"Aflos plugin",
        )
        .map_err(|e| e.to_string())?;
        conn.map_window(id).map_err(|e| e.to_string())?;
        conn.flush().map_err(|e| e.to_string())?;
        Ok(Self { conn, id, delete })
    }

    /// Drains our window's events; false once it's been closed.
    pub fn pump(&self) -> bool {
        let mut open = true;
        while let Ok(Some(event)) = self.conn.poll_for_event() {
            match event {
                Event::ClientMessage(m) if m.data.as_data32()[0] == self.delete => open = false,
                Event::DestroyNotify(_) => open = false,
                _ => {}
            }
        }
        let _ = self.conn.flush();
        open
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        let _ = self.conn.destroy_window(self.id);
        let _ = self.conn.flush();
    }
}
