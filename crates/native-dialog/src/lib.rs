//! Parent a native OS dialog to the foreground window so it opens on top of, and
//! focused over, the app — never behind it where the user must hunt for it.
//!
//! A native file dialog opened by a background/server process with no owner window
//! can be placed behind the foreground app by Windows' focus rules. Handing the
//! dialog the current foreground window as its parent fixes the z-order and focus.
//!
//! This lives in its own crate because it needs a small, audited Win32 `unsafe`
//! block that the workspace-wide `unsafe_code = "forbid"` lint blocks in the
//! callers; the crate is windows-only and dependency-light.

#[cfg(windows)]
mod windows_parent {
    use raw_window_handle::{
        DisplayHandle, HandleError, HasDisplayHandle, HasWindowHandle, RawDisplayHandle,
        RawWindowHandle, Win32WindowHandle, WindowHandle, WindowsDisplayHandle,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    /// A borrowed handle to the foreground window, usable as a dialog parent.
    ///
    /// Implements the `raw-window-handle` traits a native dialog (e.g. `rfd`)
    /// needs to own its modal to a parent window. Held only for the synchronous
    /// lifetime of the dialog call.
    pub struct ForegroundWindow(std::num::NonZeroIsize);

    impl HasWindowHandle for ForegroundWindow {
        fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
            let handle = Win32WindowHandle::new(self.0);
            // SAFETY: `self.0` is the HWND returned by `GetForegroundWindow`, a
            // real live top-level window; the borrowed handle is used only for the
            // blocking lifetime of the modal dialog that owns `self`.
            Ok(unsafe { WindowHandle::borrow_raw(RawWindowHandle::Win32(handle)) })
        }
    }

    impl HasDisplayHandle for ForegroundWindow {
        fn display_handle(&self) -> Result<DisplayHandle<'_>, HandleError> {
            // SAFETY: the Windows display handle carries no data; `borrow_raw` on
            // it is trivially valid.
            Ok(unsafe {
                DisplayHandle::borrow_raw(RawDisplayHandle::Windows(WindowsDisplayHandle::new()))
            })
        }
    }

    /// The current foreground window as a dialog parent, or `None` when there is no
    /// foreground window (nothing to own the dialog to).
    #[must_use]
    pub fn foreground_window() -> Option<ForegroundWindow> {
        // SAFETY: `GetForegroundWindow` is a parameterless, thread-safe Win32 query
        // that returns a window handle or null.
        let hwnd = unsafe { GetForegroundWindow() };
        std::num::NonZeroIsize::new(hwnd.0 as isize).map(ForegroundWindow)
    }
}

#[cfg(windows)]
pub use windows_parent::{ForegroundWindow, foreground_window};
