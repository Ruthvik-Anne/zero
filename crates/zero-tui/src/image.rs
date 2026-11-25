//! Inline images (TUI-11): a graphics protocol with a textual placeholder that
//! resolves the same artifact reference.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicsProtocol {
    Kitty,
    Iterm2,
    Halfblocks,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    pub id: String,
    pub alt: String,
    pub path: String,
}

pub fn detect(term_program: &str, kitty_graphics: bool, iterm_images: bool) -> GraphicsProtocol {
    let lower = term_program.to_ascii_lowercase();
    if kitty_graphics || lower.contains("kitty") || lower.contains("wezterm") {
        return GraphicsProtocol::Kitty;
    }
    if iterm_images || term_program == "iTerm.app" {
        return GraphicsProtocol::Iterm2;
    }
    if !term_program.is_empty() {
        return GraphicsProtocol::Halfblocks;
    }
    GraphicsProtocol::None
}

/// The textual placeholder always resolves the same artifact reference.
pub fn placeholder(image: &ImageRef) -> String {
    format!("[image:{} {}]", image.id, image.alt)
}

/// Render the image for the protocol. Unsupported protocols fall back to the
/// placeholder with the same id.
pub fn render(protocol: GraphicsProtocol, image: &ImageRef, width_cells: u16, height_cells: u16) -> String {
    match protocol {
        GraphicsProtocol::Kitty => format!(
            "\u{1b}_Ga=T,f=100,i={},c={width_cells},r={height_cells};{}\u{1b}\\{}",
            image.id,
            image.path,
            placeholder(image)
        ),
        GraphicsProtocol::Iterm2 => format!(
            "\u{1b}]1337;File=inline=1;name={}:{}\u{7}{}",
            image.id,
            image.path,
            placeholder(image)
        ),
        GraphicsProtocol::Halfblocks => {
            let mut out = String::new();
            for _ in 0..height_cells.min(4) {
                out.push_str("▀▀▀\n");
            }
            out.push_str(&placeholder(image));
            out
        }
        GraphicsProtocol::None => placeholder(image),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> ImageRef {
        ImageRef { id: "art-7".into(), alt: "screenshot".into(), path: "/tmp/shot.png".into() }
    }

    #[test]
    fn both_paths_resolve_the_same_artifact() {
        let image = image();
        for protocol in [
            GraphicsProtocol::Kitty,
            GraphicsProtocol::Iterm2,
            GraphicsProtocol::Halfblocks,
            GraphicsProtocol::None,
        ] {
            let rendered = render(protocol, &image, 40, 10);
            assert!(rendered.contains("image:art-7"), "{protocol:?}: {rendered}");
            assert!(rendered.contains("screenshot"));
        }
        assert_eq!(placeholder(&image), "[image:art-7 screenshot]");
    }

    #[test]
    fn detection_prefers_kitty_then_iterm_then_halfblocks() {
        assert_eq!(detect("xterm-kitty", false, false), GraphicsProtocol::Kitty);
        assert_eq!(detect("WezTerm", false, false), GraphicsProtocol::Kitty);
        assert_eq!(detect("iTerm.app", false, false), GraphicsProtocol::Iterm2);
        assert_eq!(detect("Windows Terminal", false, false), GraphicsProtocol::Halfblocks);
        assert_eq!(detect("", false, false), GraphicsProtocol::None);
    }
}
