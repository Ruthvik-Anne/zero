//! T-MM-01 fixture suite: one fixture per input route, plus every rejection
//! path, dedupe, and per-modality accounting. No test touches the network.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use zero_mm::{
    account, build_input, build_input_with_mapping, decode_base64, parse_reference,
    scan_references, Attachment, AttachmentMeta, AttachmentStore, ContentBlock, Dimension,
    InputMessage, Modality, RefMapping, ReferenceKind, Role, Source, MAX_IMAGE_BYTES,
    MAX_SUMMARY_CHARS, MAX_TEXT_CHARS,
};
use zero_types::ErrorCode;

/// 1x1 PNG, standard padded base64.
const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
/// 1x1 GIF, standard padded base64 (distinct content for the dedupe fixtures).
const GIF_B64: &str = "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";

fn png_bytes() -> Vec<u8> {
    let bytes = decode_base64(PNG_B64).expect("fixture PNG decodes");
    assert!(
        bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "fixture must be a PNG"
    );
    bytes
}

fn inline_image(name: &str) -> Attachment {
    Attachment {
        id: format!("att-inline-{name}"),
        kind: Modality::Image,
        source: Source::Inline {
            bytes_b64: PNG_B64.to_string(),
        },
        mime: "image/png".to_string(),
        bytes: png_bytes().len() as u64,
        name: Some(name.to_string()),
    }
}

fn inline_gif(name: &str) -> Attachment {
    let bytes = decode_base64(GIF_B64).expect("fixture GIF decodes");
    Attachment {
        id: format!("att-inline-{name}-gif"),
        kind: Modality::Image,
        source: Source::Inline {
            bytes_b64: GIF_B64.to_string(),
        },
        mime: "image/gif".to_string(),
        bytes: bytes.len() as u64,
        name: Some(name.to_string()),
    }
}

fn meta(id: &str, kind: Modality, mime: &str, bytes: Option<u64>) -> AttachmentMeta {
    AttachmentMeta {
        id: id.to_string(),
        kind,
        mime: mime.to_string(),
        bytes,
        width: None,
        height: None,
        duration_ms: None,
        pages: None,
    }
}

struct Workspace {
    temp: TempDir,
    root: PathBuf,
    store: AttachmentStore,
    shot: Attachment,
}

impl Workspace {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        fs::create_dir_all(&root).expect("allowed root");
        let mut store = AttachmentStore::new(vec![root.clone()]).expect("store");
        let shot = inline_image("shot");
        store.insert(shot.clone()).expect("insert named image");
        Self {
            temp,
            root,
            store,
            shot,
        }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).expect("write fixture");
        path
    }

    fn open(&self, path: &Path) -> Attachment {
        self.store.open_path(path, None).expect("open fixture")
    }

    fn temp_path(&self) -> &Path {
        self.temp.path()
    }
}

fn is_text(block: &ContentBlock) -> bool {
    matches!(block, ContentBlock::Text { .. })
}
fn is_image(block: &ContentBlock) -> bool {
    matches!(block, ContentBlock::Image { .. })
}
fn is_audio(block: &ContentBlock) -> bool {
    matches!(block, ContentBlock::Audio { .. })
}
fn is_video(block: &ContentBlock) -> bool {
    matches!(block, ContentBlock::Video { .. })
}
fn is_document(block: &ContentBlock) -> bool {
    matches!(block, ContentBlock::Document { .. })
}

type BlockCheck = fn(&ContentBlock) -> bool;

/// Every MM-01 input route: inline text, inline image, path file, path image,
/// URL, audio, video, document, `@file`, `@image`, `@url`, bare `@name`, and
/// duplicate references. Each fixture must produce a valid message containing
/// the block the route is for.
#[test]
fn every_input_route_builds_a_valid_message() {
    let ws = Workspace::new();
    let text_file = ws.write("notes.txt", b"notes from disk");
    let image_file = ws.write("pixel.png", &png_bytes());
    let audio_file = ws.write("voice.wav", b"RIFF\x24\x00\x00\x00WAVEfmt ");
    let video_file = ws.write("clip.mp4", b"\x00\x00\x00\x18ftypmp42");
    let pdf_file = ws.write("spec.pdf", b"%PDF-1.7\n%%EOF\n");

    let path_text = ws.open(&text_file);
    let path_image = ws.open(&image_file);
    let path_audio = ws.open(&audio_file);
    let path_video = ws.open(&video_file);
    let path_document = ws.open(&pdf_file);
    let url_document = Attachment {
        id: "att-url-spec".to_string(),
        kind: Modality::Document,
        source: Source::Url {
            url: "https://example.com/spec.pdf".to_string(),
        },
        mime: "application/pdf".to_string(),
        bytes: 0,
        name: Some("spec.pdf".to_string()),
    };

    let routes: Vec<(&str, String, Vec<Attachment>, BlockCheck)> = vec![
        (
            "inline text",
            "hello from inline text".to_string(),
            Vec::new(),
            is_text,
        ),
        (
            "inline image",
            "describe this".to_string(),
            vec![ws.shot.clone()],
            is_image,
        ),
        ("path file", String::new(), vec![path_text], is_text),
        (
            "path image",
            "what is this".to_string(),
            vec![path_image],
            is_image,
        ),
        (
            "url",
            "summarize".to_string(),
            vec![url_document],
            is_document,
        ),
        (
            "audio",
            "transcribe".to_string(),
            vec![path_audio],
            is_audio,
        ),
        ("video", String::new(), vec![path_video], is_video),
        (
            "document",
            "read the spec".to_string(),
            vec![path_document],
            is_document,
        ),
        (
            "@file",
            "read @file:notes.txt".to_string(),
            Vec::new(),
            is_text,
        ),
        (
            "@image",
            "look at @image:pixel.png".to_string(),
            Vec::new(),
            is_image,
        ),
        (
            "@url",
            "fetch @url:https://example.com/diagram.png".to_string(),
            Vec::new(),
            is_image,
        ),
        (
            "bare @name",
            "@shot what is this".to_string(),
            Vec::new(),
            is_image,
        ),
        (
            "duplicate refs",
            "@shot and @shot again".to_string(),
            Vec::new(),
            is_image,
        ),
    ];

    for (name, text, attachments, expected) in routes {
        let built = build_input_with_mapping(&text, &attachments, &ws.store)
            .unwrap_or_else(|error| panic!("route `{name}` failed: {error}"));
        assert!(
            !built.message.blocks.is_empty(),
            "route `{name}` produced no blocks"
        );
        assert!(
            built.message.blocks.iter().any(expected),
            "route `{name}` lacks its expected block: {:?}",
            built.message.blocks
        );
    }
}

#[test]
fn references_expand_in_place_and_keep_order() {
    let mut ws = Workspace::new();
    ws.store.insert(inline_gif("chart")).expect("insert chart");
    let built = build_input_with_mapping("@shot first @chart last", &[], &ws.store).expect("build");

    assert_eq!(built.message.blocks.len(), 4);
    assert_eq!(
        built.message.attachment_ids(),
        vec!["att-inline-shot", "att-inline-chart-gif"]
    );
    assert_eq!(
        built.message.blocks[0],
        ContentBlock::Image {
            attachment_id: "att-inline-shot".to_string(),
            alt: Some("shot".to_string()),
        }
    );
    assert_eq!(
        built.message.blocks[1],
        ContentBlock::Text {
            text: " first ".to_string()
        }
    );
    assert_eq!(
        built.message.blocks[2],
        ContentBlock::Image {
            attachment_id: "att-inline-chart-gif".to_string(),
            alt: Some("chart".to_string()),
        }
    );
    assert_eq!(
        built.message.blocks[3],
        ContentBlock::Text {
            text: " last".to_string()
        }
    );
}

#[test]
fn duplicate_references_are_deduplicated_and_mapped() {
    let ws = Workspace::new();
    let built = build_input_with_mapping("@shot and @shot again", &[], &ws.store).expect("build");

    let images = built
        .message
        .blocks
        .iter()
        .filter(|block| is_image(block))
        .count();
    assert_eq!(images, 1, "one attachment must produce one block");
    assert_eq!(
        built.mappings,
        vec![
            RefMapping {
                reference: "@shot".to_string(),
                attachment_id: "att-inline-shot".to_string(),
                added: true,
            },
            RefMapping {
                reference: "@shot".to_string(),
                attachment_id: "att-inline-shot".to_string(),
                added: false,
            },
        ]
    );
}

#[test]
fn pre_attached_and_referenced_content_is_also_deduped() {
    let ws = Workspace::new();
    let built = build_input_with_mapping("@shot again", std::slice::from_ref(&ws.shot), &ws.store)
        .expect("build");
    assert_eq!(built.message.attachment_ids(), vec!["att-inline-shot"]);
    assert!(!built.mappings[0].added);
}

#[test]
fn text_without_references_keeps_email_addresses_as_text() {
    let ws = Workspace::new();
    let message = build_input("mail a@b.com about @shot", &[], &ws.store).expect("build");
    assert_eq!(message.blocks.len(), 2);
    assert_eq!(
        message.blocks[0],
        ContentBlock::Text {
            text: "mail a@b.com about ".to_string(),
        }
    );
    assert!(is_image(&message.blocks[1]));
}

#[test]
fn path_outside_the_allowed_root_is_rejected() {
    let ws = Workspace::new();
    let outside = ws.temp_path().join("outside.txt");
    fs::write(&outside, b"secret").expect("write outside file");
    let attachment = Attachment {
        id: "att-outside".to_string(),
        kind: Modality::Text,
        source: Source::Path { path: outside },
        mime: "text/plain".to_string(),
        bytes: 6,
        name: None,
    };
    let error = attachment
        .validate(ws.store.roots())
        .expect_err("an outside path must be rejected");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert!(error.message().contains("outside the allowed roots"));
}

#[test]
fn path_with_a_parent_component_is_rejected() {
    let ws = Workspace::new();
    fs::write(ws.temp_path().join("outside.txt"), b"secret").expect("write outside file");
    let escaped = ws.root.join("..").join("outside.txt");
    let attachment = Attachment {
        id: "att-escaped".to_string(),
        kind: Modality::Text,
        source: Source::Path { path: escaped },
        mime: "text/plain".to_string(),
        bytes: 6,
        name: None,
    };
    let error = attachment
        .validate(ws.store.roots())
        .expect_err("a `..` path must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains(".."));
}

#[test]
fn url_with_userinfo_is_rejected() {
    let attachment = Attachment {
        id: "att-userinfo".to_string(),
        kind: Modality::Image,
        source: Source::Url {
            url: "https://user:pass@example.com/a.png".to_string(),
        },
        mime: "image/png".to_string(),
        bytes: 0,
        name: None,
    };
    let error = attachment
        .validate(&[])
        .expect_err("userinfo must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("userinfo"));
}

#[test]
fn url_scheme_must_be_http_or_https() {
    let attachment = Attachment {
        id: "att-ftp".to_string(),
        kind: Modality::Image,
        source: Source::Url {
            url: "ftp://example.com/a.png".to_string(),
        },
        mime: "image/png".to_string(),
        bytes: 0,
        name: None,
    };
    let error = attachment.validate(&[]).expect_err("ftp must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("only http and https"));
}

#[test]
fn oversized_attachment_is_rejected_before_touching_the_path() {
    let ws = Workspace::new();
    let attachment = Attachment {
        id: "att-huge".to_string(),
        kind: Modality::Image,
        source: Source::Path {
            path: ws.root.join("missing.png"),
        },
        mime: "image/png".to_string(),
        bytes: MAX_IMAGE_BYTES + 1,
        name: None,
    };
    let error = attachment
        .validate(ws.store.roots())
        .expect_err("oversize must fail");
    assert_eq!(error.code(), ErrorCode::LimitExceeded);
}

#[test]
fn wrong_mime_for_the_modality_is_rejected() {
    let mut attachment = inline_image("wrong");
    attachment.mime = "text/plain".to_string();
    let error = attachment
        .validate(&[])
        .expect_err("image/text mime must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("not valid for a image attachment"));
}

#[test]
fn malformed_or_mismatched_inline_base64_is_rejected() {
    let mut bad = inline_image("bad");
    bad.source = Source::Inline {
        bytes_b64: "not-base64!!".to_string(),
    };
    let error = bad.validate(&[]).expect_err("invalid base64 must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);

    let mut mismatched = inline_image("mismatch");
    mismatched.bytes += 1;
    let error = mismatched
        .validate(&[])
        .expect_err("size mismatch must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("declares"));
}

#[test]
fn unknown_reference_is_not_found_with_candidates() {
    let ws = Workspace::new();
    let error = build_input("@missing hello", &[], &ws.store).expect_err("unknown ref must fail");
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert!(error.message().contains("candidates"));
    assert!(error.message().contains("shot"));
}

#[test]
fn unknown_path_reference_is_not_found_with_candidates() {
    let ws = Workspace::new();
    ws.write("notes.txt", b"notes");
    let error = build_input("@file:nope.txt", &[], &ws.store).expect_err("missing file must fail");
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert!(error.message().contains("candidates"));
    assert!(error.message().contains("notes.txt"));
}

#[test]
fn names_with_spaces_are_accepted_for_direct_attachments() {
    let ws = Workspace::new();
    let file = ws.write("my notes.txt", b"hello");
    let attachment = ws.store.open_path(&file, None).expect("open");
    assert_eq!(attachment.name.as_deref(), Some("my notes.txt"));
    attachment
        .validate(ws.store.roots())
        .expect("a name with a space is valid");
    let message = build_input("", std::slice::from_ref(&attachment), &ws.store).expect("build");
    assert!(is_text(&message.blocks[0]));
}

#[test]
fn ambiguous_name_lists_the_candidate_ids() {
    let mut ws = Workspace::new();
    ws.store
        .insert(inline_gif("shot"))
        .expect("insert second shot");
    let error = build_input("@shot", &[], &ws.store).expect_err("ambiguity must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("ambiguous"));
    assert!(error.message().contains("att-inline-shot"));
    assert!(error.message().contains("att-inline-shot-gif"));
}

#[test]
fn message_with_an_unknown_attachment_id_is_rejected() {
    let message = InputMessage::new(
        Role::User,
        vec![ContentBlock::Image {
            attachment_id: "att-ghost".to_string(),
            alt: None,
        }],
    );
    let error = message.validate(&[]).expect_err("unknown id must fail");
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert!(error.message().contains("candidates"));
}

#[test]
fn empty_input_is_rejected() {
    let ws = Workspace::new();
    let error = build_input("   ", &[], &ws.store).expect_err("empty input must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("at least one block"));
}

#[test]
fn empty_text_block_is_rejected() {
    let message = InputMessage::new(
        Role::User,
        vec![ContentBlock::Text {
            text: "  ".to_string(),
        }],
    );
    let error = message.validate(&[]).expect_err("empty text must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
}

#[test]
fn control_characters_in_ids_are_rejected() {
    let attachment = Attachment {
        id: "att\n1".to_string(),
        kind: Modality::Text,
        source: Source::Inline {
            bytes_b64: String::new(),
        },
        mime: "text/plain".to_string(),
        bytes: 0,
        name: None,
    };
    let error = attachment
        .validate(&[])
        .expect_err("control char id must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);

    let message = InputMessage::new(
        Role::User,
        vec![ContentBlock::ToolResult {
            tool_use_id: "call\t1".to_string(),
            summary: "ok".to_string(),
        }],
    );
    let error = message
        .validate(&[])
        .expect_err("control char tool id must fail");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
}

#[test]
fn text_and_summary_are_bounded() {
    let message = InputMessage::new(
        Role::User,
        vec![ContentBlock::Text {
            text: "x".repeat(MAX_TEXT_CHARS + 1),
        }],
    );
    let error = message.validate(&[]).expect_err("long text must fail");
    assert_eq!(error.code(), ErrorCode::LimitExceeded);

    let message = InputMessage::new(
        Role::User,
        vec![ContentBlock::ToolResult {
            tool_use_id: "call-1".to_string(),
            summary: "y".repeat(MAX_SUMMARY_CHARS + 1),
        }],
    );
    let error = message.validate(&[]).expect_err("long summary must fail");
    assert_eq!(error.code(), ErrorCode::LimitExceeded);
}

#[test]
fn accounting_totals_each_modality() {
    let meta = vec![
        meta("att-image", Modality::Image, "image/png", Some(100)).with_pixels(4, 5),
        meta("att-audio", Modality::Audio, "audio/wav", Some(200)).with_duration_ms(1_500),
        meta("att-video", Modality::Video, "video/mp4", Some(300)).with_duration_ms(2_500),
        meta("att-doc", Modality::Document, "application/pdf", Some(400)).with_pages(7),
    ];
    let message = InputMessage::new(
        Role::User,
        vec![
            ContentBlock::Text {
                text: "hello".to_string(),
            },
            ContentBlock::Image {
                attachment_id: "att-image".to_string(),
                alt: None,
            },
            ContentBlock::Audio {
                attachment_id: "att-audio".to_string(),
                duration_ms: Some(1_500),
            },
            ContentBlock::Video {
                attachment_id: "att-video".to_string(),
                duration_ms: None,
            },
            ContentBlock::Document {
                attachment_id: "att-doc".to_string(),
                page_hint: Some(2),
            },
            ContentBlock::ToolResult {
                tool_use_id: "call-1".to_string(),
                summary: "ok".to_string(),
            },
        ],
    );
    let usage = account(&message, &meta).expect("account");

    assert_eq!(usage.text_chars, 7);
    assert_eq!(usage.image_count, 1);
    assert_eq!(usage.image_pixels, 20);
    assert_eq!(usage.audio_ms, 1_500);
    assert_eq!(usage.video_ms, 2_500);
    assert_eq!(usage.document_pages, 7);
    assert_eq!(usage.bytes_for(Modality::Text), 7);
    assert_eq!(usage.bytes_for(Modality::Image), 100);
    assert_eq!(usage.bytes_for(Modality::Audio), 200);
    assert_eq!(usage.bytes_for(Modality::Video), 300);
    assert_eq!(usage.bytes_for(Modality::Document), 400);
    assert_eq!(usage.total_bytes(), 1_007);
    assert!(usage.unknown.is_empty(), "all dimensions were known");
}

#[test]
fn accounting_reports_unknown_dimensions_instead_of_guessing() {
    let meta = vec![
        meta("att-image", Modality::Image, "image/png", Some(10)),
        meta("att-audio", Modality::Audio, "audio/wav", None),
        meta("att-doc", Modality::Document, "application/pdf", Some(30)),
    ];
    let message = InputMessage::new(
        Role::User,
        vec![
            ContentBlock::Image {
                attachment_id: "att-image".to_string(),
                alt: None,
            },
            ContentBlock::Audio {
                attachment_id: "att-audio".to_string(),
                duration_ms: None,
            },
            ContentBlock::Document {
                attachment_id: "att-doc".to_string(),
                page_hint: None,
            },
        ],
    );
    let usage = account(&message, &meta).expect("account");

    assert_eq!(usage.image_pixels, 0);
    assert_eq!(usage.audio_ms, 0);
    assert_eq!(usage.document_pages, 0);
    assert_eq!(usage.total_bytes(), 40);
    assert_eq!(
        usage.unknown,
        vec![
            zero_mm::UnknownDimension {
                attachment_id: "att-audio".to_string(),
                dimension: Dimension::Bytes,
            },
            zero_mm::UnknownDimension {
                attachment_id: "att-audio".to_string(),
                dimension: Dimension::DurationMs,
            },
            zero_mm::UnknownDimension {
                attachment_id: "att-doc".to_string(),
                dimension: Dimension::Pages,
            },
            zero_mm::UnknownDimension {
                attachment_id: "att-image".to_string(),
                dimension: Dimension::Pixels,
            },
        ]
    );
}

#[test]
fn accounting_is_deterministic_and_round_trips_json() {
    let meta = vec![meta("att-doc", Modality::Document, "application/pdf", Some(40)).with_pages(3)];
    let message = InputMessage::new(
        Role::User,
        vec![
            ContentBlock::Text {
                text: "abc".to_string(),
            },
            ContentBlock::Document {
                attachment_id: "att-doc".to_string(),
                page_hint: None,
            },
        ],
    );
    let first = account(&message, &meta).expect("first");
    let second = account(&message, &meta).expect("second");
    assert_eq!(first, second);

    let json = serde_json::to_string(&first).expect("serialize");
    let decoded: zero_mm::ModalityUsage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, first);
    assert!(json.contains("\"document_pages\":3"));
}

#[test]
fn reference_grammar_parses_every_form() {
    let file = parse_reference("@file:notes.txt").expect("file");
    assert_eq!((file.kind, file.target), (ReferenceKind::File, "notes.txt"));
    let image = parse_reference("@image:/tmp/a.png").expect("image");
    assert_eq!(
        (image.kind, image.target),
        (ReferenceKind::Image, "/tmp/a.png")
    );
    let url = parse_reference("@url:https://example.com/a.png").expect("url");
    assert_eq!(
        (url.kind, url.target),
        (ReferenceKind::Url, "https://example.com/a.png")
    );
    let name = parse_reference("@shot").expect("name");
    assert_eq!((name.kind, name.target), (ReferenceKind::Name, "shot"));

    for invalid in [
        "@",
        "@file:",
        "@bad:name",
        "@url:ftp://example.com/a.png",
        "@no space",
    ] {
        assert!(
            parse_reference(invalid).is_err(),
            "{invalid} must be rejected"
        );
    }

    let references = scan_references("a@b.com @shot (@image:pixel.png)").expect("scan");
    assert_eq!(references.len(), 2);
    assert_eq!(references[0].target, "shot");
    assert_eq!(references[1].kind, ReferenceKind::Image);
}

#[test]
fn forced_kind_must_match_the_file_extension() {
    let ws = Workspace::new();
    let image_file = ws.write("pixel.png", &png_bytes());
    let error = ws
        .store
        .open_path(&image_file, Some(Modality::Audio))
        .expect_err("png is not audio");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("not audio"));
}

#[test]
fn unknown_attachment_is_rejected() {
    let ws = Workspace::new();
    let text_file = ws.write("note.txt", b"hello");
    let attachment = ws.open(&text_file);
    let mut message = InputMessage::new(
        Role::User,
        vec![ContentBlock::Text {
            text: "hello".to_string(),
        }],
    );
    message.blocks.push(ContentBlock::Document {
        attachment_id: "att-missing".to_string(),
        page_hint: None,
    });
    let error = message
        .validate(&[attachment])
        .expect_err("unknown attachment must fail");
    assert_eq!(error.code(), ErrorCode::NotFound);
}
