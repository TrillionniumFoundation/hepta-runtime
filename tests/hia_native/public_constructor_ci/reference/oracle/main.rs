use std::io::{self, Read, Write};
use rmcp::model::{CallToolResult, ContentBlock, ServerResult};

fn word(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    assert!(input.len() >= 64);
    assert_eq!(&input[..8], b"HRTCRQ01");
    assert_eq!(word(&input, 8), 1);
    let is_error = word(&input, 16);
    let policy = word(&input, 24);
    assert!(is_error <= 1 && policy <= 2);
    assert_eq!(word(&input, 32), (input.len() - 64) as u64);
    assert_eq!((word(&input, 40), word(&input, 48), word(&input, 56)), (0, 0, 0));
    let text = String::from_utf8(input[64..].to_vec())?;
    let content = vec![ContentBlock::text(text)];
    let constructed = if is_error == 0 {
        CallToolResult::success(content)
    } else {
        CallToolResult::error(content)
    };
    let mut result = ServerResult::CallToolResult(constructed);
    match policy {
        0 => {},
        1 => result.strip_result_type_for_legacy_peer(),
        2 => result.fill_missing_cache_hints(),
        _ => unreachable!(),
    }
    let wire = serde_json::to_vec(&result)?;
    let mut out = io::stdout().lock();
    out.write_all(b"HRTCRS01")?;
    for value in [0, is_error, policy, 64, wire.len() as u64, 0, 0] {
        out.write_all(&value.to_le_bytes())?;
    }
    out.write_all(&wire)?;
    out.flush()?;
    Ok(())
}

