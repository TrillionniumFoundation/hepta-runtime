use super::super::blocks::sequence_section::ModeType;
use super::super::blocks::sequence_section::Sequence;
use super::super::blocks::sequence_section::SequencesHeader;
use super::scratch::FSEScratch;
use crate::bit_io::BitReaderReversed;
use crate::blocks::sequence_section::{
    MAX_LITERAL_LENGTH_CODE, MAX_MATCH_LENGTH_CODE, MAX_OFFSET_CODE,
};
use crate::decoding::errors::DecodeSequenceError;
use crate::fse::FSEDecoder;
use alloc::vec::Vec;

/// Validate the actual destination while decoding each sequence, before examining
/// later FSE symbols or the final bitstream state. No decoded bytes are allocated.
/// A prior invalid literal/offset ends this capacity proof: it must not be replaced
/// by a later capacity error. The normal executor still validates all data.
pub struct SequenceOutputCapacity {
    limit: usize,
    generated: usize,
    literals: usize,
    literals_used: usize,
    history: usize,
    offsets: [u32; 3],
    valid_prefix: bool,
}

impl SequenceOutputCapacity {
    pub(super) fn new(limit: usize, literals: usize, history: usize, offsets: [u32; 3]) -> Self {
        Self {
            limit,
            generated: 0,
            literals,
            literals_used: 0,
            history,
            offsets,
            valid_prefix: true,
        }
    }

    fn advance(&mut self, sequence: Sequence) -> Result<(), DecodeSequenceError> {
        if !self.valid_prefix {
            return Ok(());
        }
        let after_literals = self.generated.saturating_add(sequence.ll as usize);
        let required = after_literals.saturating_add(sequence.ml as usize);
        if required > self.limit {
            return Err(DecodeSequenceError::OutputCapacityExceeded {
                capacity: self.limit,
                required,
            });
        }
        self.literals_used = self.literals_used.saturating_add(sequence.ll as usize);
        let offset = super::sequence_execution::do_offset_history(
            sequence.of,
            sequence.ll,
            &mut self.offsets,
        );
        if self.literals_used > self.literals
            || offset == 0
            || offset as usize > self.history.saturating_add(after_literals)
        {
            self.valid_prefix = false;
        }
        self.generated = required;
        Ok(())
    }

    fn incomplete(&mut self, known_minimum: Option<(u32, u32)>) -> Result<(), DecodeSequenceError> {
        // Missing input bits are padded by this backend. Do not treat that
        // padded value as the other decoder's sequence length. Only a symbol
        // selected from a complete FSE state supplies a reliable lower bound.
        if self.valid_prefix {
            if let Some((literals, matches)) = known_minimum {
                let required = self
                    .generated
                    .saturating_add(literals as usize)
                    .saturating_add(matches as usize);
                if required > self.limit {
                    return Err(DecodeSequenceError::OutputCapacityExceeded {
                        capacity: self.limit,
                        required,
                    });
                }
            }
        }
        self.valid_prefix = false;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<(), DecodeSequenceError> {
        if self.valid_prefix {
            let required = self
                .generated
                .saturating_add(self.literals - self.literals_used);
            if required > self.limit {
                return Err(DecodeSequenceError::OutputCapacityExceeded {
                    capacity: self.limit,
                    required,
                });
            }
        }
        Ok(())
    }
}

/// Decode the provided source as a series of sequences into the supplied `target`.
pub fn decode_sequences(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
    target: &mut Vec<Sequence>,
    capacity: Option<&mut SequenceOutputCapacity>,
) -> Result<(), DecodeSequenceError> {
    let bytes_read = maybe_update_fse_tables(section, source, scratch)?;

    vprintln!("Updating tables used {} bytes", bytes_read);

    let bit_stream = &source[bytes_read..];

    let mut br = BitReaderReversed::new(bit_stream);

    //skip the 0 padding at the end of the last byte of the bit stream and throw away the first 1 found
    let mut skipped_bits = 0;
    loop {
        let val = br.get_bits(1);
        skipped_bits += 1;
        if val == 1 || skipped_bits > 8 {
            break;
        }
    }
    if skipped_bits > 8 {
        //if more than 7 bits are 0, this is not the correct end of the bitstream. Either a bug or corrupted data
        return Err(DecodeSequenceError::ExtraPadding { skipped_bits });
    }

    if scratch.ll_rle.is_some() || scratch.ml_rle.is_some() || scratch.of_rle.is_some() {
        decode_sequences_with_rle(section, &mut br, scratch, target, capacity)
    } else {
        decode_sequences_without_rle(section, &mut br, scratch, target, capacity)
    }
}

fn decode_sequences_with_rle(
    section: &SequencesHeader,
    br: &mut BitReaderReversed<'_>,
    scratch: &FSEScratch,
    target: &mut Vec<Sequence>,
    mut capacity: Option<&mut SequenceOutputCapacity>,
) -> Result<(), DecodeSequenceError> {
    let mut ll_dec = FSEDecoder::new(&scratch.literal_lengths);
    let mut ml_dec = FSEDecoder::new(&scratch.match_lengths);
    let mut of_dec = FSEDecoder::new(&scratch.offsets);

    if scratch.ll_rle.is_none() {
        ll_dec.init_state(br)?;
    }
    if scratch.of_rle.is_none() {
        of_dec.init_state(br)?;
    }
    if scratch.ml_rle.is_none() {
        ml_dec.init_state(br)?;
    }

    target.clear();
    target.reserve(section.num_sequences as usize);

    for _seq_idx in 0..section.num_sequences {
        let state_bits_complete = br.bits_remaining() >= 0;
        //get the codes from either the RLE byte or from the decoder
        let ll_code = if let Some(ll_rle) = scratch.ll_rle {
            ll_rle
        } else {
            ll_dec.decode_symbol()
        };
        let ml_code = if let Some(ml_rle) = scratch.ml_rle {
            ml_rle
        } else {
            ml_dec.decode_symbol()
        };
        let of_code = if let Some(of_rle) = scratch.of_rle {
            of_rle
        } else {
            of_dec.decode_symbol()
        };

        let (ll_value, ll_num_bits) = lookup_ll_code(ll_code);
        let (ml_value, ml_num_bits) = lookup_ml_code(ml_code);

        //println!("Sequence: {}", i);
        //println!("of stat: {}", of_dec.state);
        //println!("of Code: {}", of_code);
        //println!("ll stat: {}", ll_dec.state);
        //println!("ll bits: {}", ll_num_bits);
        //println!("ll Code: {}", ll_value);
        //println!("ml stat: {}", ml_dec.state);
        //println!("ml bits: {}", ml_num_bits);
        //println!("ml Code: {}", ml_value);
        //println!("");

        if of_code > MAX_OFFSET_CODE {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: of_code,
            });
        }

        let (obits, ml_add, ll_add) = br.get_bits_triple(of_code, ml_num_bits, ll_num_bits);
        let offset = obits as u32 + (1u32 << of_code);

        if offset == 0 {
            return Err(DecodeSequenceError::ZeroOffset);
        }

        target.push(Sequence {
            ll: ll_value + ll_add as u32,
            ml: ml_value + ml_add as u32,
            of: offset,
        });
        let sequence_bits_complete = br.bits_remaining() >= 0;

        if target.len() < section.num_sequences as usize {
            //println!(
            //    "Bits left: {} ({} bytes)",
            //    br.bits_remaining(),
            //    br.bits_remaining() / 8,
            //);
            if scratch.ll_rle.is_none() {
                ll_dec.update_state(br);
            }
            if scratch.ml_rle.is_none() {
                ml_dec.update_state(br);
            }
            if scratch.of_rle.is_none() {
                of_dec.update_state(br);
            }
        }

        if let Some(capacity) = capacity.as_deref_mut() {
            if sequence_bits_complete {
                capacity.advance(target[target.len() - 1])?;
            } else {
                capacity.incomplete(state_bits_complete.then_some((ll_value, ml_value)))?;
            }
        }
        if br.bits_remaining() < 0 {
            return Err(DecodeSequenceError::NotEnoughBytesForNumSequences);
        }
    }

    if br.bits_remaining() > 0 {
        Err(DecodeSequenceError::ExtraBits {
            bits_remaining: br.bits_remaining(),
        })
    } else {
        Ok(())
    }
}

fn decode_sequences_without_rle(
    section: &SequencesHeader,
    br: &mut BitReaderReversed<'_>,
    scratch: &FSEScratch,
    target: &mut Vec<Sequence>,
    mut capacity: Option<&mut SequenceOutputCapacity>,
) -> Result<(), DecodeSequenceError> {
    let mut ll_dec = FSEDecoder::new(&scratch.literal_lengths);
    let mut ml_dec = FSEDecoder::new(&scratch.match_lengths);
    let mut of_dec = FSEDecoder::new(&scratch.offsets);

    ll_dec.init_state(br)?;
    of_dec.init_state(br)?;
    ml_dec.init_state(br)?;

    target.clear();
    target.reserve(section.num_sequences as usize);

    for _seq_idx in 0..section.num_sequences {
        let state_bits_complete = br.bits_remaining() >= 0;
        let ll_code = ll_dec.decode_symbol();
        let ml_code = ml_dec.decode_symbol();
        let of_code = of_dec.decode_symbol();

        let (ll_value, ll_num_bits) = lookup_ll_code(ll_code);
        let (ml_value, ml_num_bits) = lookup_ml_code(ml_code);

        if of_code > MAX_OFFSET_CODE {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: of_code,
            });
        }

        let (obits, ml_add, ll_add) = br.get_bits_triple(of_code, ml_num_bits, ll_num_bits);
        let offset = obits as u32 + (1u32 << of_code);

        if offset == 0 {
            return Err(DecodeSequenceError::ZeroOffset);
        }

        target.push(Sequence {
            ll: ll_value + ll_add as u32,
            ml: ml_value + ml_add as u32,
            of: offset,
        });
        let sequence_bits_complete = br.bits_remaining() >= 0;

        if target.len() < section.num_sequences as usize {
            //println!(
            //    "Bits left: {} ({} bytes)",
            //    br.bits_remaining(),
            //    br.bits_remaining() / 8,
            //);
            ll_dec.update_state(br);
            ml_dec.update_state(br);
            of_dec.update_state(br);
        }

        if let Some(capacity) = capacity.as_deref_mut() {
            if sequence_bits_complete {
                capacity.advance(target[target.len() - 1])?;
            } else {
                capacity.incomplete(state_bits_complete.then_some((ll_value, ml_value)))?;
            }
        }
        if br.bits_remaining() < 0 {
            return Err(DecodeSequenceError::NotEnoughBytesForNumSequences);
        }
    }

    if br.bits_remaining() > 0 {
        Err(DecodeSequenceError::ExtraBits {
            bits_remaining: br.bits_remaining(),
        })
    } else {
        Ok(())
    }
}

/// Look up the provided state value from a literal length table predefined
/// by the Zstandard reference document. Returns a tuple of (value, number of bits).
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ll_code(code: u8) -> (u32, u8) {
    match code {
        0..=15 => (u32::from(code), 0),
        16 => (16, 1),
        17 => (18, 1),
        18 => (20, 1),
        19 => (22, 1),
        20 => (24, 2),
        21 => (28, 2),
        22 => (32, 3),
        23 => (40, 3),
        24 => (48, 4),
        25 => (64, 6),
        26 => (128, 7),
        27 => (256, 8),
        28 => (512, 9),
        29 => (1024, 10),
        30 => (2048, 11),
        31 => (4096, 12),
        32 => (8192, 13),
        33 => (16384, 14),
        34 => (32768, 15),
        35 => (65536, 16),
        _ => unreachable!("Illegal literal length code was: {}", code),
    }
}

/// Look up the provided state value from a match length table predefined
/// by the Zstandard reference document. Returns a tuple of (value, number of bits).
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ml_code(code: u8) -> (u32, u8) {
    match code {
        0..=31 => (u32::from(code) + 3, 0),
        32 => (35, 1),
        33 => (37, 1),
        34 => (39, 1),
        35 => (41, 1),
        36 => (43, 2),
        37 => (47, 2),
        38 => (51, 3),
        39 => (59, 3),
        40 => (67, 4),
        41 => (83, 4),
        42 => (99, 5),
        43 => (131, 7),
        44 => (259, 8),
        45 => (515, 9),
        46 => (1027, 10),
        47 => (2051, 11),
        48 => (4099, 12),
        49 => (8195, 13),
        50 => (16387, 14),
        51 => (32771, 15),
        52 => (65539, 16),
        _ => unreachable!("Illegal match length code was: {}", code),
    }
}

// This info is buried in the symbol compression mode table
/// "The maximum allowed accuracy log for literals length and match length tables is 9"
pub const LL_MAX_LOG: u8 = 9;
/// "The maximum allowed accuracy log for literals length and match length tables is 9"
pub const ML_MAX_LOG: u8 = 9;
/// "The maximum accuracy log for the offset table is 8."
pub const OF_MAX_LOG: u8 = 8;

fn maybe_update_fse_tables(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
) -> Result<usize, DecodeSequenceError> {
    let modes = section
        .modes
        .ok_or(DecodeSequenceError::MissingCompressionMode)?;

    let mut bytes_read = 0;

    match modes.ll_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.literal_lengths.build_decoder(source, LL_MAX_LOG)?;
            bytes_read += bytes;

            vprintln!("Updating ll table");
            vprintln!("Used bytes: {}", bytes);
            scratch.ll_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE ll table");
            if source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleLlTable);
            }
            bytes_read += 1;
            if source[0] > MAX_LITERAL_LENGTH_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.ll_rle = Some(source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined ll table");
            scratch.literal_lengths.build_from_probabilities(
                LL_DEFAULT_ACC_LOG,
                &Vec::from(&LITERALS_LENGTH_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.ll_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ll table");
            /* Nothing to do */
        }
    };

    let of_source = &source[bytes_read..];

    match modes.of_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.offsets.build_decoder(of_source, OF_MAX_LOG)?;
            vprintln!("Updating of table");
            vprintln!("Used bytes: {}", bytes);
            bytes_read += bytes;
            scratch.of_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE of table");
            if of_source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleOfTable);
            }
            bytes_read += 1;
            if of_source[0] > MAX_OFFSET_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.of_rle = Some(of_source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined of table");
            scratch.offsets.build_from_probabilities(
                OF_DEFAULT_ACC_LOG,
                &Vec::from(&OFFSET_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.of_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat of table");
            /* Nothing to do */
        }
    };

    let ml_source = &source[bytes_read..];

    match modes.ml_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.match_lengths.build_decoder(ml_source, ML_MAX_LOG)?;
            bytes_read += bytes;
            vprintln!("Updating ml table");
            vprintln!("Used bytes: {}", bytes);
            scratch.ml_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE ml table");
            if ml_source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            bytes_read += 1;
            if ml_source[0] > MAX_MATCH_LENGTH_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.ml_rle = Some(ml_source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined ml table");
            scratch.match_lengths.build_from_probabilities(
                ML_DEFAULT_ACC_LOG,
                &Vec::from(&MATCH_LENGTH_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.ml_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ml table");
            /* Nothing to do */
        }
    };

    Ok(bytes_read)
}

// The default Literal Length decoding table uses an accuracy logarithm of 6 bits.
const LL_DEFAULT_ACC_LOG: u8 = 6;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#literals-length
const LITERALS_LENGTH_DEFAULT_DISTRIBUTION: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];

// The default Match Length decoding table uses an accuracy logarithm of 6 bits.
const ML_DEFAULT_ACC_LOG: u8 = 6;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
const MATCH_LENGTH_DEFAULT_DISTRIBUTION: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];

// The default Match Length decoding table uses an accuracy logarithm of 5 bits.
const OF_DEFAULT_ACC_LOG: u8 = 5;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
const OFFSET_DEFAULT_DISTRIBUTION: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

#[test]
fn test_ll_default() {
    let mut table = crate::fse::FSETable::new(MAX_LITERAL_LENGTH_CODE);
    table
        .build_from_probabilities(
            LL_DEFAULT_ACC_LOG,
            &Vec::from(&LITERALS_LENGTH_DEFAULT_DISTRIBUTION[..]),
        )
        .unwrap();

    #[cfg(feature = "std")]
    for idx in 0..table.decode.len() {
        std::println!(
            "{:3}: {:3} {:3} {:3}",
            idx,
            table.decode[idx].symbol,
            table.decode[idx].num_bits,
            table.decode[idx].base_line
        );
    }

    assert!(table.decode.len() == 64);

    //just test a few values. TODO test all values
    assert!(table.decode[0].symbol == 0);
    assert!(table.decode[0].num_bits == 4);
    assert!(table.decode[0].base_line == 0);

    assert!(table.decode[19].symbol == 27);
    assert!(table.decode[19].num_bits == 6);
    assert!(table.decode[19].base_line == 0);

    assert!(table.decode[39].symbol == 25);
    assert!(table.decode[39].num_bits == 4);
    assert!(table.decode[39].base_line == 16);

    assert!(table.decode[60].symbol == 35);
    assert!(table.decode[60].num_bits == 6);
    assert!(table.decode[60].base_line == 0);

    assert!(table.decode[59].symbol == 24);
    assert!(table.decode[59].num_bits == 5);
    assert!(table.decode[59].base_line == 32);
}
