// use crate::keri::serdering::{BaseSerder, Serder};

// pub struct CesrParser<'a> {
//     data: &'a [u8],
//     position: usize,
//     state: ParserState,
//     buffer: Vec<u8>,
// }
//
// enum ParserState {
//     Initial,
//     Header,
//     Event,
//     Attachment
// }
//
// #[derive(Debug)]
// pub enum CesrElement {
//     Message(BaseSerder),
//     Signature,  // (SignatureData),
//     Attachment,  // (AttachmentData),
//     // Other element types
// }
//
// impl<'a> CesrParser<'a> {
//     pub fn new(data: &'a [u8]) -> Self {
//         Self {
//             data,
//             position: 0,
//             state: ParserState::Initial,
//             buffer: Vec::new(),
//         }
//     }
//
//     // Helper methods for parsing specific elements
//     fn parse_header(&mut self) -> Result<CesrElement, ParserError> {
//         // Header parsing logic
//         Ok(CesrElement::Signature)
//     }
//
//     // Other parsing helper methods
// }
//
// impl<'a> Iterator for CesrParser<'a> {
//     type Item = Result<CesrElement, ParserError>;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         if self.position >= self.data.len() {
//             return None;
//         }
//
//         // Parse based on current state
//         let result = match self.state {
//             ParserState::Initial => {
//                 // Initial parsing to determine what's next
//                 // Update state accordingly
//             },
//             ParserState::Header => self.parse_header(),
//             // Other states
//             _ => Err(ParserError::InvalidState),
//         };
//
//         Some(result)
//     }
// }
//
// #[derive(Debug)]
// pub enum ParserError {
//     InvalidState,
//     InvalidData,
//     InvalidFormat,
//     IncompleteData,
//     UnsupportedVersion,
//     InvalidHeader,
// },

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::io::{self, Cursor};
//     use crate::cesr::Versionage;
//
//     // Helper function to create test data
//     fn create_test_data(header: &[u8], body: &[u8], attachment: Option<&[u8]>) -> Vec<u8> {
//         let mut data = Vec::new();
//         data.extend_from_slice(header);
//         data.extend_from_slice(body);
//         if let Some(att) = attachment {
//             data.extend_from_slice(att);
//         }
//         data
//     }
//
//     #[test]
//     fn test_parser_empty_data() {
//         // Test with empty data - should return None immediately
//         let empty_data: &[u8] = &[];
//         let mut parser = CesrParser::new(empty_data);
//         assert!(parser.next().is_none());
//     }
//
//     #[test]
//     fn test_parser_valid_message() {
//         // Create a valid CESR message with header, event, and signature
//         let header = b"CESR\x01\x00"; // Example header
//         let event = b"{\"id\":\"test\",\"type\":\"event\"}"; // Example event
//         let signature = b"AABCDEFG"; // Example signature
//
//         let test_data = create_test_data(header, event, Some(signature));
//         let mut parser = CesrParser::new(&test_data);
//
//         // First element should be the header
//         match parser.next() {
//             Some(Ok(CesrElement::Message(msg))) => {
//                 assert_eq!(msg.version().unwrap(), Versionage { major: 1, minor: 0 });
//                 assert_eq!(msg.ilk(), 0);
//             },
//             other => panic!("Expected message header, got {:?}", other),
//         }
//
//         // Second element should be the event
//         match parser.next() {
//             Some(Ok(CesrElement::Event(evt))) => {
//                 assert_eq!(evt.id, "test");
//                 assert_eq!(evt.event_type, "event");
//             },
//             other => panic!("Expected event data, got {:?}", other),
//         }
//
//         // Third element should be the signature
//         match parser.next() {
//             Some(Ok(CesrElement::Signature(sig))) => {
//                 assert_eq!(sig.raw, b"ABCDEFG");
//             },
//             other => panic!("Expected signature, got {:?}", other),
//         }
//
//         // No more elements
//         assert!(parser.next().is_none());
//     }
//
//     #[test]
//     fn test_parser_incomplete_message() {
//         // Test with incomplete data (header only)
//         let header = b"CESR\x01\x00";
//         let mut parser = CesrParser::new(header);
//
//         // Should parse the header
//         match parser.next() {
//             Some(Ok(CesrElement::Message(msg))) => {
//                 assert_eq!(msg.version, 1);
//             },
//             other => panic!("Expected message header, got {:?}", other),
//         }
//
//         // Should return error for incomplete data
//         match parser.next() {
//             Some(Err(ParserError::IncompleteData)) => {},
//             other => panic!("Expected incomplete data error, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_invalid_header() {
//         // Test with invalid header
//         let invalid_header = b"INVALID";
//         let mut parser = CesrParser::new(invalid_header);
//
//         // Should return error for invalid header
//         match parser.next() {
//             Some(Err(ParserError::InvalidHeader)) => {},
//             other => panic!("Expected invalid header error, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_version_mismatch() {
//         // Test with unsupported version
//         let header = b"CESR\x99\x00"; // Version 99 is unsupported
//         let mut parser = CesrParser::new(header);
//
//         // Should return error for unsupported version
//         match parser.next() {
//             Some(Err(ParserError::UnsupportedVersion(99))) => {},
//             other => panic!("Expected unsupported version error, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_corrupted_event() {
//         // Test with corrupted event data
//         let header = b"CESR\x01\x00";
//         let corrupted_event = b"{\"id\":\"test\",\"type\":\"event"; // Missing closing brace
//
//         let test_data = create_test_data(header, corrupted_event, None);
//         let mut parser = CesrParser::new(&test_data);
//
//         // Should parse the header
//         let _ = parser.next(); // Skip header
//
//         // Should return error for corrupted JSON
//         match parser.next() {
//             Some(Err(ParserError::InvalidFormat)) => {},
//             other => panic!("Expected invalid format error, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_streaming() {
//         // Test that parser correctly handles streaming data
//         let header = b"CESR\x01\x00";
//         let event = b"{\"id\":\"test\",\"type\":\"event\"}";
//         let signature = b"AABCDEFG";
//
//         // Simulate streaming by providing data incrementally
//         let test_data = create_test_data(header, event, Some(signature));
//
//         // First provide only partial data
//         let mut parser = CesrParser::new(&test_data[0..10]);
//
//         // Try to parse (should get incomplete data)
//         match parser.next() {
//             Some(Ok(CesrElement::Message(msg))) => {
//                 assert_eq!(msg.version, 1);
//             },
//             other => panic!("Expected message header, got {:?}", other),
//         }
//
//         // Incomplete event data
//         match parser.next() {
//             Some(Err(ParserError::IncompleteData)) => {},
//             other => panic!("Expected incomplete data error, got {:?}", other),
//         }
//
//         // Now "stream" the rest of the data by creating a new parser with all data
//         let mut parser = CesrParser::new(&test_data);
//         parser.position = 10; // Simulate having already consumed 10 bytes
//
//         // Should now parse the event successfully
//         match parser.next() {
//             Some(Ok(CesrElement::Event(evt))) => {
//                 assert_eq!(evt.id, "test");
//             },
//             other => panic!("Expected event data, got {:?}", other),
//         }
//
//         // And signature
//         match parser.next() {
//             Some(Ok(CesrElement::Signature(sig))) => {
//                 assert_eq!(sig.raw, b"ABCDEFG");
//             },
//             other => panic!("Expected signature, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_reset() {
//         // Test parser reset functionality
//         let test_data = create_test_data(b"CESR\x01\x00", b"{\"test\":true}", None);
//         let mut parser = CesrParser::new(&test_data);
//
//         // Consume first element
//         let _ = parser.next();
//
//         // Reset parser
//         parser.reset();
//
//         // Should start from beginning again
//         match parser.next() {
//             Some(Ok(CesrElement::Message(_))) => {},
//             other => panic!("Expected message header after reset, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_multiple_attachments() {
//         // Test with multiple attachments
//         let header = b"CESR\x01\x00";
//         let event = b"{\"id\":\"test\",\"attachments\":2}";
//         let attachment1 = b"ATT1";
//         let attachment2 = b"ATT2";
//
//         let mut data = Vec::new();
//         data.extend_from_slice(header);
//         data.extend_from_slice(event);
//         data.extend_from_slice(attachment1);
//         data.extend_from_slice(attachment2);
//
//         let mut parser = CesrParser::new(&data);
//
//         // Skip header and event
//         let _ = parser.next();
//         let _ = parser.next();
//
//         // Check first attachment
//         match parser.next() {
//             Some(Ok(CesrElement::Attachment(att))) => {
//                 assert_eq!(att.data, b"ATT1");
//             },
//             other => panic!("Expected first attachment, got {:?}", other),
//         }
//
//         // Check second attachment
//         match parser.next() {
//             Some(Ok(CesrElement::Attachment(att))) => {
//                 assert_eq!(att.data, b"ATT2");
//             },
//             other => panic!("Expected second attachment, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_with_io_errors() {
//         // Test handling of I/O errors when reading from a stream
//         struct FailingReader;
//
//         impl io::Read for FailingReader {
//             fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
//                 Err(io::Error::new(io::ErrorKind::Other, "Simulated read failure"))
//             }
//         }
//
//         let mut cursor = Cursor::new(b"CESR\x01\x00");
//         let mut parser = CesrStreamingParser::new(&mut cursor);
//
//         // First read should succeed
//         assert!(parser.parse_next().is_ok());
//
//         // Now replace with failing reader
//         let mut failing = FailingReader;
//         let mut parser = CesrStreamingParser::new(&mut failing);
//
//         // Should return I/O error
//         match parser.parse_next() {
//             Err(ParserError::IoError(_)) => {},
//             other => panic!("Expected I/O error, got {:?}", other),
//         }
//     }
//
//     #[test]
//     fn test_parser_state_transitions() {
//         // Test that parser correctly handles state transitions
//         let test_data = create_test_data(b"CESR\x01\x00", b"{\"test\":true}", None);
//         let mut parser = CesrParser::new(&test_data);
//
//         // Initial state should be Initial
//         assert_eq!(parser.state, ParserState::Initial);
//
//         // After parsing header, should be in Header state
//         let _ = parser.next();
//         assert_eq!(parser.state, ParserState::Event);
//
//         // After parsing event, should be in Event state
//         let _ = parser.next();
//         assert_eq!(parser.state, ParserState::Complete);
//     }
//
//     #[test]
//     fn test_parser_with_custom_error_handling() {
//         // Test custom error handling approach
//         let corrupted_data = b"CESR\x01\x00{invalid}";
//         let mut parser = CesrParser::new(corrupted_data);
//
//         // Create a handler that collects errors
//         let mut errors = Vec::new();
//         let mut elements = Vec::new();
//
//         while let Some(result) = parser.next() {
//             match result {
//                 Ok(element) => elements.push(element),
//                 Err(err) => errors.push(err),
//             }
//         }
//
//         // Should have 1 element (header) and 1 error
//         assert_eq!(elements.len(), 1);
//         assert_eq!(errors.len(), 1);
//         assert!(matches!(errors[0], ParserError::InvalidFormat));
//     }
//
//     #[test]
//     fn test_parser_with_invalid_state_sequence() {
//         // Test handling of invalid state sequences
//         let mut parser = CesrParser::new(b"CESR\x01\x00");
//
//         // Manually set to an invalid state sequence
//         parser.state = ParserState::Attachment;
//
//         // Should return invalid state error
//         match parser.next() {
//             Some(Err(ParserError::InvalidState)) => {},
//             other => panic!("Expected invalid state error, got {:?}", other),
//         }
//     }
// }