import unittest

from securechat.protocol import FrameDecoder, MAX_FRAME_BYTES, ProtocolError, encode_frame


class ProtocolTests(unittest.TestCase):
    def test_round_trip_single_frame(self):
        payload = {"type": "chat", "text": "hello"}
        self.assertEqual(FrameDecoder().feed(encode_frame(payload)), [payload])

    def test_decoder_keeps_fragmented_frame_until_newline_arrives(self):
        frame = encode_frame({"type": "join", "room": "general"})
        decoder = FrameDecoder()

        self.assertEqual(decoder.feed(frame[:5]), [])
        self.assertEqual(decoder.feed(frame[5:]), [{"type": "join", "room": "general"}])

    def test_decoder_returns_all_frames_from_one_chunk(self):
        first = {"type": "join", "room": "general"}
        second = {"type": "chat", "text": "hi"}

        self.assertEqual(FrameDecoder().feed(encode_frame(first) + encode_frame(second)), [first, second])

    def test_decoder_rejects_malformed_json(self):
        with self.assertRaises(ProtocolError):
            FrameDecoder().feed(b'{"type":\n')

    def test_exact_maximum_frame_is_accepted_and_one_byte_more_is_rejected(self):
        empty_wire_length = len(b'{"x":""}\n')
        exact = {"x": "a" * (MAX_FRAME_BYTES - empty_wire_length)}
        self.assertEqual(len(encode_frame(exact)), MAX_FRAME_BYTES)

        too_large = {"x": "a" * (MAX_FRAME_BYTES - empty_wire_length + 1)}
        with self.assertRaises(ProtocolError):
            encode_frame(too_large)

    def test_decoder_rejects_unterminated_oversized_frame(self):
        decoder = FrameDecoder()
        with self.assertRaises(ProtocolError):
            decoder.feed(b"x" * (MAX_FRAME_BYTES + 1))


if __name__ == "__main__":
    unittest.main()
