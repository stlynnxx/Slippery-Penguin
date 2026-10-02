import unittest
from html.parser import HTMLParser

from htmlgenerator import generate_PDF


class PreBlocks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.current = ""

    def handle_data(self, data):
        if self.current is not None:
            self.current += data

    def handle_endtag(self, tag):
        if tag == "pre" and self.current is not None:
            self.blocks.append(self.current)
            self.current = None


def blocks(data):
    parser = PreBlocks()
    parser.feed(generate_PDF(data))
    return parser.blocks


class EmptyPDFResultsTests(unittest.TestCase):
    def test_empty_result_sections(self):
        for data in ({}, {"flags": [], "strace": [], "gtfo": [], "timeouts": []},
                     {"flags": None, "strace": "", "gtfo": None, "timeouts": ""}):
            with self.subTest(data=data):
                self.assertEqual(blocks({"/example/binary": data}), ["No results available"] * 4)

    def test_nonempty_results_remain_and_escaped(self):
        data = {"flags": [{"string": "<flag>", "severity": "low"}],
                "strace": ["trace"], "gtfo": ["match"], "timeouts": ["timeout"]}
        self.assertEqual(blocks({"/example/binary": data}), ["<flag> (low)\n", "trace", "match", "timeout"])
        self.assertIn("&lt;flag&gt;", generate_PDF({"/example/binary": data}))
        self.assertNotIn("No results available", generate_PDF({"/example/binary": data}))

    def test_mixed_sections_and_multiple_binaries(self):
        self.assertEqual(blocks({"/a": {"strace": ["trace"]}, "/b": {"gtfo": ["match"]}}),
                         ["No results available", "trace", "No results available", "No results available",
                          "No results available", "No results available", "match", "No results available"])

    def test_no_binaries(self):
        self.assertIn("No results available", generate_PDF({}))


if __name__ == "__main__":
    unittest.main()
