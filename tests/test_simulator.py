import os
import pytest

from utils import shannon_entropy
from simulator.payloads import (
    generate_high_entropy_content,
    generate_moderate_entropy_content,
    generate_ransom_note,
)
import config


class TestHighEntropyContent:
    def test_produces_requested_size(self):
        data = generate_high_entropy_content(1024)
        assert len(data) >= 1024

    def test_minimum_size_floor(self):
        data = generate_high_entropy_content(10)
        assert len(data) >= 64

    def test_entropy_near_eight(self):
        data = generate_high_entropy_content(4096)
        assert shannon_entropy(data) > 7.0


class TestModerateEntropyContent:
    def test_preserves_length(self):
        original = b"Hello world this is a test " * 20
        result = generate_moderate_entropy_content(original)
        assert len(result) == len(original)

    def test_entropy_higher_than_original(self):
        original = b"Normal text content for testing purposes. " * 20
        result = generate_moderate_entropy_content(original)
        original_e = shannon_entropy(original)
        result_e = shannon_entropy(result)
        assert result_e > original_e

    def test_entropy_lower_than_random(self):
        original = b"Normal text content for testing purposes. " * 50
        result = generate_moderate_entropy_content(original)
        random_data = os.urandom(len(original))
        assert shannon_entropy(result) < shannon_entropy(random_data)


class TestRansomNote:
    def test_returns_two_strings(self):
        txt, html = generate_ransom_note()
        assert isinstance(txt, str) and len(txt) > 0
        assert isinstance(html, str) and len(html) > 0

    def test_html_is_valid_html(self):
        _, html = generate_ransom_note()
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_contains_required_keywords(self):
        txt, _ = generate_ransom_note()
        content = txt.lower()
        matches = [kw for kw in config.RANSOM_NOTE_KEYWORDS if kw in content]
        assert len(matches) >= 3

    def test_contains_btc_address(self):
        txt, _ = generate_ransom_note()
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in txt

    def test_contains_victim_id(self):
        txt, _ = generate_ransom_note()
        assert "VICTIM ID:" in txt
