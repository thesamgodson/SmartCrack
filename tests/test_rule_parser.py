from hashcrack.plugins.rule_parser import parse_rule_file, apply_hashcat_rule, rule_file_candidates

def test_parse_lowercase_rule():
    assert apply_hashcat_rule("l", "PassWord") == "password"

def test_parse_uppercase_rule():
    assert apply_hashcat_rule("u", "password") == "PASSWORD"

def test_parse_capitalize_rule():
    assert apply_hashcat_rule("c", "password") == "Password"

def test_parse_reverse_rule():
    assert apply_hashcat_rule("r", "abc") == "cba"

def test_parse_duplicate_rule():
    assert apply_hashcat_rule("d", "abc") == "abcabc"

def test_parse_append_char():
    assert apply_hashcat_rule("$1", "pass") == "pass1"

def test_parse_prepend_char():
    assert apply_hashcat_rule("^1", "pass") == "1pass"

def test_parse_toggle_at():
    assert apply_hashcat_rule("T0", "password") == "Password"

def test_parse_rule_file_skips_comments(tmp_path):
    rule_file = tmp_path / "test.rule"
    rule_file.write_text("# comment\nl\nu\n\n: # noop\n")
    rules = parse_rule_file(rule_file)
    assert len(rules) >= 2

def test_parse_chained_rules():
    assert apply_hashcat_rule("l$1", "PASS") == "pass1"

def test_rule_file_candidates_yields_original(tmp_path):
    rule_file = tmp_path / "test.rule"
    rule_file.write_text("u\n")
    results = list(rule_file_candidates(iter(["hello"]), rule_file))
    assert "hello" in results
    assert "HELLO" in results

def test_noop_rule():
    assert apply_hashcat_rule(":", "test") == "test"
