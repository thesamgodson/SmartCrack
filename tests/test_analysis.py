from smartcrack.analysis import (
    analyze_password,
    calculate_entropy,
    detect_patterns,
    generate_audit_summary,
)

def test_calculate_entropy_simple():
    assert calculate_entropy("password") < 30

def test_calculate_entropy_complex():
    assert calculate_entropy("X#9kL!mP2@vQ") > 50

def test_calculate_entropy_empty():
    assert calculate_entropy("") == 0.0

def test_detect_patterns_name_year():
    patterns = detect_patterns("john1990")
    assert "name+year" in patterns

def test_detect_patterns_keyboard():
    patterns = detect_patterns("qwerty")
    assert "keyboard_walk" in patterns

def test_detect_patterns_leet():
    patterns = detect_patterns("p@ssw0rd")
    assert "leet_speak" in patterns

def test_detect_patterns_sequential():
    patterns = detect_patterns("abc123")
    assert "sequential" in patterns

def test_detect_patterns_digits_only():
    patterns = detect_patterns("123456")
    assert "digits_only" in patterns

def test_detect_patterns_common_suffix():
    patterns = detect_patterns("pass123")
    assert "common_suffix" in patterns

def test_detect_patterns_repeated():
    patterns = detect_patterns("aaabbb")
    assert "repeated_chars" in patterns

def test_analyze_password_weak():
    analysis = analyze_password("password")
    assert analysis.strength == "weak"
    assert analysis.entropy > 0
    assert analysis.length == 8

def test_analyze_password_strong():
    analysis = analyze_password("X#9kL!mP2@vQ")
    assert analysis.strength in ("strong", "very_strong")

def test_audit_summary():
    passwords = ["password", "123456", "john1990", "X#9kL!mP2@vQ"]
    summary = generate_audit_summary(passwords)
    assert summary.total == 4
    assert summary.avg_entropy > 0
    assert len(summary.pattern_distribution) > 0
    assert summary.policy_failures >= 0

def test_audit_summary_empty():
    summary = generate_audit_summary([])
    assert summary.total == 0
    assert summary.avg_entropy == 0

def test_audit_summary_recommendations():
    # Mostly weak passwords should generate recommendations
    passwords = ["password", "123456", "qwerty", "abc123", "letmein"]
    summary = generate_audit_summary(passwords)
    assert len(summary.recommendations) > 0

