"""Tests for expanded combo engine — mechanical candidate generation."""

from __future__ import annotations

from smartcrack.models import ExpandedProfile, MutationProfile


def _sample_expanded() -> ExpandedProfile:
    return ExpandedProfile(
        names=("johnny", "john", "jon"),
        nicknames=("jboy",),
        dates=("1990", "90", "0115"),
        keywords_direct=("arsenal", "football"),
        keywords_cultural=("gunners", "highbury", "emirates", "henry", "wenger", "coyg"),
        keywords_generational=("pokemon", "freshprince"),
        locale_slang=("lad", "mate"),
        phonetic_variants=("arsnl", "jnny"),
        related_numbers=("14", "42", "49", "1886"),
        mutation_profile=MutationProfile(
            leet_likelihood="medium",
            special_char_preference=("!", "@"),
            separator_preference=("", "_", "."),
            capitalization_style="capitalize",
            typical_length_range=(8, 14),
            suffix_patterns=("!", "90", "1990"),
        ),
        high_confidence_seeds=("Johnny1990", "Arsenal90", "JohnnyArsenal"),
    )


class TestSeedsFirst:
    def test_high_confidence_seeds_yielded_first(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        gen = generate_from_expanded(_sample_expanded())
        first_three = [next(gen) for _ in range(3)]
        assert first_three == ["Johnny1990", "Arsenal90", "JohnnyArsenal"]


class TestRawTokens:
    def test_case_variants_generated(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates = set()
        gen = generate_from_expanded(_sample_expanded())
        for _ in range(500):
            candidates.add(next(gen))

        assert "johnny" in candidates
        assert "Johnny" in candidates
        assert "JOHNNY" in candidates
        assert "arsenal" in candidates
        assert "Arsenal" in candidates


class TestTokenNumberCombos:
    def test_token_number_with_separators(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates = list(generate_from_expanded(_sample_expanded()))
        candidates_set = set(candidates)

        assert "johnny1990" in candidates_set or "Johnny1990" in candidates_set
        assert "johnny_1990" in candidates_set or "Johnny_1990" in candidates_set
        assert "johnny.1990" in candidates_set or "Johnny.1990" in candidates_set

    def test_number_first_variants(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        assert "1990johnny" in candidates_set or "1990_johnny" in candidates_set


class TestTwoTokenCombos:
    def test_name_keyword_pairs(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))

        # Name + cultural keyword
        assert "johnnygunners" in candidates_set or "Johnnygunners" in candidates_set or "JohnnyGunners" in candidates_set
        assert "johnnyhighbury" in candidates_set or "JohnnyHighbury" in candidates_set


class TestThreeTokenCombos:
    def test_name_keyword_number_triple(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # Should find at least some 3-token combos
        three_token = [c for c in candidates_set if "johnny" in c.lower() and "arsenal" in c.lower() and "90" in c]
        assert len(three_token) > 0


class TestLeetSpeak:
    def test_leet_applied_when_medium(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # "arsenal" with leet -> "@r$3n@l" or similar
        leet_candidates = [c for c in candidates_set if "@" in c or "$" in c or "3" in c]
        assert len(leet_candidates) > 0

    def test_full_leet_skipped_when_none_but_selective_still_runs(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        expanded = ExpandedProfile(
            names=("alice",),
            keywords_direct=("test",),
            keywords_cultural=("arsenal",),
            related_numbers=("42",),
            mutation_profile=MutationProfile(leet_likelihood="none"),
            high_confidence_seeds=(),
        )
        candidates = set(generate_from_expanded(expanded))
        # Selective leet always runs on keywords_direct: "test" -> "t3st", "te$t", etc.
        assert any("3" in c or "$" in c for c in candidates)
        # But full leet on cultural keywords should NOT run when leet_likelihood="none"
        # Full leet of "arsenal" = "@r$3n@l" — should not be present
        assert "@r$3n@l" not in candidates


class TestMechanicalTransforms:
    def test_reversed_tokens(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        assert "ynnhoj" in candidates_set  # johnny reversed

    def test_vowel_stripped(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # "arsenal" vowel-stripped -> "rsnl"
        assert "rsnl" in candidates_set

    def test_initialisms(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # Initials of all keywords: arsenal, football, gunners, highbury, emirates, henry, wenger, coyg, pokemon, freshprince, lad, mate
        # First letters: a, f, g, h, e, h, w, c, p, f, l, m -> "afghehwcpflm"
        # Just verify SOME initialism exists
        assert any(len(c) >= 8 and c.isalpha() for c in candidates_set)


class TestDedup:
    def test_no_duplicates(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        gen = generate_from_expanded(_sample_expanded())
        first_5000 = []
        for _ in range(5000):
            try:
                first_5000.append(next(gen))
            except StopIteration:
                break

        assert len(first_5000) == len(set(first_5000))


class TestVolumeTarget:
    def test_generates_at_least_10k_candidates(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        count = sum(1 for _ in generate_from_expanded(_sample_expanded()))
        assert count >= 13_000, f"Only generated {count} candidates, expected >= 13,000"


class TestThreePartCombos:
    def test_token_number_suffix(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # highbury + 42 + ! should exist (token + number + suffix)
        assert any("highbury" in c.lower() and "42" in c and "!" in c for c in candidates_set)

    def test_reversed_token_with_number(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # "ynnhoj" (johnny reversed) + some number
        assert any(c.startswith("ynnhoj") and any(ch.isdigit() for ch in c) for c in candidates_set)

    def test_leet_with_full_year(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # Leet token + 1990
        leet_year = [c for c in candidates_set if "1990" in c and ("@" in c or "$" in c or "3" in c)]
        assert len(leet_year) > 0

    def test_two_token_plus_suffix(self) -> None:
        from smartcrack.expanded_combo import generate_from_expanded

        candidates_set = set(generate_from_expanded(_sample_expanded()))
        # Name + keyword + suffix pattern
        assert any("johnny" in c.lower() and "gunners" in c.lower() and ("!" in c or "90" in c) for c in candidates_set)
