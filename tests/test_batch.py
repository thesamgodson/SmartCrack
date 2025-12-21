from hashcrack.batch import parse_hash_file, BatchJob, BatchResult, deduplicate_hashes, auto_type_jobs

def test_parse_hash_file_one_per_line(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("5d41402abc4b2a76b9719d911017c592\ne10adc3949ba59abbe56e057f20f883e\n")
    jobs = parse_hash_file(f)
    assert len(jobs) == 2
    assert jobs[0].hash_value == "5d41402abc4b2a76b9719d911017c592"

def test_parse_hash_file_with_salt(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("5d41402abc4b2a76b9719d911017c592:mysalt\n")
    jobs = parse_hash_file(f)
    assert jobs[0].salt == "mysalt"

def test_deduplicate_hashes():
    jobs = [
        BatchJob(hash_value="abc", salt=""),
        BatchJob(hash_value="abc", salt=""),
        BatchJob(hash_value="def", salt=""),
    ]
    deduped = deduplicate_hashes(jobs)
    assert len(deduped) == 2

def test_parse_skips_comments(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("# header\nabc123\n\n# another comment\ndef456\n")
    jobs = parse_hash_file(f)
    assert len(jobs) == 2

def test_batch_result_success_rate():
    r = BatchResult(total=10, cracked=3, failed=7, results={})
    assert r.success_rate == 0.3

def test_batch_result_zero_total():
    r = BatchResult(total=0, cracked=0, failed=0, results={})
    assert r.success_rate == 0.0

def test_auto_type_jobs():
    jobs = [BatchJob(hash_value="5d41402abc4b2a76b9719d911017c592")]
    typed = auto_type_jobs(jobs)
    assert typed[0].hash_type is not None

def test_parse_empty_file(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("")
    jobs = parse_hash_file(f)
    assert len(jobs) == 0

def test_deduplicate_preserves_different_salts():
    jobs = [
        BatchJob(hash_value="abc", salt="salt1"),
        BatchJob(hash_value="abc", salt="salt2"),
    ]
    deduped = deduplicate_hashes(jobs)
    assert len(deduped) == 2
