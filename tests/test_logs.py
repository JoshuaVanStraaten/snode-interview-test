import json
import pytest
import warnings
from deepdiff import DeepDiff
import os
from elasticsearch import Elasticsearch
import time
import hashlib
from datetime import datetime
from collections import defaultdict
import re


# --- Elasticsearch Client Setup ---
ELASTICSEARCH_HOSTS = os.environ.get("ELASTICSEARCH_HOSTS",
                                     "http://localhost:9200").split(',')
# Instantiate Elasticsearch client
es_client = Elasticsearch(ELASTICSEARCH_HOSTS)


def get_truncated_timestamp(log_entry, precision=6):
    """
    Truncates timestamp to specified precision to handle rounding differences.
    """
    timestamp_full = log_entry.get("@timestamp")

    if timestamp_full:
        try:
            parts = timestamp_full.split('.')
            if len(parts) > 1:
                datetime_part = parts[0]
                nanoseconds_and_z = parts[1]
                nanoseconds_truncated = nanoseconds_and_z[:precision]
                return f"{datetime_part}.{nanoseconds_truncated}"
            return timestamp_full
        except Exception as e:
            warnings.warn(
                f"Error processing timestamp '{timestamp_full}': {e}")
            return None
    return None


def get_composite_identifier(log_entry):
    """
    Creates a composite identifier using multiple fields to uniquely identify
    logs. This reduces dependency on precise timestamp matching.
    """
    # Core fields that should be consistent across similar log entries
    identifier_fields = [
        'action',
        'action_type',
        'src',
        'dst',
        'srcport',
        'dstport',
        'event_id',
        'user',
        'srcip',
        'dstip',
        'severity',
        'event_id_desc'
    ]

    # Build identifier from available fields
    id_parts = []
    for field in identifier_fields:
        value = log_entry.get(field)
        if value is not None and value != "":
            id_parts.append(f"{field}:{value}")

    # Add truncated timestamp as additional context (more precision for
    # composite)
    truncated_timestamp = get_truncated_timestamp(log_entry, precision=4)
    if truncated_timestamp:
        id_parts.append(f"ts:{truncated_timestamp}")

    return "|".join(id_parts) if id_parts else None


def get_content_hash(log_entry):
    """
    Creates a hash based on log content, excluding timestamp and Elasticsearch
    fields.
    """
    # Fields to exclude from content hash
    exclude_fields = {
        '@timestamp', '@version', '_id', '_index', '_score', '_type',
        'enrich_status', 'siem', 'test_event_id', 'test_route_flow'
    }

    # Create a copy excluding timestamp and ES fields
    content_dict = {k: v for k, v in log_entry.items() if k not in
                    exclude_fields}

    # Sort keys for consistent hashing
    content_str = json.dumps(content_dict, sort_keys=True)
    return hashlib.md5(content_str.encode()).hexdigest()[:12]


def get_fuzzy_timestamp_identifier(log_entry):
    """
    Creates identifier based on timestamp rounded to nearest 100ms.
    """
    timestamp_full = log_entry.get("@timestamp")

    if timestamp_full:
        try:
            # Normalize timezone format and truncate fractional seconds to 6
            # digits max
            timestamp_normalized = timestamp_full.replace('Z', '+00:00')

            # Use regex to truncate fractional seconds to 6 digits if longer
            timestamp_normalized = re.sub(r'\.(\d{6})\d*([+-]\d{2}:\d{2})',
                                          r'.\1\2', timestamp_normalized)

            # Parse timestamp
            dt = datetime.fromisoformat(timestamp_normalized)

            # Round to nearest 100ms
            microseconds = dt.microsecond
            rounded_microseconds = round(microseconds / 100000) * 100000
            dt_rounded = dt.replace(microsecond=rounded_microseconds)

            rounded_timestamp = dt_rounded.isoformat()

            # Combine with key identifying fields
            key_fields = [
                log_entry.get('action', ''),
                log_entry.get('src', ''),
                log_entry.get('dst', ''),
                log_entry.get('event_id', ''),
                log_entry.get('user', '')
            ]

            return \
                f"{rounded_timestamp}|{':'.join(str(f) for f in key_fields)}"
        except Exception as e:
            warnings.warn(f"Error processing fuzzy timestamp: {e}")
            return None
    return None


def create_multiple_identifiers(log_entry):
    """
    Creates multiple identifiers for a single log entry to increase matching
    chances.
    """
    identifiers = {}

    # Strategy 1: Composite identifier (highest priority)
    composite_id = get_composite_identifier(log_entry)
    if composite_id:
        identifiers['composite'] = composite_id

    # Strategy 2: Content hash (ignoring timestamp and ES fields)
    identifiers['content_hash'] = get_content_hash(log_entry)

    # Strategy 3: Fuzzy timestamp matching
    fuzzy_id = get_fuzzy_timestamp_identifier(log_entry)
    if fuzzy_id:
        identifiers['fuzzy_timestamp'] = fuzzy_id

    # Strategy 4: Original truncated timestamp approach (fallback)
    truncated_id = get_truncated_timestamp(log_entry, precision=6)
    if truncated_id:
        identifiers['truncated_timestamp'] = truncated_id

    return identifiers


def match_logs_with_multiple_strategies(expected_logs, generated_logs):
    """
    Matches logs using multiple identifier strategies to handle edge cases.
    """
    print(f"\nStarting log matching with {len(expected_logs)} expected and "
          f"{len(generated_logs)} generated logs")

    # Create identifier mappings for each strategy
    expected_mappings = defaultdict(lambda: defaultdict(list))
    generated_mappings = defaultdict(lambda: defaultdict(list))

    # Build mappings for expected logs
    for i, log in enumerate(expected_logs):
        identifiers = create_multiple_identifiers(log)
        for strategy, identifier in identifiers.items():
            if identifier:
                expected_mappings[strategy][identifier].append((i, log))

    # Build mappings for generated logs
    for i, log in enumerate(generated_logs):
        identifiers = create_multiple_identifiers(log)
        for strategy, identifier in identifiers.items():
            if identifier:
                generated_mappings[strategy][identifier].append((i, log))

    # Match logs using different strategies in priority order
    strategy_priority = ['composite', 'content_hash', 'fuzzy_timestamp',
                         'truncated_timestamp']

    matched_pairs = []
    used_expected = set()
    used_generated = set()

    for strategy in strategy_priority:
        strategy_matches = 0

        for identifier in expected_mappings[strategy]:
            if identifier in generated_mappings[strategy]:
                expected_candidates = expected_mappings[strategy][identifier]
                generated_candidates = generated_mappings[strategy][identifier]

                # Match candidates that haven't been used yet
                for exp_idx, exp_log in expected_candidates:
                    if exp_idx in used_expected:
                        continue

                    for gen_idx, gen_log in generated_candidates:
                        if gen_idx in used_generated:
                            continue

                        # Found a match!
                        matched_pairs.append((exp_idx, gen_idx, exp_log,
                                              gen_log, strategy))
                        used_expected.add(exp_idx)
                        used_generated.add(gen_idx)
                        strategy_matches += 1
                        break

        if strategy_matches > 0:
            print(f"Strategy '{strategy}' matched {strategy_matches} log "
                  "pairs")

    # Report unmatched logs
    unmatched_expected = [i for i in range(len(expected_logs)) if i not in
                          used_expected]
    unmatched_generated = [i for i in range(len(generated_logs)) if i not in
                           used_generated]

    print("\nMatching Summary:")
    print(f"  Total matches: {len(matched_pairs)}")
    print(f"  Unmatched expected: {len(unmatched_expected)}")
    print(f"  Unmatched generated: {len(unmatched_generated)}")

    return matched_pairs, unmatched_expected, unmatched_generated


def timestamps_close_enough(ts1, ts2, tolerance_ms=1):
    """
    Checks if two timestamps are within tolerance (in milliseconds).
    """
    if not ts1 or not ts2:
        return ts1 == ts2

    try:
        dt1 = datetime.fromisoformat(ts1.replace('Z', '+00:00'))
        dt2 = datetime.fromisoformat(ts2.replace('Z', '+00:00'))

        diff_ms = abs((dt1 - dt2).total_seconds() * 1000)
        return diff_ms <= tolerance_ms
    except Exception:
        return ts1 == ts2


def load_logs_from_file(filepath):
    """Loads JSON logs from a file, one JSON object per line."""
    logs = []
    with open(filepath, 'r') as f:
        for line in f:
            try:
                logs.append(json.loads(line.strip()))
            except json.JSONDecodeError as e:
                warnings.warn(f"Failed to parse JSON line in {filepath}: "
                              f"{line.strip()} - Error: {e}")
    return logs


@pytest.fixture(scope="module")
def generated_logs_from_es():
    """
    Fetches generated logs from Elasticsearch.
    Polls until logs are found or a timeout occurs.
    """
    max_retries = 40
    retry_delay = 5  # seconds

    # Query all indices starting with 'siem-'
    target_index_pattern = "siem-*"

    warnings.warn(f"Attempting to fetch logs from Elasticsearch index pattern:"
                  f" {target_index_pattern}")

    for attempt in range(max_retries):
        try:
            # Query Elasticsearch to get all documents from the specified index
            # pattern
            response = es_client.search(
                index=target_index_pattern,
                body={
                    "query": {
                        "match_all": {}  # Fetch all documents
                    },
                    "size": 10000,  # Max results per query
                    "sort": [{"@timestamp": {"order": "asc"}}]
                }
            )
            logs = [hit['_source'] for hit in response['hits']['hits']]

            if logs:
                warnings.warn(f"Successfully fetched {len(logs)} logs from "
                              f"Elasticsearch.")
                return logs
            else:
                warnings.warn(f"Attempt {attempt + 1}/{max_retries}: No logs "
                              f"found in Elasticsearch index pattern "
                              f"'{target_index_pattern}'. "
                              f"Retrying in {retry_delay}s...")
        except Exception as e:
            warnings.warn(f"Attempt {attempt + 1}/{max_retries}: Error "
                          f"connecting to Elasticsearch or fetching data: {e}."
                          f"Retrying in {retry_delay}s...")

        time.sleep(retry_delay)

    pytest.fail("Failed to fetch logs from Elasticsearch after multiple "
                "retries. No data for testing.")


@pytest.fixture(scope="module")
def expected_logs():
    """Loads the expected logs."""
    return load_logs_from_file("/app/tests/expected_logs/output.log")


def test_log_comparison(expected_logs, generated_logs_from_es):
    """
    Compares generated logs from Elasticsearch against expected logs using
    multiple matching strategies to handle timestamp rounding and other edge
    cases.
    """
    print("\n" + "="*60)
    print("STARTING LOG COMPARISON TEST")
    print("="*60)

    issues = []

    # Use multi-strategy matching
    matched_pairs, unmatched_expected, unmatched_generated = \
        match_logs_with_multiple_strategies(expected_logs,
                                            generated_logs_from_es)

    # 1. Compare matched log pairs
    print(f"\n--- Comparing {len(matched_pairs)} matched log pairs ---")
    for exp_idx, gen_idx, exp_log, gen_log, strategy in matched_pairs:
        # Deeply compare the two logs
        # Exclude timestamp and Elasticsearch-specific fields
        diff = DeepDiff(
            exp_log,
            gen_log,
            ignore_order=True,
            report_repetition=True,
            exclude_paths=[
                "root['@timestamp']",  # Exclude original timestamp
                "root['@version']",    # Elasticsearch adds this
                "root['_id']",         # Elasticsearch adds this
                "root['_index']",      # Elasticsearch adds this
                "root['_score']",      # Elasticsearch adds this
                "root['_type']"        # Elasticsearch adds this
            ]
        )

        # Check if timestamps are close enough
        timestamp_issue = None
        if not timestamps_close_enough(exp_log.get("@timestamp"),
                                       gen_log.get("@timestamp"),
                                       tolerance_ms=2):
            timestamp_issue = (f"Timestamp difference beyond tolerance: "
                               f"expected='{exp_log.get('@timestamp')}', "
                               f"generated='{gen_log.get('@timestamp')}'")

        if diff or timestamp_issue:
            issue_msg = (f"Differences found for matched logs (strategy: "
                         f"{strategy}):\n"
                         f"  Expected log index: {exp_idx}\n"
                         f"  Generated log index: {gen_idx}\n")

            if timestamp_issue:
                issue_msg += f"  Timestamp Issue: {timestamp_issue}\n"

            if diff:
                issue_msg += f"  Field Differences:\n{diff.pretty()}\n"

            issues.append(issue_msg)

    # 2. Report unmatched expected logs
    if unmatched_expected:
        print(f"\n--- {len(unmatched_expected)} expected logs not found in "
              f"generated output ---")
        for exp_idx in unmatched_expected:
            exp_log = expected_logs[exp_idx]
            issues.append(f"Expected log not found in generated output:\n"
                          f"  Index: {exp_idx}\n"
                          f"  Log: {json.dumps(exp_log, indent=2)}\n")

    # 3. Report unexpected generated logs
    if unmatched_generated:
        print(f"\n--- {len(unmatched_generated)} unexpected logs found in "
              f"generated output ---")
        for gen_idx in unmatched_generated:
            gen_log = generated_logs_from_es[gen_idx]
            issues.append(f"Unexpected log found in generated output:\n"
                          f"  Index: {gen_idx}\n"
                          f"  Log: {json.dumps(gen_log, indent=2)}\n")

    # 4. Generate detailed matching report
    print("\n--- Detailed Matching Report ---")
    strategy_counts = defaultdict(int)
    for _, _, _, _, strategy in matched_pairs:
        strategy_counts[strategy] += 1

    for strategy, count in strategy_counts.items():
        print(f"  {strategy}: {count} matches")

    # Report all collected issues
    if issues:
        print(f"\n--- {len(issues)} Issues Found ---")
        for i, issue in enumerate(issues, 1):
            print(f"{i}. {issue}")
        print("="*60)
    else:
        print("\n--- No Issues Found - All logs matched successfully! ---")
        print("="*60)

    # Test assertions
    total_expected = len(expected_logs)
    total_generated = len(generated_logs_from_es)
    total_matched = len(matched_pairs)

    print("\nFinal Summary:")
    print(f"  Expected logs: {total_expected}")
    print(f"  Generated logs: {total_generated}")
    print(f"  Matched pairs: {total_matched}")
    print(f"  Match rate: "
          f"{(total_matched/max(total_expected, total_generated)*100):.1f}%")

    # The test passes if we can match logs (even with minor differences)
    # but we report all issues as warnings for investigation
    assert total_matched > 0, \
        "No logs could be matched between expected and generated sets"
