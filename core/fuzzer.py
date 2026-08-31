"""
Deep JSON & Structured Body Fuzzer for AutoSecAudit.

Recursively navigates and mutates nested JSON payloads, arrays, and sub-objects,
enabling scanners to audit complex REST and GraphQL API request bodies
without violating surrounding schema structures.
"""

import copy
import logging
from typing import Dict, Any, List, Tuple, Union

logger = logging.getLogger(__name__)


def extract_json_leaf_paths(data: Union[Dict, List], current_path: str = "") -> List[Tuple[str, Any]]:
    """
    Recursively extracts all leaf keys and their current values in a JSON structure.

    Example:
        {"user": {"name": "alice", "roles": ["admin"]}}
        -> [("user.name", "alice"), ("user.roles.0", "admin")]
    """
    paths: List[Tuple[str, Any]] = []

    if isinstance(data, dict):
        for key, value in data.items():
            path_key = f"{current_path}.{key}" if current_path else str(key)
            if isinstance(value, (dict, list)):
                paths.extend(extract_json_leaf_paths(value, path_key))
            else:
                paths.append((path_key, value))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            path_key = f"{current_path}.{idx}" if current_path else str(idx)
            if isinstance(item, (dict, list)):
                paths.extend(extract_json_leaf_paths(item, path_key))
            else:
                paths.append((path_key, item))

    return paths


def mutate_json_at_path(data: Union[Dict, List], path: str, payload: Any) -> Union[Dict, List]:
    """
    Returns a deep-copied JSON object with the value at `path` replaced by `payload`.

    Example:
        data = {"user": {"id": 1, "profile": {"name": "test"}}}
        path = "user.profile.name"
        payload = "' OR 1=1--"
        -> {"user": {"id": 1, "profile": {"name": "' OR 1=1--"}}}
    """
    mutated = copy.deepcopy(data)
    parts = path.split(".")

    curr: Any = mutated
    for i, part in enumerate(parts[:-1]):
        if isinstance(curr, dict):
            curr = curr[part]
        elif isinstance(curr, list):
            curr = curr[int(part)]

    last_part = parts[-1]
    if isinstance(curr, dict):
        curr[last_part] = payload
    elif isinstance(curr, list):
        curr[int(last_part)] = payload

    return mutated


def generate_json_fuzz_mutations(
    base_json: Dict[str, Any],
    payload: Any,
) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Generates a list of (path_name, mutated_json_body) for every leaf field in `base_json`.
    """
    leaf_paths = extract_json_leaf_paths(base_json)
    mutations: List[Tuple[str, Dict[str, Any]]] = []

    for path, _ in leaf_paths:
        mutated_body = mutate_json_at_path(base_json, path, payload)
        if isinstance(mutated_body, dict):
            mutations.append((path, mutated_body))

    return mutations
