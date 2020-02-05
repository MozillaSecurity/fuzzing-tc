# -*- coding: utf-8 -*-

import os

import pytest

from decision.pool import MachineTypes, PoolConfiguration

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.mark.parametrize(
    "size, divisor, result",
    [
        ("2g", "1g", 2),
        ("2g", "1m", 2048),
        ("2g", 1, 2048 * 1024 * 1024),
        ("128t", "1g", 128 * 1024),
    ],
)
def test_parse_size(size, divisor, result):
    if isinstance(divisor, str):
        divisor = PoolConfiguration.parse_size(divisor)

    assert PoolConfiguration.parse_size(size, divisor) == result


@pytest.mark.parametrize(
    "provider, cpu, cores, ram, metal, result",
    [
        ("gcp", "x64", 1, 1, False, ["base", "2-cpus", "more-ram", "metal"]),
        ("gcp", "x64", 2, 1, False, ["2-cpus", "more-ram"]),
        ("gcp", "x64", 2, 5, False, ["more-ram"]),
        ("gcp", "x64", 1, 1, True, ["metal"]),
        ("aws", "arm64", 1, 1, False, ["a1", "a2", "a3"]),
        ("aws", "arm64", 2, 1, False, ["a2", "a3"]),
        ("aws", "arm64", 12, 32, False, ["a3"]),
        ("aws", "arm64", 1, 1, True, []),
        # x64 is not present in aws
        ("aws", "x64", 1, 1, False, KeyError),
        # invalid provider raises too
        ("dummy", "x64", 1, 1, False, KeyError),
    ],
)
def test_machine_filters(provider, cpu, ram, cores, metal, result):
    path = os.path.join(FIXTURES_DIR, "machines.yml")
    assert os.path.exists(path)
    type_list = MachineTypes.from_file(path)

    if isinstance(result, list):
        assert list(type_list.filter(provider, cpu, cores, ram, metal)) == result
    else:
        with pytest.raises(result):
            list(type_list.filter(provider, cpu, cores, ram, metal))
