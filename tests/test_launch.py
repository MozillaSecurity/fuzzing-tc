# -*- coding: utf-8 -*-

import os
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import yaml

from fuzzing_tc.pool_launch import cli
from fuzzing_tc.pool_launch.launcher import PoolLauncher


@patch("fuzzing_tc.pool_launch.cli.PoolLauncher", autospec=True)
def test_main_calls(mock_launcher):
    # if configure returns None, clone/load_params should not be called
    mock_launcher.return_value.configure.return_value = None
    cli.main([])
    mock_launcher.assert_called_once()
    mock_launcher.return_value.configure.assert_called_once()
    mock_launcher.return_value.clone.assert_not_called()
    mock_launcher.return_value.load_params.assert_not_called()
    mock_launcher.return_value.exec.assert_called_once()

    # if configure returns something, clone/load_params should be called
    mock_launcher.reset_mock(return_value=True)
    mock_launcher.return_value = Mock(spec=PoolLauncher)
    mock_launcher.return_value.configure.return_value = {}
    cli.main([])
    mock_launcher.assert_called_once()
    mock_launcher.return_value.configure.assert_called_once()
    mock_launcher.return_value.clone.assert_called_once()
    mock_launcher.return_value.load_params.assert_called_once()
    mock_launcher.return_value.exec.assert_called_once()


@patch("os.environ", {})
def test_load_params(tmp_path):
    os.environ["STATIC"] = "value"
    pool_data = {
        "cloud": "aws",
        "scopes": [],
        "disk_size": "120g",
        "cycle_time": "1h",
        "cores_per_task": 10,
        "metal": False,
        "name": "Amazing fuzzing pool",
        "tasks": 3,
        "command": [],
        "container": "MozillaSecurity/fuzzer:latest",
        "minimum_memory_per_core": "1g",
        "imageset": "generic-worker-A",
        "parents": [],
        "cpu": "arm64",
        "platform": "linux",
        "macros": {"ENVVAR1": "123456", "ENVVAR2": "789abc"},
    }

    # test 1: environment from pool is merged
    launcher = PoolLauncher(["command", "arg"], "test-pool")
    launcher.fuzzing_config_dir = tmp_path
    with (tmp_path / "test-pool.yml").open("w") as test_cfg:
        yaml.dump(pool_data, stream=test_cfg)

    launcher.load_params()
    assert launcher.command == ["command", "arg"]
    assert launcher.environment == {
        "ENVVAR1": "123456",
        "ENVVAR2": "789abc",
        "STATIC": "value",
    }

    # test 2: command from pool is used
    pool_data["macros"].clear()
    pool_data["command"] = ["new-command", "arg1", "arg2"]
    launcher = PoolLauncher([], "test-pool")
    launcher.fuzzing_config_dir = tmp_path
    with (tmp_path / "test-pool.yml").open("w") as test_cfg:
        yaml.dump(pool_data, stream=test_cfg)

    launcher.load_params()
    assert launcher.command == ["new-command", "arg1", "arg2"]
    assert launcher.environment == {"STATIC": "value"}

    # test 3: command from init and pool is error
    launcher = PoolLauncher(["command", "arg"], "test-pool")
    launcher.fuzzing_config_dir = tmp_path

    with pytest.raises(AssertionError):
        launcher.load_params()


def test_launch_exec(tmp_path, monkeypatch):
    # Start with taskcluster detection disabled, even on CI
    monkeypatch.delenv("TASK_ID", raising=False)
    monkeypatch.delenv("TASKCLUSTER_ROOT_URL", raising=False)
    with patch("os.execvpe"), patch("os.dup2"):
        log_dir = tmp_path / "logs"
        pool = PoolLauncher(["cmd"], "testpool")
        assert pool.in_taskcluster is False
        pool.log_dir = str(log_dir)
        pool.exec()
        os.dup2.assert_not_called()
        os.execvpe.assert_called_once_with("cmd", ["cmd"], pool.environment)
        assert not log_dir.is_dir()

        # Then enable taskcluster detection
        monkeypatch.setenv("TASK_ID", "someTask")
        monkeypatch.setenv("TASKCLUSTER_ROOT_URL", "http://fakeTaskcluster")
        assert pool.in_taskcluster is True

        os.execvpe.reset_mock()
        pool.exec()
        assert os.dup2.call_count == 2
        os.execvpe.assert_called_once_with("cmd", ["cmd"], pool.environment)
        assert log_dir.is_dir()
