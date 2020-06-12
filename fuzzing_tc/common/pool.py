# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import datetime
import logging
import pathlib
import re
import types

import yaml

LOG = logging.getLogger("fuzzing_tc.common.pool")

# fields that must exist in pool.yml, and their types
FIELD_TYPES = types.MappingProxyType(
    {
        "cloud": str,
        "command": list,
        "container": str,
        "cores_per_task": int,
        "cpu": str,
        "cycle_time": str,
        "disk_size": str,
        "imageset": str,
        "macros": dict,
        "metal": bool,
        "minimum_memory_per_core": str,
        "name": str,
        "parents": list,
        "platform": str,
        "scopes": list,
        "tasks": int,
    }
)
CPU_ALIASES = {
    "x86_64": "x64",
    "amd64": "x64",
    "x86-64": "x64",
    "x64": "x64",
    "arm64": "arm64",
    "aarch64": "arm64",
}
PROVIDERS = frozenset(("aws", "gcp"))
ARCHITECTURES = frozenset(("x64", "arm64"))


class MachineTypes:
    """Database of all machine types available, by provider and architecture.
    """

    def __init__(self, machines_data):
        for provider, provider_archs in machines_data.items():
            assert provider in PROVIDERS, f"unknown provider: {provider}"
            for arch, machines in provider_archs.items():
                assert arch in ARCHITECTURES, f"unknown architecture: {provider}.{arch}"
                for machine, spec in machines.items():
                    missing = list({"cpu", "ram"} - set(spec))
                    extra = list(set(spec) - {"cpu", "ram", "metal", "zone_blacklist"})
                    assert (
                        not missing
                    ), f"machine {provider}.{arch}.{machine} missing required keys: {missing!r}"
                    assert (
                        not extra
                    ), f"machine {provider}.{arch}.{machine} has unknown keys: {extra!r}"
        self._data = machines_data

    @classmethod
    def from_file(cls, machines_yml):
        assert machines_yml.is_file()
        return cls(yaml.safe_load(machines_yml.read_text()))

    def cpus(self, provider, architecture, machine):
        return self._data[provider][architecture][machine]["cpu"]

    def zone_blacklist(self, provider, architecture, machine):
        return frozenset(
            self._data[provider][architecture][machine].get("zone_blacklist", [])
        )

    def filter(self, provider, architecture, min_cpu, min_ram_per_cpu, metal=False):
        """Generate machine types which fit the given requirements.

        Args:
            provider (str): the cloud provider (aws or google)
            architecture (str): the cpu architecture (x64 or arm64)
            min_cpu (int): the least number of acceptable cpu cores
            min_ram_per_cpu (float): the least amount of memory acceptable per cpu core
            metal (bool): whether a bare-metal instance is required

        Returns:
            generator of str: machine type names for the given provider/architecture
        """
        for name, spec in self._data[provider][architecture].items():
            if (
                spec["cpu"] == min_cpu
                and (spec["ram"] / spec["cpu"]) >= min_ram_per_cpu
            ):
                if not metal or (metal and spec.get("metal", False)):
                    yield name


class PoolConfiguration:
    """Fuzzing Pool Configuration

    Attributes:
        cloud (str): cloud provider, like aws or gcp
        command (list): list of strings, command to execute in the image/container
        container (str): name of the container
        cores_per_task (int): number of cores to be allocated per task
        cpu (int): cpu architecture (eg. x64/arm64)
        cycle_time (int): maximum run time of this pool in seconds
        disk_size (int): disk size in GB
        imageset (str): imageset name in community-tc-config/config/imagesets.yml
        macros (dict): dictionary of environment variables passed to the target
        metal (bool): whether or not the target requires to be run on bare metal
        minimum_memory_per_core (float): minimum RAM to be made available per core in GB
        name (str): descriptive name of the configuration
        parents (list): list of parents to inherit from
        platform (str): operating system of the target (linux, windows)
        pool_id (str): basename of the pool on disk (eg. "pool1" for pool1.yml)
        scopes (list): list of taskcluster scopes required by the target
        tasks (int): number of tasks to run (each with `cores_per_task`)
    """

    def __init__(self, pool_id, data, base_dir=None, _flattened=None):
        LOG.debug(f"creating pool {pool_id}")
        missing = list(set(data) - set(FIELD_TYPES))
        extra = list(set(FIELD_TYPES) - set(data))
        assert not missing, f"configuration is missing fields: {missing!r}"
        assert not extra, f"configuration has extra fields: {extra!r}"

        # "normal" fields
        self.pool_id = pool_id
        self.base_dir = base_dir or pathlib.Path.cwd()

        # check that all fields are of the right type (or None)
        for field, cls in FIELD_TYPES.items():
            if data[field] is not None:
                assert isinstance(
                    data[field], cls
                ), f"expected '{field}' to be '{cls.__name__}', got '{type(data[field]).__name__}'"
        for key, value in data["macros"].items():
            assert isinstance(
                key, str
            ), f"expected macro '{key!r}' name to be 'str', got '{type(key).__name__}'"
            assert isinstance(
                value, str
            ), f"expected macro '{key}' value to be 'str', got '{type(value).__name__}'"

        self.container = data["container"]
        self.cores_per_task = data["cores_per_task"]
        self.imageset = data["imageset"]
        self.metal = data["metal"]
        self.name = data["name"]
        assert self.name is not None, "name is required for every configuration"
        self.platform = data["platform"]
        self.tasks = data["tasks"]

        # dict fields
        self.macros = data["macros"].copy()

        # list fields
        # command is an overwriting field, null is allowed
        if data["command"] is not None:
            self.command = data["command"].copy()
        else:
            self.command = None
        self.parents = data["parents"].copy()
        self.scopes = data["scopes"].copy()

        # size fields
        self.minimum_memory_per_core = self.disk_size = None
        if data["minimum_memory_per_core"] is not None:
            self.minimum_memory_per_core = self.parse_size(
                data["minimum_memory_per_core"], self.parse_size("1g")
            )
        if data["disk_size"] is not None:
            self.disk_size = int(
                self.parse_size(data["disk_size"], self.parse_size("1g"))
            )

        # time fields
        self.cycle_time = None
        if data["cycle_time"] is not None:
            self.cycle_time = int(self.parse_time(data["cycle_time"]))

        # other special fields
        self.cpu = self.cloud = None
        if data["cpu"] is not None:
            cpu = self.alias_cpu(data["cpu"])
            assert cpu in ARCHITECTURES
            self.cpu = cpu

        if data["cloud"] is not None:
            assert data["cloud"] in PROVIDERS, "Invalid cloud - use {}".format(
                ",".join(PROVIDERS)
            )
        self.cloud = data["cloud"]

        if _flattened is None:
            _flattened = {self.pool_id}
        self._flatten(_flattened)

    def assert_complete(self):
        missing = {field for field in FIELD_TYPES if getattr(self, field) is None}
        assert not missing, f"Pool is missing fields: {list(missing)!r}"

    def _flatten(self, flattened):
        overwriting_fields = (
            "cloud",
            "command",
            "container",
            "cores_per_task",
            "cpu",
            "cycle_time",
            "disk_size",
            "imageset",
            "metal",
            "minimum_memory_per_core",
            "name",
            "platform",
            "tasks",
        )
        merge_dict_fields = ("macros",)
        merge_list_fields = ("scopes",)
        null_fields = {
            field for field in overwriting_fields if getattr(self, field) is None
        }
        # need to update dict values defined in self at the very end
        my_merge_dict_values = {
            field: getattr(self, field).copy() for field in merge_dict_fields
        }

        for parent_id in self.parents:
            assert (
                parent_id not in flattened
            ), f"attempt to resolve cyclic configuration, {parent_id} already encountered"
            flattened.add(parent_id)
            parent_obj = self.from_file(self.base_dir / f"{parent_id}.yml", flattened)

            # "normal" overwriting fields
            for field in overwriting_fields:
                if field in null_fields:
                    if getattr(parent_obj, field) is not None:
                        LOG.debug(
                            f"overwriting field {field} in {self.pool_id} from {parent_id}"
                        )
                    setattr(self, field, getattr(parent_obj, field))

            # merged dict fields
            for field in merge_dict_fields:
                if getattr(parent_obj, field):
                    LOG.debug(
                        f"merging dict field {field} in {self.pool_id} from {parent_id}"
                    )
                getattr(self, field).update(getattr(parent_obj, field))

            # merged list fields
            for field in merge_list_fields:
                if getattr(parent_obj, field):
                    LOG.debug(
                        f"merging list field {field} in {self.pool_id} from {parent_id}"
                    )
                setattr(
                    self,
                    field,
                    list(set(getattr(self, field)) | set(getattr(parent_obj, field))),
                )

        # dict values defined in self take precedence over values defined in parents
        for field, values in my_merge_dict_values.items():
            getattr(self, field).update(values)

    def get_machine_list(self, machine_types):
        """
        Args:
            machine_types (MachineTypes): database of all machine types

        Returns:
            generator of machine (name, capacity): instance type name and task capacity
        """
        yielded = False
        for machine in machine_types.filter(
            self.cloud,
            self.cpu,
            self.cores_per_task,
            self.minimum_memory_per_core,
            self.metal,
        ):
            cpus = machine_types.cpus(self.cloud, self.cpu, machine)
            zone_blacklist = machine_types.zone_blacklist(self.cloud, self.cpu, machine)
            yield (machine, cpus // self.cores_per_task, zone_blacklist)
            yielded = True
        assert yielded, "No available machines match specified configuration"

    def cycle_crons(self, start=None):
        """Generate cron patterns that correspond to cycle_time (starting from now)

        Args:
            start (float): Unix timestamp to offset from (default to now)

        Returns:
            generator of str: One or more strings in simple cron format. If all patterns
                              are installed, the result should correspond to cycle_time.
        """
        if start is not None:
            assert isinstance(start, (float, int))
            now = datetime.datetime.fromtimestamp(start, datetime.timezone.utc)
        else:
            now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
                seconds=1
            )
        interval = datetime.timedelta(seconds=self.cycle_time)

        # special case if the cycle time is a factor of 24 hours
        if (24 * 60 * 60) % self.cycle_time == 0:
            stop = now + datetime.timedelta(days=1)
            while now < stop:
                now += interval
                yield f"{now.second} {now.minute} {now.hour} * * *"
            return

        # special case if the cycle time is a factor of 7 days
        if (7 * 24 * 60 * 60) % self.cycle_time == 0:
            stop = now + datetime.timedelta(days=7)
            while now < stop:
                now += interval
                weekday = now.isoweekday() % 7
                yield f"{now.second} {now.minute} {now.hour} * * {weekday}"
            return

        # if the cycle can't be represented as a daily or weekly pattern, then it is
        #   awkward to represent in cron format: resort to generating an annual schedule
        # the cycle will glitch if it really runs for the full year, and either have
        #   dead time or overlapping runs, happening once around the anniversary.
        stop = now + datetime.timedelta(days=365)
        while now < stop:
            now += interval
            yield f"{now.second} {now.minute} {now.hour} {now.day} {now.month} *"

    @classmethod
    def from_file(cls, pool_yml, _flattened=None):
        assert pool_yml.is_file()
        return cls(
            pool_yml.stem,
            yaml.safe_load(pool_yml.read_text()),
            base_dir=pool_yml.parent,
            _flattened=_flattened,
        )

    @staticmethod
    def alias_cpu(cpu_name):
        """
        Args:
            cpu_name: a cpu string like x86_64 or x64

        Returns:
            str: x64 or arm64
        """
        return CPU_ALIASES[cpu_name.lower()]

    @staticmethod
    def parse_size(size, divisor=1):
        """Parse a human readable size like "4g" into (4 * 1024 * 1024 * 1024)

        Args:
            size (str): size as a string, with si prefixes allowed
            divisor (int): unit to divide by (eg. 1024 for result in kb)

        Returns:
            float: size with si prefix expanded and divisor applied
        """
        match = re.match(
            r"\s*(\d+\.\d*|\.\d+|\d+)\s*([kmgt]?)b?\s*", size, re.IGNORECASE
        )
        assert (
            match is not None
        ), "size should be a number followed by optional si prefix"
        result = float(match.group(1))
        multiplier = {
            "": 1,
            "k": 1024,
            "m": 1024 * 1024,
            "g": 1024 * 1024 * 1024,
            "t": 1024 * 1024 * 1024 * 1024,
        }[match.group(2).lower()]
        return result * multiplier / divisor

    @staticmethod
    def parse_time(time, divisor=1):
        """Parse a human readable time like 1h30m or 30m10s

        Args:
            time (str): time as a string
            divisor (int): seconds to divide by (1s default, 60 for result in minutes, etc.)

        Returns:
            float: time in seconds (or units determined by divisor)
        """
        result = 0
        got_anything = False
        while time:
            match = re.match(r"\s*(\d+)\s*([wdhms]?)\s*(.*)", time, re.IGNORECASE)
            assert (
                got_anything or match is not None
            ), "time should be a number followed by optional unit"
            if match is None:
                break
            if match.group(2):
                multiplier = {
                    "w": 7 * 24 * 60 * 60,
                    "d": 24 * 60 * 60,
                    "h": 60 * 60,
                    "m": 60,
                    "s": 1,
                }[match.group(2).lower()]
            else:
                assert not match.group(3), "trailing data"
                assert not got_anything, "multipart time must specify all units"
                multiplier = 1
            got_anything = True
            result += int(match.group(1)) * multiplier
            time = match.group(3)
        return result / divisor


def test_main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path, help="machines.yml")
    parser.add_argument(
        "--cpu", help="cpu architecture", choices=ARCHITECTURES, default="x64"
    )
    parser.add_argument(
        "--provider", help="cloud provider", choices=PROVIDERS, default="aws"
    )
    parser.add_argument(
        "--cores", help="minimum number of cpu cores", type=int, required=True
    )
    parser.add_argument(
        "--ram", help="minimum amount of ram per core, eg. 4gb", required=True
    )
    parser.add_argument("--metal", help="bare metal machines", action="store_true")
    args = parser.parse_args()

    ram = PoolConfiguration.parse_size(args.ram, PoolConfiguration.parse_size("1g"))
    type_list = MachineTypes.from_file(args.input)
    for machine in type_list.filter(
        args.provider, args.cpu, args.cores, ram, args.metal
    ):
        print(machine)


if __name__ == "__main__":
    test_main()
