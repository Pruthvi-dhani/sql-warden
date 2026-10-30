from importlib.metadata import version
from importlib.resources import files

import sql_warden


def test_version_matches_installed_metadata() -> None:
    assert sql_warden.__version__ == version("sql-warden")


def test_package_ships_py_typed_marker() -> None:
    assert files("sql_warden").joinpath("py.typed").is_file()
