# 1.4.0

* Support freethreaded CPython installs. `lilyenv activate <project> 3.13t`
* Support Python 3.13.
* Allow setting the shell (bash, zsh or fish) on a per-project basis in addition to the existing global config option.

# 1.3.0

* Support installing release candidate CPython builds.

# 1.2.0

* Support installing CPython debug builds.

# 1.1.2

* Improve UX of `lilyenv list` when no virtualenvs exist yet.
* Omit metadata file `directory` from `lilyenv list` output.

# 1.1.1

* Fix paths in `sysconfig` and `pkgconfig` to match the interpreter's location after being downloaded.

# 1.1.0

* Add `lilyenv site-packages` command to open a subshell in a virtualenv's site-packages.

# 1.0.2

* Set `LD_LIBRARY_PATH` in activated virtualenvs to allow linking the python interpreter in other programs.

# 1.0.1

* Fix README formatting on crates.io.

# 1.0.0

* Initial release.
