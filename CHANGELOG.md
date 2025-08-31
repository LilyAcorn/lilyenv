# 1.6.0

* Obtain an API token from GitHub to avoid rate limiting when accessing data about CPython releases.
* Fetch less data from the GitHub API in each request to avoid gateway timeout errors.
* Cache CPython release data from previous requests to avoid unnecessary http queries.
* Correctly fixup paths in `sysconfig`.
* Improve the error message for gateway timeouts to distinguish from other rate limiting errors.

# 1.5.1

* Fix regression where old Python versions were preferred for download over more recent bugfix releases.

# 1.5.0

* Add `--no-cd` flag to `lilyenv activate` to open the new shell in the current working directory instead of in the project directory.
* Support relative paths when setting the project directory.
* Support setting the project directory via `lilyenv activate --directory`.
* Support setting the project directory via `lilyenv virtualenv --directory`.
* Support `lilyenv activate` without a Python version when there is a unique virtualenv for the project.
* Add retry logic for accessing the GitHub API to view CPython releases.
* Simplify CPython release sorting and hide duplicates.

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
