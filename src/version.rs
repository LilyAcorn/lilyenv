use nom::Parser;
use serde::{Deserialize, Serialize};

use crate::error::Error;

pub const PYPY_DOWNLOAD_URL: &str = "https://downloads.python.org/pypy/";

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Deserialize, Serialize)]
pub enum Interpreter {
    CPython,
    PyPy,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Deserialize, Serialize)]
pub enum PreRelease {
    None,
    Alpha(u8),
    Beta(u8),
    RC(u8),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Deserialize, Serialize)]
pub struct Version {
    pub interpreter: Interpreter,
    pub major: u8,
    pub minor: u8,
    pub bugfix: Option<u8>,
    pub debug: bool,
    pub freethreaded: bool,
    pub prerelease: PreRelease,
}

impl Version {
    pub fn compatible(&self, other: &Self) -> bool {
        if self == other {
            true
        } else {
            self.interpreter == other.interpreter
                && self.major == other.major
                && self.minor == other.minor
                && self.debug == other.debug
                && self.freethreaded == other.freethreaded
                && other.bugfix.is_none()
                && self.prerelease == PreRelease::None
                && other.prerelease == PreRelease::None
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.interpreter {
            Interpreter::CPython => "",
            Interpreter::PyPy => "pypy",
        };
        let prerelease = match self.prerelease {
            PreRelease::None => "".to_string(),
            PreRelease::Alpha(n) => format!("a{n}"),
            PreRelease::Beta(n) => format!("b{n}"),
            PreRelease::RC(n) => format!("rc{n}"),
        };
        let debug = match self.debug {
            false => "",
            true => "-debug",
        };
        let freethreaded = match self.freethreaded {
            false => "",
            true => "t",
        };
        match self.bugfix {
            Some(bugfix) => write!(
                f,
                "{}{}.{}.{}{}{}{}",
                prefix, self.major, self.minor, bugfix, prerelease, freethreaded, debug
            ),
            None => write!(
                f,
                "{}{}.{}{}{}",
                prefix, self.major, self.minor, freethreaded, debug
            ),
        }
    }
}

impl std::str::FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parse_version(s) {
            Ok(("", version)) => Ok(version),
            _ => Err(Error::InvalidVersion(s.into())),
        }
    }
}

fn parse_prerelease(input: &str) -> nom::IResult<&str, PreRelease> {
    use nom::branch::alt;
    use nom::bytes::complete::tag;
    use nom::character::complete::u8;
    let (rest, prerelease_type) =
        nom::combinator::opt(alt((tag("a"), tag("b"), tag("rc")))).parse(input)?;
    let prerelease_type = match prerelease_type {
        None => return Ok((rest, PreRelease::None)),
        Some(prerelease_type) => prerelease_type,
    };
    let (rest, value) = u8(rest)?;
    match prerelease_type {
        "a" => Ok((rest, PreRelease::Alpha(value))),
        "b" => Ok((rest, PreRelease::Beta(value))),
        "rc" => Ok((rest, PreRelease::RC(value))),
        _ => unreachable!(),
    }
}

fn parse_version(version: &str) -> nom::IResult<&str, Version> {
    use nom::bytes::complete::tag;
    use nom::character::complete::u8;
    use nom::sequence::separated_pair;
    let (rest, interpreter) = nom::combinator::opt(tag("pypy")).parse(version)?;
    let (rest, (major, minor)) = separated_pair(u8, tag("."), u8).parse(rest)?;
    let (rest, bugfix) = nom::combinator::opt(nom::sequence::preceded(tag("."), u8)).parse(rest)?;
    let (rest, prerelease) = parse_prerelease(rest)?;
    let (rest, freethreaded) = nom::combinator::opt(tag("t")).parse(rest)?;
    let (rest, debug) = nom::combinator::opt(tag("-debug")).parse(rest)?;
    let interpreter = match interpreter {
        Some(_) => Interpreter::PyPy,
        None => Interpreter::CPython,
    };
    Ok((
        rest,
        Version {
            interpreter,
            major,
            minor,
            bugfix,
            debug: debug.is_some(),
            freethreaded: freethreaded.is_some(),
            prerelease,
        },
    ))
}

fn _parse_cpython_filename(filename: &str) -> nom::IResult<&str, (String, Version)> {
    use nom::bytes::complete::tag;
    let (input, _) = tag("cpython-")(filename)?;
    let (input, mut version) = parse_version(input)?;
    let (input, _) = tag("+")(input)?;
    let (input, release_tag) = nom::character::complete::digit1(input)?;
    let (input, freethreaded) =
        nom::combinator::opt(nom::bytes::complete::take_until("freethreaded")).parse(input)?;
    let (input, debug) =
        nom::combinator::opt(nom::bytes::complete::take_until("debug")).parse(input)?;
    if freethreaded.is_some() {
        version.freethreaded = true;
    }
    if debug.is_some() {
        version.debug = true;
    }
    Ok((input, (release_tag.to_string(), version)))
}

pub fn parse_cpython_filename(filename: &str) -> Result<(String, Version), Error> {
    match _parse_cpython_filename(filename) {
        Ok((_, (release_tag, version))) => Ok((release_tag, version)),
        Err(_) => Err(Error::ParseAsset(filename.to_string())),
    }
}

fn _parse_pypy_url(url: &str) -> nom::IResult<&str, (String, String, Version)> {
    use nom::bytes::complete::{tag, take_until};
    let (filename, _) = tag(PYPY_DOWNLOAD_URL)(url)?;
    let (rest, version) = parse_version(filename)?;
    let (rest, _) = tag("-")(rest)?;
    let (rest, release_tag) = take_until("-")(rest)?;

    Ok((
        rest,
        (filename.to_string(), release_tag.to_string(), version),
    ))
}

pub fn parse_pypy_url(url: &str) -> Result<(String, String, Version), Error> {
    match _parse_pypy_url(url) {
        Ok((_, (filename, release_tag, version))) => Ok((filename, release_tag, version)),
        Err(_) => Err(Error::ParseAsset(url.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_str() {
        assert_eq!(
            "3.12".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 12,
                bugfix: None,
                debug: false,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "3.12.1".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 12,
                bugfix: Some(1),
                debug: false,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "pypy3.10".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::PyPy,
                major: 3,
                minor: 10,
                bugfix: None,
                debug: false,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "pypy3.10.4".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::PyPy,
                major: 3,
                minor: 10,
                bugfix: Some(4),
                debug: false,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "3.12-debug".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 12,
                bugfix: None,
                debug: true,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "3.12.1-debug".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 12,
                bugfix: Some(1),
                debug: true,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "pypy3.10-debug".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::PyPy,
                major: 3,
                minor: 10,
                bugfix: None,
                debug: true,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );

        assert_eq!(
            "pypy3.10.4-debug".parse::<Version>().unwrap(),
            Version {
                interpreter: Interpreter::PyPy,
                major: 3,
                minor: 10,
                bugfix: Some(4),
                debug: true,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );
    }

    #[test]
    fn test_invalid_version() {
        let version = "3";
        let err = version.parse::<Version>();
        assert!(matches!(err, Err(Error::InvalidVersion(_))));
        if let Err(Error::InvalidVersion(s)) = err {
            assert_eq!(s, version);
        }

        let version = "3.";
        let err = version.parse::<Version>();
        assert!(matches!(err, Err(Error::InvalidVersion(_))));
        if let Err(Error::InvalidVersion(s)) = err {
            assert_eq!(s, version);
        }

        let version = "3.10.";
        let err = version.parse::<Version>();
        assert!(matches!(err, Err(Error::InvalidVersion(_))));
        if let Err(Error::InvalidVersion(s)) = err {
            assert_eq!(s, version);
        }

        let version = "py3.10.4";
        let err = version.parse::<Version>();
        assert!(matches!(err, Err(Error::InvalidVersion(_))));
        if let Err(Error::InvalidVersion(s)) = err {
            assert_eq!(s, version);
        }

        let version = "3.12.3abc";
        let err = version.parse::<Version>();
        assert!(matches!(err, Err(Error::InvalidVersion(_))));
        if let Err(Error::InvalidVersion(s)) = err {
            assert_eq!(s, version);
        }
    }

    #[test]
    fn test_parse_cpython_filename() {
        let filename = "cpython-3.10.13+20240107-x86_64-unknown-linux-gnu-install_only.tar.gz";
        let (release_tag, version) = parse_cpython_filename(filename).unwrap();
        assert_eq!(release_tag, "20240107");
        assert_eq!(
            version,
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 10,
                bugfix: Some(13),
                debug: false,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );
    }

    #[test]
    fn test_parse_cpython_filename_debug() {
        let filename = "cpython-3.11.9+20240415-x86_64_v3-unknown-linux-gnu-debug-full.tar.zst";
        let (release_tag, version) = parse_cpython_filename(filename).unwrap();
        assert_eq!(release_tag, "20240415");
        assert_eq!(
            version,
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 11,
                bugfix: Some(9),
                debug: true,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );
    }

    #[test]
    fn test_parse_cpython_release_candidate() {
        let filename = "cpython-3.13.0rc2+20240909-x86_64-unknown-linux-gnu-debug-full.tar.zst";
        let (release_tag, version) = parse_cpython_filename(filename).unwrap();
        assert_eq!(release_tag, "20240909");
        assert_eq!(
            version,
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 13,
                bugfix: Some(0),
                debug: true,
                freethreaded: false,
                prerelease: PreRelease::RC(2),
            }
        );
    }

    #[test]
    fn test_parse_cpython_filename_freethreaded_debug() {
        let filename =
            "cpython-3.13.1+20250115-x86_64-unknown-linux-gnu-freethreaded+debug-full.tar.zst";
        let (release_tag, version) = parse_cpython_filename(filename).unwrap();
        assert_eq!(release_tag, "20250115");
        assert_eq!(
            version,
            Version {
                interpreter: Interpreter::CPython,
                major: 3,
                minor: 13,
                bugfix: Some(1),
                debug: true,
                freethreaded: true,
                prerelease: PreRelease::None,
            }
        );
    }

    #[test]
    fn test_parse_pypy_url() {
        let url = "https://downloads.python.org/pypy/pypy3.10-v7.3.15-linux64.tar.bz2";
        let (filename, release_tag, version) = parse_pypy_url(url).unwrap();
        assert_eq!(filename, "pypy3.10-v7.3.15-linux64.tar.bz2");
        assert_eq!(release_tag, "v7.3.15");
        assert_eq!(
            version,
            Version {
                interpreter: Interpreter::PyPy,
                major: 3,
                minor: 10,
                bugfix: None,
                debug: false,
                freethreaded: false,
                prerelease: PreRelease::None,
            }
        );
    }
}
