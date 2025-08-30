use std::cmp::Ordering;

use crate::error::Error;
use crate::version::{PYPY_DOWNLOAD_URL, Version, parse_cpython_filename, parse_pypy_url};
use current_platform::CURRENT_PLATFORM;
use octocrab::Error as OctocrabError;
use url::Url;

#[derive(Debug)]
pub struct Python {
    pub name: String,
    pub url: Url,
    pub version: Version,
    pub release_tag: String,
    pub debug: bool,
    pub freethreaded: bool,
}

impl PartialEq for Python {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.debug == other.debug
            && self.freethreaded == other.freethreaded
            && self.release_tag == other.release_tag
    }
}

impl Eq for Python {}

impl Ord for Python {
    fn cmp(&self, other: &Self) -> Ordering {
        self.version
            .cmp(&other.version)
            .then(self.release_tag.cmp(&other.release_tag).reverse())
            .then(self.debug.cmp(&other.debug))
            .then(self.freethreaded.cmp(&other.freethreaded))
    }
}

impl PartialOrd for Python {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

async fn _cpython_releases() -> Result<Vec<Python>, Error> {
    let octocrab = octocrab::instance();
    let releases = octocrab
        .repos("astral-sh", "python-build-standalone")
        .releases()
        .list()
        .send()
        .await?;

    let releases = releases
        .items
        .into_iter()
        .filter(|release| {
            release.created_at
                > Some(
                    chrono::DateTime::parse_from_rfc3339("2022-02-26T00:00:00Z")
                        .expect("Could not parse hardcoded datetime.")
                        .into(),
                )
        })
        .flat_map(|release| release.assets)
        .filter(|asset| !asset.name.ends_with(".sha256"))
        .filter(|asset| asset.name.contains(CURRENT_PLATFORM))
        .map(|asset| {
            let (release_tag, version) = parse_cpython_filename(&asset.name)?;
            Ok(Python {
                name: asset.name,
                url: asset.browser_download_url,
                version,
                release_tag,
                debug: version.debug,
                freethreaded: version.freethreaded,
            })
        })
        .collect::<Result<Vec<Python>, Error>>()?;

    let mut versions: Vec<Python> = releases
        .into_iter()
        .filter(|python| python.debug || python.freethreaded || python.name.ends_with(".tar.gz"))
        .collect();
    versions.sort_unstable();
    versions.dedup_by_key(|python| (python.version, python.debug, python.freethreaded));
    Ok(versions)
}

pub async fn cpython_releases() -> Result<Vec<Python>, Error> {
    let mut backoff = 500;
    for _ in 1..=5 {
        return match _cpython_releases().await {
            Ok(releases) => Ok(releases),
            Err(Error::Octocrab(e)) => match &e {
                OctocrabError::GitHub { source, .. } => {
                    if source.status_code.is_server_error() {
                        eprintln!("Github server error, retrying");
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
                        backoff *= 2;
                        continue;
                    } else if source.status_code == http::StatusCode::TOO_MANY_REQUESTS
                        || source.status_code == http::StatusCode::FORBIDDEN
                    {
                        Err(Error::CPythonDownloadRateLimit)
                    } else {
                        Err(Error::Octocrab(e))
                    }
                }
                OctocrabError::Serde { .. } => {
                    eprintln!("Github gateway timeout, retrying");
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
                    backoff *= 2;
                    continue;
                }
                _ => Err(Error::Octocrab(e)),
            },
            Err(e) => Err(e),
        };
    }
    match _cpython_releases().await {
        Ok(releases) => Ok(releases),
        Err(Error::Octocrab(e)) => match &e {
            OctocrabError::GitHub { source, .. } => {
                if source.status_code == http::StatusCode::TOO_MANY_REQUESTS
                    || source.status_code == http::StatusCode::FORBIDDEN
                {
                    Err(Error::CPythonDownloadRateLimit)
                } else {
                    Err(Error::Octocrab(e))
                }
            }
            OctocrabError::Serde { .. } => Err(Error::CPythonDownloadFailed),
            _ => Err(Error::Octocrab(e)),
        },
        Err(e) => Err(e),
    }
}

fn pypy_platform_tag() -> Result<&'static str, Error> {
    match CURRENT_PLATFORM {
        "x86_64-unknown-linux-gnu" => Ok("linux64"),
        "x86_64-apple-darwin" => Ok("macos_x86_64"),
        "aarch64-unknown-linux-gnu" => Ok("aarch64"),
        "aarch64-apple-darwin" => Ok("macos_arm64"),
        _ => Err(Error::Platform(CURRENT_PLATFORM.to_string())),
    }
}

pub fn pypy_releases() -> Result<Vec<Python>, Error> {
    let html = reqwest::blocking::get("https://www.pypy.org/download.html")?.text()?;
    let document = scraper::Html::parse_document(&html);
    let selector = match scraper::Selector::parse("table>tbody>tr>td>p>a") {
        Ok(selector) => selector,
        Err(_) => Err(Error::Scraper(
            "Could not find table of pypy downloads.".to_string(),
        ))?,
    };
    let tag = pypy_platform_tag()?;
    document
        .select(&selector)
        .map(|link| {
            link.value()
                .attr("href")
                .expect("A pypy download <a> tag has a href attribute.")
        })
        .filter(|link| link.starts_with(PYPY_DOWNLOAD_URL))
        .filter(|link| link.contains(tag))
        .map(|url| {
            let (name, release_tag, version) = parse_pypy_url(url)?;
            Ok(Python {
                name,
                url: Url::parse(url)?,
                version,
                release_tag,
                debug: false,
                freethreaded: false,
            })
        })
        .collect()
}
