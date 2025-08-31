use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::directories::{asset_cache, github_api_token};
use crate::error::Error;
use crate::version::{PYPY_DOWNLOAD_URL, Version, parse_cpython_filename, parse_pypy_url};
use current_platform::CURRENT_PLATFORM;
use http::header::ACCEPT;
use octocrab::Error as OctocrabError;
use octocrab::models::ReleaseId;
use octocrab::models::repos::Release;
use octocrab::{Octocrab, Page};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

const CLIENT_ID: &str = "Iv23lijakGjyxVNPgY4l";
const CLIENT_SECRET: &str = "efc4a9206a4646fc0037011c2c83552ed254b17d";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time since unix epoch should be positive")
        .as_secs()
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub expires_at: Option<u64>,
    pub refresh_token: Option<String>,
    pub refresh_token_expires_at: Option<u64>,
}

impl Credentials {
    fn new(oauth: octocrab::auth::OAuth, timestamp: u64) -> Self {
        Self {
            access_token: oauth.access_token.expose_secret().to_string(),
            expires_at: oauth.expires_in.map(|t| t as u64 + timestamp),
            refresh_token: oauth.refresh_token.map(|t| t.expose_secret().to_string()),
            refresh_token_expires_at: oauth.refresh_token_expires_in.map(|t| t as u64 + timestamp),
        }
    }

    fn is_valid(&self, timestamp: u64) -> bool {
        match self.expires_at {
            None => true,
            Some(expires_at) => expires_at > timestamp,
        }
    }

    fn refresh(&self, timestamp: u64) -> Option<&str> {
        if self.refresh_token_expires_at? > timestamp {
            self.refresh_token.as_deref()
        } else {
            None
        }
    }
}

async fn get_oauth() -> Result<Credentials, Error> {
    let timestamp = now();
    let client_id = SecretString::from(CLIENT_ID);
    let crab = Octocrab::builder()
        .base_uri("https://github.com")?
        .add_header(ACCEPT, "application/json".to_string())
        .build()?;

    let codes = crab
        .authenticate_as_device(&client_id, ["public_repo", "read:org"])
        .await?;
    println!(
        "Go to {} and enter code {} to authorize lilyenv to download via the GitHub API",
        codes.verification_uri, codes.user_code
    );
    let oauth = codes.poll_until_available(&crab, &client_id).await?;
    let credentials = Credentials::new(oauth, timestamp);
    let json = serde_json::to_string(&credentials)?;
    std::fs::write(github_api_token(), json)?;
    Ok(credentials)
}

async fn refresh_oauth(refresh_token: &str) -> Result<Credentials, Error> {
    let timestamp = now();
    let client = reqwest::Client::new();
    let response = client
        .post("https://github.com/login/oauth/access_token")
        .query(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?;
    let oauth = match response.json::<octocrab::auth::OAuth>().await {
        Ok(oauth) => oauth,
        Err(_) => return get_oauth().await,
    };
    let credentials = Credentials::new(oauth, timestamp);
    let json = serde_json::to_string(&credentials)?;
    std::fs::write(github_api_token(), json)?;
    Ok(credentials)
}

fn filter_assets(release: &Release) -> Result<Option<Vec<Python>>, Error> {
    let too_old = chrono::DateTime::parse_from_rfc3339("2022-02-26T00:00:00Z")
        .expect("Could not parse hardcoded datetime.");
    if release.created_at <= Some(too_old.into()) {
        return Ok(None);
    }
    Ok(Some(
        release
            .assets
            .iter()
            .filter(|asset| !asset.name.ends_with(".sha256"))
            .filter(|asset| asset.name.contains(CURRENT_PLATFORM))
            .map(|asset| {
                let (release_tag, version) = parse_cpython_filename(&asset.name)?;
                Ok(Python {
                    name: asset.name.clone(),
                    url: asset.browser_download_url.clone(),
                    version,
                    release_tag,
                    debug: version.debug,
                    freethreaded: version.freethreaded,
                })
            })
            .collect::<Result<Vec<Python>, Error>>()?,
    ))
}

async fn release_for_page(
    octocrab: &Octocrab,
    page: u32,
) -> Result<Page<Release>, octocrab::Error> {
    octocrab
        .repos("astral-sh", "python-build-standalone")
        .releases()
        .list()
        .per_page(1)
        .page(page)
        .send()
        .await
}

async fn load_cpython_assets(assets: &mut HashMap<ReleaseId, Vec<Python>>, octocrab: &Octocrab, first_page_release: &Release, total_pages: u32) -> Result<(), Error> {
    if let Some(first_assets) = filter_assets(first_page_release)? {
        assets.insert(first_page_release.id, first_assets);
    }

    for page in 2..total_pages {
        let mut release_page = release_for_page(octocrab, page).await?;
        let release = match release_page.items.pop() {
            Some(release) => release,
            None => continue,
        };
        if assets.contains_key(&release.id) {
            break
        }
        match filter_assets(&release)? {
            Some(release_assets) => assets.insert(release.id, release_assets),
            None => break,
        };
    }
    std::fs::write(asset_cache(), serde_json::to_string(&assets)?)?;
    Ok(())
}

async fn _cpython_releases(octocrab: &Octocrab) -> Result<Vec<Python>, Error> {
    let first_page = release_for_page(octocrab, 1).await?;
    let total_pages = first_page.number_of_pages().unwrap_or(1);
    let first_page_release = &first_page.items[0];

    let mut assets: HashMap<ReleaseId, Vec<Python>> = match std::fs::read_to_string(asset_cache()) {
        Ok(cached_assets) => serde_json::from_str(&cached_assets)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(err) => return Err(err.into()),
    };
    if !assets.contains_key(&first_page_release.id) {
        load_cpython_assets(&mut assets, octocrab, first_page_release, total_pages).await?;
    }

    let mut versions: Vec<Python> = assets
        .into_iter()
        .flat_map(|(_, pythons)| pythons)
        .filter(|python| python.debug || python.freethreaded || python.name.ends_with(".tar.gz"))
        .collect();
    versions.sort_unstable();
    versions.dedup_by_key(|python| (python.version, python.debug, python.freethreaded));
    Ok(versions)
}

async fn get_credentials() -> Result<Credentials, Error> {
    match std::fs::read_to_string(github_api_token()) {
        Ok(auth) => {
            let auth: Credentials = match serde_json::from_str(&auth) {
                Ok(auth) => auth,
                Err(_) => return get_oauth().await,
            };
            let timestamp = now();
            if auth.is_valid(timestamp) {
                Ok(auth)
            } else if let Some(refresh_token) = auth.refresh(timestamp) {
                refresh_oauth(refresh_token).await
            } else {
                get_oauth().await
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => get_oauth().await,
        Err(err) => Err(err.into()),
    }
}

pub async fn cpython_releases() -> Result<Vec<Python>, Error> {
    let auth = get_credentials().await?;
    let octocrab =
        octocrab::instance().user_access_token(SecretString::from(auth.access_token.clone()))?;
    let mut backoff = 500;
    for _ in 1..=5 {
        return match _cpython_releases(&octocrab).await {
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
    match _cpython_releases(&octocrab).await {
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
