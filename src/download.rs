use crate::directories::{downloads_dir, is_downloaded, python_dir};
use crate::error::Error;
use crate::releases::{cpython_releases, pypy_releases};
use crate::version::{Interpreter, Version};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::File;
use std::path::Path;
use tar::Archive;
use url::Url;
use zstd::stream::read::Decoder as ZstDecoder;

pub fn download_python(version: &Version, upgrade: bool) -> Result<(), Error> {
    match version.interpreter {
        Interpreter::CPython => download_cpython(version, upgrade),
        Interpreter::PyPy => download_pypy(version, upgrade),
    }
}

pub fn print_available_downloads() -> Result<(), Error> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let releases = rt.block_on(cpython_releases())?;
    for python in releases {
        println!("{} ({})", python.version, python.release_tag);
    }
    let mut pypy_releases = pypy_releases()?;
    pypy_releases.sort_unstable_by_key(|p| p.version);
    for python in pypy_releases {
        println!("{} ({})", python.version, python.release_tag);
    }
    Ok(())
}

fn download_cpython(version: &Version, upgrade: bool) -> Result<(), Error> {
    let python_dir = python_dir(version);
    if !upgrade && is_downloaded(&python_dir)? {
        return Ok(());
    }

    let downloads = downloads_dir();
    std::fs::create_dir_all(&downloads)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut releases = rt.block_on(cpython_releases())?;
    releases.reverse();
    let python = match releases
        .into_iter()
        .find(|python| python.version.compatible(version))
    {
        Some(python) => python,
        None => {
            return Err(Error::VersionNotFound(version.to_string()));
        }
    };
    let path = downloads.join(&python.name);
    if upgrade || !path.exists() {
        download_file(python.url.clone(), &path)?;
    }
    match python.debug || python.freethreaded {
        false => extract_tar_gz(&path, &python_dir)?,
        true => {
            extract_tar_zst(&path, &python_dir)?;
            move_install(&python_dir)?;
        }
    };
    fixup_sysconfig_paths(&python_dir)?;
    Ok(())
}

fn download_pypy(version: &Version, upgrade: bool) -> Result<(), Error> {
    let python_dir = python_dir(version);
    if !upgrade && python_dir.exists() {
        return Ok(());
    }

    let downloads = downloads_dir();
    std::fs::create_dir_all(&downloads)?;

    let python = match pypy_releases()?
        .into_iter()
        .find(|python| python.version.compatible(version))
    {
        Some(python) => python,
        None => {
            return Err(Error::VersionNotFound(version.to_string()));
        }
    };
    let path = downloads.join(python.name);
    if upgrade || !path.exists() {
        download_file(python.url, &path)?;
    }
    extract_tar_bz2(&path, &python_dir)?;
    Ok(())
}

fn download_file(url: Url, target: &Path) -> Result<(), Error> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("lilyenv")
        .build()?;
    let response = client.get(url).send()?;
    let mut file = File::create(target)?;
    let mut content = std::io::Cursor::new(response.bytes()?);
    std::io::copy(&mut content, &mut file)?;
    Ok(())
}

fn extract_tar_gz(source: &Path, target: &Path) -> Result<(), std::io::Error> {
    let tar_gz = File::open(source)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(target)?;
    Ok(())
}

fn extract_tar_zst(source: &Path, target: &Path) -> Result<(), std::io::Error> {
    let tar_zst = File::open(source)?;
    let tar = ZstDecoder::new(tar_zst)?;
    let mut archive = Archive::new(tar);
    archive.unpack(target)?;
    Ok(())
}

fn extract_tar_bz2(source: &Path, target: &Path) -> Result<(), std::io::Error> {
    let tar_gz = File::open(source)?;
    let tar = BzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(target)?;
    Ok(())
}

fn fixup_sysconfig_paths(python_dir: &Path) -> Result<(), Error> {
    let root = python_dir.join("python");
    let lib = root
        .join("lib")
        .read_dir()?
        .collect::<Result<Vec<std::fs::DirEntry>, std::io::Error>>()?
        .into_iter()
        .find(|dir| dir.file_name().to_str().unwrap().starts_with("python"))
        .unwrap();
    let sysconfig = lib
        .path()
        .read_dir()?
        .collect::<Result<Vec<std::fs::DirEntry>, std::io::Error>>()?
        .into_iter()
        .find(|dir| {
            dir.file_name()
                .to_str()
                .unwrap()
                .contains("_sysconfigdata_")
        })
        .unwrap()
        .path();
    let data = std::fs::read_to_string(&sysconfig)?;
    let install_dir = root.to_str().unwrap();
    let data = data.replace("'/install", &format!("'{}", install_dir));
    let data = data.replace("\"/install", &format!("\"{}", install_dir));
    let data = data.replace(" /install", &format!(" {}", install_dir));
    let data = data.replace("=/install", &format!("={}", install_dir));
    std::fs::write(&sysconfig, data)?;

    let pkgconfig = root.join("lib").join("pkgconfig");
    for dir in pkgconfig.read_dir()? {
        let path = dir?.path();
        if path.is_symlink() {
            continue;
        }
        let data = std::fs::read_to_string(&path)?;
        let data = data.replace("=/install", &format!("={}", install_dir));
        std::fs::write(&path, data)?;
    }
    Ok(())
}

fn move_install(python_dir: &Path) -> Result<(), std::io::Error> {
    let temp = python_dir.join("temp");
    let python_dir = python_dir.join("python");
    let install = python_dir.join("install");
    std::fs::rename(&install, &temp)?;
    std::fs::remove_dir_all(&python_dir)?;
    std::fs::rename(&temp, &python_dir)?;
    Ok(())
}
