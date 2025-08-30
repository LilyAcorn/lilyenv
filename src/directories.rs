use crate::version::Version;

fn lilyenv_dir() -> directories::ProjectDirs {
    directories::ProjectDirs::from("", "", "Lilyenv").expect("Could not find the home directory")
}

pub fn downloads_dir() -> std::path::PathBuf {
    lilyenv_dir().cache_dir().join("downloads")
}

pub fn python_dir(version: &Version) -> std::path::PathBuf {
    lilyenv_dir()
        .data_local_dir()
        .join("pythons")
        .join(version.to_string())
}

pub fn virtualenvs_dir() -> std::path::PathBuf {
    lilyenv_dir().data_local_dir().join("virtualenvs")
}

pub fn shell_file(project: Option<&str>) -> std::path::PathBuf {
    match project {
        None => lilyenv_dir().data_local_dir().join("shell"),
        Some(project) => project_dir(project).join("shell"),
    }
}

pub fn project_dir(project: &str) -> std::path::PathBuf {
    virtualenvs_dir().join(project)
}

pub fn virtualenv_dir(project: &str, version: &Version) -> std::path::PathBuf {
    project_dir(project).join(version.to_string())
}

pub fn project_file(project: &str) -> std::path::PathBuf {
    project_dir(project).join("directory")
}

pub fn is_downloaded(python_dir: &std::path::Path) -> std::io::Result<bool> {
    Ok(python_dir.exists() && std::fs::read_dir(python_dir)?.next().is_some())
}
