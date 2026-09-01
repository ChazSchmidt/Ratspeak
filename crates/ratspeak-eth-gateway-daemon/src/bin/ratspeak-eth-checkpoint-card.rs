use std::path::PathBuf;

fn main() {
    let Some(path) = parse_config_path(std::env::args_os().skip(1)) else {
        std::process::exit(2);
    };
    if ratspeak_eth_gateway_daemon::checkpoint_card::run(&path).is_err() {
        eprintln!(
            "checkpoint card generation failed: invalid configuration, provider response, or output boundary"
        );
        std::process::exit(1);
    }
}

fn parse_config_path(mut args: impl Iterator<Item = std::ffi::OsString>) -> Option<PathBuf> {
    let flag = args.next()?;
    let path = PathBuf::from(args.next()?);
    if flag != "--config" || args.next().is_some() || !path.is_absolute() {
        return None;
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::parse_config_path;
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn arguments_require_one_absolute_config_path() {
        assert_eq!(
            parse_config_path(
                [OsString::from("--config"), OsString::from("/tmp/card.json")].into_iter()
            ),
            Some(PathBuf::from("/tmp/card.json"))
        );
        for args in [
            vec![],
            vec![OsString::from("--wrong"), OsString::from("/tmp/card.json")],
            vec![OsString::from("--config")],
            vec![OsString::from("--config"), OsString::from("relative.json")],
            vec![
                OsString::from("--config"),
                OsString::from("/tmp/card.json"),
                OsString::from("extra"),
            ],
        ] {
            assert_eq!(parse_config_path(args.into_iter()), None);
        }
    }
}
