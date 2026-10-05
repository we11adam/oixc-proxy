use serde::{Deserialize, Serialize};

pub const MAX_USERINFO_AGE: u64 = 24 * 3600;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire: Option<u64>,
}

impl UserInfo {
    /// Parse the API's Subscription-Userinfo string. Missing traffic fields,
    /// duplicates, unknown fields and noninteger values do not become zeroes.
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() > 2048 || value.chars().any(char::is_control) {
            return None;
        }
        let mut fields = std::collections::HashMap::new();
        for part in value.split(';').filter(|part| !part.trim().is_empty()) {
            let (key, value) = part.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if !["upload", "download", "total", "expire"].contains(&key)
                || value.is_empty()
                || !value.bytes().all(|c| c.is_ascii_digit())
                || fields.insert(key, value.parse::<u64>().ok()?).is_some()
            {
                return None;
            }
        }
        let result = Self {
            upload: *fields.get("upload")?,
            download: *fields.get("download")?,
            total: *fields.get("total")?,
            expire: fields.get("expire").copied(),
        };
        result.valid().then_some(result)
    }

    pub fn valid(&self) -> bool {
        self.upload.checked_add(self.download).is_some()
            && self.expire.is_none_or(|time| time <= 253_402_300_799)
    }

    pub fn header(&self, fetched_at: Option<u64>, now: u64) -> Option<String> {
        let age = now.checked_sub(fetched_at?)?;
        if age > MAX_USERINFO_AGE || !self.valid() {
            return None;
        }
        let mut header = format!(
            "upload={}; download={}; total={}",
            self.upload, self.download, self.total
        );
        if let Some(expire) = self.expire {
            header.push_str(&format!("; expire={expire}"));
        }
        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_metadata_without_inventing_values_or_header_injection() {
        let info =
            UserInfo::parse("upload=0; download=100; total=1000; expire=1700000000").unwrap();
        assert_eq!(
            info.header(Some(10), 11).unwrap(),
            "upload=0; download=100; total=1000; expire=1700000000"
        );
        assert!(
            !UserInfo::parse("upload=1;download=2;total=3")
                .unwrap()
                .header(Some(10), 10)
                .unwrap()
                .contains("expire")
        );
        for raw in [
            "",
            "upload=0; download=0",
            "upload=-1; download=2; total=3",
            "upload=1;upload=2;download=2;total=3",
            "upload=1;download=2;total=3\r\nInjected: yes",
            "upload=1;download=2;total=18446744073709551616",
            "upload=1;download=2;total=3;expire=18446744073709551615",
        ] {
            assert!(UserInfo::parse(raw).is_none(), "{raw}");
        }
        assert!(info.header(None, 100).is_none());
        assert!(info.header(Some(10), 9).is_none());
        assert!(info.header(Some(10), 11 + MAX_USERINFO_AGE).is_none());
    }
}
