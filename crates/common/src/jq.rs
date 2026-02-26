use std::path::Path;

use jaq_all::jaq_core::Filter;
use jaq_all::jaq_core::ValT;
use jaq_all::jaq_core::{Ctx, Vars, data::JustLut};
use jaq_all::json::Val;

/// An error when working with a jq predicate or filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JqError {
    pub err: String,

    pub relevant_file: Option<String>,
    pub relevant_jq: Option<String>,
}

/// Parses the given bytes based on heuristics regarding the given path (i.e. file extension).
pub fn parse_file<P: AsRef<Path>>(path: P, data: Vec<u8>) -> Result<Val, JqError> {
    match path.as_ref().extension().map(|oss| oss.to_str()) {
        Some(Some("toml")) => Ok(jaq_all::fmts::read::toml::parse(
            &String::from_utf8(data).map_err(|e| JqError {
                err: e.to_string(),
                relevant_file: Some(path.as_ref().to_str().unwrap().to_string()),
                relevant_jq: None,
            })?,
        )
        .map_err(|e| JqError {
            err: e.to_string(),
            relevant_file: Some(path.as_ref().to_str().unwrap().to_string()),
            relevant_jq: None,
        })?),
        Some(Some("json")) => Ok(jaq_all::fmts::read::json::parse_single(&data).unwrap()),
        _ => Err(JqError {
            err: "cannot handle file extension".to_string(),
            relevant_file: Some(path.as_ref().to_str().unwrap().to_string()),
            relevant_jq: None,
        }),
    }
}

/// A compiled jq expression.
pub struct Expression {
    raw: String,
    filter: Filter<JustLut<Val>>,
}

impl Expression {
    pub fn parse(filter_str: &str) -> Result<Self, JqError> {
        match jaq_all::compile_with(
            filter_str,
            jaq_all::jaq_std::defs().chain(jaq_all::json::defs()),
            jaq_all::jaq_std::funs().chain(jaq_all::json::funs()),
            &[],
        ) {
            Ok(filter) => Ok(Expression {
                filter,
                raw: filter_str.to_string(),
            }),
            Err(error) => Err(JqError {
                err: format!("{:?}", error),
                relevant_file: None,
                relevant_jq: Some(filter_str.to_string()),
            }),
        }
    }

    pub fn predicate_eval(&self, input: Val) -> Result<bool, JqError> {
        let ctx = Ctx::<JustLut<Val>>::new(&self.filter.lut, Vars::new([]));

        match self.filter.id.run((ctx, input)).next() {
            Some(Ok(v)) => Ok(v.as_bool()),
            Some(Err(e)) => Err(JqError {
                err: format!("{:?}", e),
                relevant_file: None,
                relevant_jq: Some(self.raw.clone()),
            }),
            None => Err(JqError {
                err: "predicate yielded no result".to_string(),
                relevant_file: None,
                relevant_jq: Some(self.raw.clone()),
            }),
        }
    }
}
