use nickel_lang_core::{
    eval::{cache::CacheImpl, value::NickelValue},
    program::Program,
    term::{IndexMap, RuntimeContract},
};
use serde::{Deserialize, Serialize};

use crate::{Error, StrPos, eval_if_closure, record_data_from_val};

/// The value of an attribute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttrValue {
    String(String, Option<StrPos>),
    Bool(bool),
    Number(f64),
    List(Vec<AttrValue>),
    Map(IndexMap<String, AttrValue>),
    EnumVariant(String, Box<AttrValue>),
}

impl Default for AttrValue {
    fn default() -> Self {
        AttrValue::String(String::new(), None)
    }
}

/// Maximum nesting depth accepted when constructing an [AttrValue].
///
/// Nickel evaluation forces one level of nesting per recursive call, so an
/// unbounded config aborts the process with a stack overflow during evaluation
/// before any error can be returned. Capping construction at the trust boundary
/// turns hostile or accidental deep nesting into a recoverable error.
const MAX_ATTR_DEPTH: usize = 128;

impl AttrValue {
    pub(crate) fn from_term(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<Option<Self>, Error> {
        Self::from_term_at(rt, program, 0)
    }

    fn from_term_at(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
        depth: usize,
    ) -> Result<Option<Self>, Error> {
        if depth > MAX_ATTR_DEPTH {
            return Err(Error::AttrTooDeep {
                max_depth: MAX_ATTR_DEPTH,
            });
        }
        let rt = eval_if_closure(rt, program)?;

        if let Some(s) = rt.as_string() {
            let pos = rt.pos(program.pos_table()).try_into().ok();
            return Ok(Some(Self::String(s.to_string(), pos)));
        }
        if let Some(b) = rt.as_bool() {
            return Ok(Some(Self::Bool(b)));
        }
        if let Some(v) = rt.as_number() {
            return Ok(Some(Self::Number(f64::try_from(v).unwrap())));
        }
        if let Some(tag) = rt.as_enum_tag() {
            return Ok(Some(Self::String(
                tag.into_label(),
                rt.pos(program.pos_table()).try_into().ok(),
            )));
        }
        if let Some(r) = record_data_from_val(&rt) {
            let mut map = IndexMap::with_capacity(6);
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    if let Some(val) = field.value.as_ref() {
                        let val = RuntimeContract::apply_all(
                            val.clone(),
                            field.pending_contracts.iter().cloned(),
                            val.pos_idx(),
                        );

                        if let Some(value) = Self::from_term_at(&val, program, depth + 1)? {
                            map.insert(ident_and_loc.label().to_string(), value);
                        }
                    }
                    Ok(())
                })?;
            return Ok(Some(Self::Map(map)));
        }
        if let Some(a) = rt.as_array() {
            return Ok(Some(Self::List(
                a.iter()
                    .map(|e| Self::from_term_at(e, program, depth + 1))
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten()
                    .collect(),
            )));
        }
        // Optional fields which are validated by a custom contract will come
        // across as this type - so we treat them as unset.
        if rt.type_of() == Some("CustomContract") {
            return Ok(None);
        }
        // Empty records (Container::Empty) - treat as empty map
        if crate::is_record(&rt) {
            return Ok(Some(Self::Map(IndexMap::default())));
        }
        if let Some(ev) = rt.as_enum_variant() {
            return Ok(Some(Self::EnumVariant(
                ev.tag.into_label(),
                Box::new(
                    Self::from_term_at(&ev.arg.clone().unwrap(), program, depth + 1)?.unwrap(),
                ),
            )));
        }

        todo!("error for unexpected attribute value type: {:?}", rt)
    }

    /// Returns the inner list, if this [AttrValue] is the list variant.
    pub fn as_list(&self) -> Option<&Vec<AttrValue>> {
        match self {
            Self::List(l) => Some(l),
            _ => None,
        }
    }
    /// Returns the inner map, if this [AttrValue] is the map variant.
    pub fn as_map(&self) -> Option<&IndexMap<String, AttrValue>> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
    /// Returns the inner string, if this [AttrValue] is the string variant.
    pub fn as_string(&self) -> Option<&String> {
        match self {
            Self::String(s, _) => Some(s),
            _ => None,
        }
    }
    /// Returns the inner bool, if this [AttrValue] is the bool variant.
    pub fn as_bool(&self) -> Option<&bool> {
        match self {
            Self::Bool(b) => Some(b),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;

    #[test]
    fn parse_str() {
        let (term, mut program, _origin, _target) =
            Loader::new("\"a\"", None, &LoadOptions::for_test())
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("load failed");
                })
                .finish()
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("finish failed");
                });

        assert!(matches!(
        AttrValue::from_term(&term, &mut program).unwrap().unwrap(),
        AttrValue::String(a, _) if a == "a",
        ));
    }
    #[test]
    fn parse_bool() {
        let (term, mut program, _origin, _target) =
            Loader::new("true", None, &LoadOptions::for_test())
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("load failed");
                })
                .finish()
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("finish failed");
                });

        assert_eq!(
            AttrValue::from_term(&term, &mut program).unwrap().unwrap(),
            AttrValue::Bool(true),
        );
    }
    #[test]
    fn parse_enum() {
        let (term, mut program, _origin, _target) =
            Loader::new("'Uwu", None, &LoadOptions::for_test())
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("load failed");
                })
                .finish()
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("finish failed");
                });

        assert!(matches!(
        AttrValue::from_term(&term, &mut program).unwrap().unwrap(),
        AttrValue::String(a, _) if a == "Uwu",
        ));
    }

    #[test]
    fn parse_record() {
        let (term, mut program, _origin, _target) =
            Loader::new("{key = \"a\"}", None, &LoadOptions::for_test())
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("load failed");
                })
                .finish()
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("finish failed");
                });

        let result = AttrValue::from_term(&term, &mut program).unwrap().unwrap();
        let map = result.as_map().unwrap();
        assert_eq!(map.len(), 1);
        assert!(matches!(map.get("key").unwrap(), AttrValue::String(a, _) if a == "a"));
    }

    #[test]
    fn parse_list() {
        let (term, mut program, _origin, _target) =
            Loader::new("[\"a\", \"b\"]", None, &LoadOptions::for_test())
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("load failed");
                })
                .finish()
                .unwrap_or_else(|e| {
                    e.report_to_stderr();
                    panic!("finish failed");
                });

        let result = AttrValue::from_term(&term, &mut program).unwrap().unwrap();
        let list = result.as_list().unwrap();
        assert_eq!(list.len(), 2);
        assert!(matches!(&list[0], AttrValue::String(a, _) if a == "a"));
        assert!(matches!(&list[1], AttrValue::String(a, _) if a == "b"));
    }

    /// Config that nests attribute values past the cap must surface a
    /// structured [`Error::AttrTooDeep`] rather than aborting the process with a
    /// stack overflow. Evaluation forces one level per nested list, so the
    /// assertion runs on a thread with a large stack to guarantee the cap is
    /// reached and reported before any overflow could occur.
    #[test]
    fn nesting_past_cap_errors_instead_of_overflowing() {
        let depth = MAX_ATTR_DEPTH + 32;
        let spec = format!("{}{}", "[".repeat(depth), "]".repeat(depth));

        // `Error` carries non-`Send` Nickel types, so match inside the worker
        // and hand back only a `Send` verdict string.
        let outcome: Result<(), String> = std::thread::Builder::new()
            .stack_size(128 * 1024 * 1024)
            .spawn(move || {
                let (term, mut program, _origin, _target) =
                    Loader::new(spec, None, &LoadOptions::for_test())
                        .unwrap()
                        .finish()
                        .unwrap();
                match AttrValue::from_term(&term, &mut program) {
                    Err(Error::AttrTooDeep { .. }) => Ok(()),
                    other => Err(format!("expected Error::AttrTooDeep, got {other:?}")),
                }
            })
            .unwrap()
            .join()
            .unwrap();

        outcome.expect("nesting past the cap should return a structured error");
    }

    #[test]
    fn unknown_attr_nickel_err() {
        let res = Loader::new(
            "let {Attrs, ..} = import \"minimal.ncl\" in {unknown_attr = \"a\"} | Attrs",
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish();

        assert!(res.is_err());
        assert!(matches!(res, Err(Error::Nickel(_))));
    }

    #[test]
    fn attr_wrong_schema_nickel_err() {
        let res = Loader::new(
            "let {Attrs, ..} = import \"minimal.ncl\" in {binary_from = \"blueberry://example.com/bersh.exe\"} | Attrs",
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish();

        assert!(res.is_err());
        assert!(matches!(res, Err(Error::Nickel(_))));
    }

    #[test]
    fn attr_binary_from_ok() {
        let res = Loader::new(
            "let {Attrs, ..} = import \"minimal.ncl\" in {binary_from = \"https://example.com/bersh.exe\"} | Attrs",
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish();

        assert!(res.is_ok());
    }

    #[test]
    fn attr_upstream_purl_ok() {
        let res = Loader::new(
            "let {Attrs, ..} = import \"minimal.ncl\" in {upstream_purl = \"pkg:npm/foobar@12.3.1?arch=i386&distro=jessie\"} | Attrs",
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish();

        assert!(res.is_ok());
    }
}
