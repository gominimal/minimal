use nickel_lang_core::{
    eval::cache::CacheImpl,
    program::Program,
    term::{IndexMap, RichTerm, Term},
};

use crate::{Error, eval_if_closure};

/// The value of an attribute.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AttrValue {
    String(String),
    Bool(bool),
    List(Vec<AttrValue>),
    Map(IndexMap<String, AttrValue>),
    EnumVariant(String, Box<AttrValue>),
}

impl Default for AttrValue {
    fn default() -> Self {
        AttrValue::String(String::new())
    }
}

impl AttrValue {
    pub(crate) fn from_term(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<Option<Self>, Error> {
        let rt = eval_if_closure(rt, program)?;

        Ok(match rt.term.as_ref() {
            Term::Str(s) => Some(Self::String(s.to_string())),
            Term::Bool(b) => Some(Self::Bool(*b)),
            Term::Enum(a) => Some(Self::String(a.into_label())),
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                let mut map = IndexMap::with_capacity(6);
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        if let Some(value) =
                            AttrValue::from_term(field.value.as_ref().unwrap(), program)?
                        {
                            map.insert(ident_and_loc.label().to_string(), value);
                        }
                        Ok(())
                    })?;
                Some(Self::Map(map))
            }
            Term::Array(e, _attrs) => Some(Self::List(
                e.iter()
                    .map(|e| AttrValue::from_term(e, program))
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten()
                    .collect(),
            )),
            // Optional fields which are validated by a custom contract will come
            // across as this type - so we treat them as unset.
            Term::CustomContract(_) => None,
            Term::EnumVariant { tag, arg, attrs: _ } => Some(Self::EnumVariant(
                tag.into_label(),
                Box::new(AttrValue::from_term(arg, program)?.unwrap()),
            )),
            _ => todo!(
                "error for unexpected attribute value type: {:?}",
                rt.term.as_ref()
            ),
        })
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
            Self::String(s) => Some(s),
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
        let (term, mut program, _origin) = Loader::new("\"a\"", &LoadOptions::for_test())
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
            AttrValue::String("a".to_string()),
        );
    }
    #[test]
    fn parse_bool() {
        let (term, mut program, _origin) = Loader::new("true", &LoadOptions::for_test())
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
        let (term, mut program, _origin) = Loader::new("'Uwu", &LoadOptions::for_test())
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
            AttrValue::String("Uwu".to_string()),
        );
    }

    #[test]
    fn parse_record() {
        let (term, mut program, _origin) = Loader::new("{key = \"a\"}", &LoadOptions::for_test())
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
            AttrValue::Map(IndexMap::from_iter([(
                "key".to_string(),
                AttrValue::String("a".to_string())
            )])),
        );
    }

    #[test]
    fn parse_list() {
        let (term, mut program, _origin) = Loader::new("[\"a\", \"b\"]", &LoadOptions::for_test())
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
            AttrValue::List(vec![
                AttrValue::String("a".to_string()),
                AttrValue::String("b".to_string()),
            ]),
        );
    }

    #[test]
    fn unknown_attr_nickel_err() {
        let res = Loader::new(
            "let {Attrs, ..} = import \"minimal.ncl\" in {unknown_attr = \"a\"} | Attrs",
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
            "let {Attrs, ..} = import \"minimal.ncl\" in {env_state_wiring = \"a\"} | Attrs",
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
}
