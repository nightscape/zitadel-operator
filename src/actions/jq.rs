use jaq_core::{
    data::JustLut,
    load::{Arena, File, Loader},
    unwrap_valr, Compiler, Ctx, Native, Vars,
};
use jaq_json::Val;
use serde_json::Value;
use thiserror::Error;

type Data = JustLut<Val>;

#[derive(Debug, Error, PartialEq)]
pub enum JqError {
    #[error("jq program does not compile: {0}")]
    Compile(String),
    #[error("jq program failed: {0}")]
    Run(String),
    #[error("jq program produced no output")]
    Empty,
}

/// A compiled jq program. Compilation is cheap enough to do per call, so no
/// instance of this outlives the request that made it — which keeps the jaq
/// types, none of which are `Send`, out of the async machinery.
pub struct Program {
    filter: jaq_core::compile::Filter<Native<Data>>,
}

impl Program {
    pub fn compile(code: &str) -> Result<Self, JqError> {
        let loader = Loader::new(
            jaq_core::defs()
                .chain(jaq_std::defs())
                .chain(jaq_json::defs()),
        );
        let arena = Arena::default();
        let modules = loader
            .load(&arena, File { code, path: () })
            .map_err(|e| JqError::Compile(format!("{e:?}")))?;
        let filter = Compiler::default()
            .with_funs(
                jaq_core::funs()
                    .chain(jaq_std::funs())
                    .chain(jaq_json::funs()),
            )
            .compile(modules)
            .map_err(|e| JqError::Compile(format!("{e:?}")))?;
        Ok(Self { filter })
    }

    /// Runs the program and returns its first output. A program with several
    /// outputs is a program whose author meant something the payload cannot
    /// express, so the rest are dropped.
    pub fn run(&self, input: &Value) -> Result<Value, JqError> {
        let bytes = serde_json::to_vec(input).expect("serde_json::Value always serialises");
        let input = jaq_json::read::parse_single(&bytes)
            .map_err(|e| JqError::Run(format!("payload is not JSON: {e:?}")))?;
        let ctx = Ctx::<Data>::new(&self.filter.lut, Vars::new([]));
        let mut out = self.filter.id.run((ctx, input)).map(unwrap_valr);
        match out.next() {
            Some(Ok(value)) => serde_json::from_str(&value.to_string())
                .map_err(|e| JqError::Run(format!("output is not JSON: {e}"))),
            Some(Err(e)) => Err(JqError::Run(format!("{e:?}"))),
            None => Err(JqError::Empty),
        }
    }

    /// jq truthiness: everything but `false` and `null`.
    pub fn test(&self, input: &Value) -> Result<bool, JqError> {
        Ok(!matches!(self.run(input)?, Value::Null | Value::Bool(false)))
    }
}
