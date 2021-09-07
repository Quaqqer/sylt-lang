use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use crate::{Compiler, Name};
use sylt_parser::{
    AST, Assignable, AssignableKind, Expression, ExpressionKind, Identifier,
    Statement, StatementKind,
};
use sylt_parser::statement::NameIdentifier;

struct Context<'a> {
    compiler: &'a Compiler,
    namespace: usize,
    variables: Vec<String>,
}

impl Context<'_> {
    fn shadow(&mut self, variable: &String) {
        if !self.shadowed(variable) {
            self.variables.push(variable.clone());
        }
    }

    fn shadowed(&self, variable: &String) -> bool {
        return self.variables.iter().rfind(|&v| v == variable).is_some();
    }
}



fn assignable_dependencies(ctx: &mut Context, assignable: &Assignable, namespace: Option<usize>) -> HashSet<Name> {
    use AssignableKind::*;
    match &assignable.kind {
        Read(ident) => {
            // Might be shadowed here
            let shadowed = ctx.shadowed(&ident.name);
            let in_namespace = namespace.is_some();
            match ctx.compiler.namespaces[namespace.unwrap_or(ctx.namespace)].get(&ident.name) {
                Some(&name) if !shadowed && !in_namespace => {
                    [name].iter().cloned().collect()
                },
                _ => HashSet::new(),
            }
        },
        Call(ass, exprs) => assignable_dependencies(ctx, ass, namespace)
            .union(&exprs.iter()
                .map(|expr| dependencies(ctx, expr))
                .flatten()
                .collect()
            )
            .cloned()
            .collect(),
        ArrowCall(expr, ass, exprs) => dependencies(ctx, expr).iter()
            .chain(assignable_dependencies(ctx, ass, namespace).iter())
            .cloned()
            .chain(exprs.iter().map(|e| dependencies(ctx, e)).flatten())
            .collect(),
        Access(_, _) => {
            fn recursive_access(ctx: &mut Context, ass: &Assignable) -> (usize, HashSet<Name>) {
                match &ass.kind {
                    AssignableKind::Access(lhs, field) => {
                        let (namespace, mut deps) = recursive_access(ctx, lhs);
                        match ctx.compiler.namespaces[namespace].get(&field.name) {
                            Some(&name) => {
                                deps.insert(name);
                                let ns = if let Name::Namespace(ns) = name { ns } else { ctx.namespace };
                                (ns, deps)
                            }
                            None => (ctx.namespace, deps),
                        }
                    }
                    Read(ident) => {
                        // Might be shadowed here
                        let shadowed = ctx.shadowed(&ident.name);
                        match ctx.compiler.namespaces[ctx.namespace].get(&ident.name) {
                            Some(&name) if !shadowed => {
                                let ns = if let Name::Namespace(ns) = name { ns } else { ctx.namespace };
                                (ns, [name].iter().cloned().collect())
                            },
                            _ => (ctx.namespace, HashSet::new()),
                        }
                    }
                    _ => (ctx.namespace, assignable_dependencies(ctx, ass, None)),
                }
            }
            let (_, deps) = recursive_access(ctx, assignable);
            deps
        },
        Index(ass, expr) => assignable_dependencies(ctx, ass, namespace)
            .union(&dependencies(ctx, expr))
            .cloned()
            .collect(),
        Expression(expr) => dependencies(ctx, expr),
    }
}

fn statement_dependencies(ctx: &mut Context, statement: &Statement) -> HashSet<Name> {
    use StatementKind::*;
    match &statement.kind {
        Assignment { target, value, .. } => dependencies(ctx, value)
            .union(&assignable_dependencies(ctx, target, None))
            .cloned()
            .collect(),
        If { condition, pass, fail } => [
                dependencies(ctx, condition),
                statement_dependencies(ctx, pass),
                statement_dependencies(ctx, fail),
            ].iter()
            .flatten()
            .cloned()
            .collect(),
        Loop { condition, body } => dependencies(ctx, condition)
            .union(&statement_dependencies(ctx, body))
            .cloned()
            .collect(),
        Block { statements } => {
            let vars_before = ctx.variables.len();
            let deps = statements.iter()
                .map(|stmt| statement_dependencies(ctx, stmt))
                .flatten()
                .collect();
            ctx.variables.truncate(vars_before);
            deps
        },
        Definition { ident, value, .. } => {
            ctx.shadow(&ident.name);
            dependencies(ctx, value)
        },

        | Ret { value }
        | StatementExpression { value } => dependencies(ctx, value),

        | Use { .. }
        | Blob { .. }
        | IsCheck { .. }
        | Break
        | Continue
        | Unreachable
        | EmptyStatement => HashSet::new(),
    }
}

fn dependencies(ctx: &mut Context, expression: &Expression) -> HashSet<Name> {
    use ExpressionKind::*;
    match &expression.kind {

        Get(assignable) => assignable_dependencies(ctx, assignable, None),

        | Neg(expr)
        | Not(expr)
        | Duplicate(expr)
        | Parenthesis(expr) => dependencies(ctx, expr),

        | Comparison(lhs, _, rhs)
        | Add(lhs, rhs)
        | Sub(lhs, rhs)
        | Mul(lhs, rhs)
        | Div(lhs, rhs)
        | AssertEq(lhs, rhs)
        | And(lhs, rhs)
        | Or(lhs, rhs) => dependencies(ctx, lhs)
            .union(&dependencies(ctx, rhs))
            .cloned()
            .collect(),

        | IfExpression { condition, pass, fail }
        | IfShort { lhs: pass, condition, fail } => {
            [pass, fail, condition].iter()
                .map(|expr| dependencies(ctx, expr))
                .flatten()
                .collect()
        },

        // Functions are a bit special. They only create dependencies once
        // called, which is a problem. It is currently impossible to know when
        // a function is going to be called after being read, so for our
        // purposes defining the function requires all dependencies.
        Function { body, params, .. } => {
            let vars_before = ctx.variables.len();
            params.iter().for_each(|(ident, _)| ctx.shadow(&ident.name));
            let deps = statement_dependencies(ctx, body);
            ctx.variables.truncate(vars_before);
            deps
        },
        Instance { blob, fields } => {
            assignable_dependencies(ctx, blob, None).union(&fields.iter()
                .map(|(_, expr)| dependencies(ctx, expr))
                .flatten()
                .collect()
            )
            .cloned()
            .collect()
        },

        | Tuple(exprs)
        | List(exprs)
        | Set(exprs)
        | Dict(exprs) => {
            exprs.iter()
                .map(|expr| dependencies(ctx, expr))
                .flatten()
                .collect()
        },

        // No dependencies
        | TypeConstant(_)
        | Float(_)
        | Int(_)
        | Str(_)
        | Bool(_)
        | Nil => HashSet::new(),
    }
}

fn order(
    to_order: HashMap<Name, (HashSet<Name>, (&Statement, usize))>
) -> Result<Vec<(&Statement, usize)>, Vec<(&Statement, usize)>> {
    enum State {
        Inserting,
        Inserted,
    }

    fn recurse<'a>(
        name: Name,
        to_order: &HashMap<Name, (HashSet<Name>, (&'a Statement, usize))>,
        inserted: &mut HashMap<Name, State>,
        ordered: &mut Vec<(&'a Statement, usize)>
    ) -> Result<(), Vec<(&'a Statement, usize)>> {
        match inserted.entry(name) {
            Vacant(entry) => entry.insert(State::Inserting),
            Occupied(entry) => return match entry.get() {
                State::Inserting => Err(Vec::new()),
                State::Inserted => Ok(()),
            },
        };
        let (deps, statement) = to_order.get(&name).unwrap();
        for dep in deps {
            recurse(*dep, to_order, inserted, ordered)
                .map_err(|mut cycle| { cycle.push(*statement); cycle })?;
        }

        inserted.insert(name, State::Inserted);
        ordered.push(*statement);
        Ok(())
    }

    let mut ordered = Vec::new();
    let mut inserted = HashMap::new();
    for (name, _) in to_order.iter() {
        recurse(*name, &to_order, &mut inserted, &mut ordered)?;
    }

    Ok(ordered)
}

pub(crate) fn initialization_order<'a>(
    tree: &'a AST,
    compiler: &Compiler
) -> Result<Vec<(&'a Statement, usize)>, Vec<(&'a Statement, usize)>> {
    let path_to_namespace_id: HashMap<_, _> = compiler.namespace_id_to_path
        .iter()
        .map(|(a, b)| (b.clone(), *a))
        .collect();
    let mut to_order = HashMap::new();
    let mut is_checks = Vec::new();
    for (path, module) in tree.modules.iter() {
        let namespace = *path_to_namespace_id.get(path).unwrap();
        for statement in module.statements.iter() {
            use StatementKind::*;
            match &statement.kind {
                | Use { name: NameIdentifier::Implicit(Identifier { name, .. }), .. }
                | Use { name: NameIdentifier::Alias(Identifier { name, .. }), .. }
                | Blob { name, .. } => {
                    to_order.insert(
                        *compiler.namespaces[namespace].get(name).unwrap(),
                        (HashSet::new(), (statement, namespace))
                    );
                }
                Definition { ident, value, .. } => {
                    let mut ctx = Context {
                        compiler,
                        namespace,
                        variables: Vec::new(),
                    };
                    ctx.shadow(&ident.name);
                    let deps = dependencies(&mut ctx, value);
                    to_order.insert(
                        *compiler.namespaces[namespace].get(&ident.name).unwrap(),
                        (deps, (statement, namespace))
                    );
                }
                IsCheck { .. } => is_checks.push((statement, namespace)),
                _ => {}
            }
        }
    }
    return order(to_order).map(|mut o| { o.extend(is_checks); o });
}
