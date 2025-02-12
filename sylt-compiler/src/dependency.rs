use crate::{Compiler, Name};
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use sylt_parser::statement::NameIdentifier;
use sylt_parser::{
    Assignable, AssignableKind, Expression, ExpressionKind, Identifier, Statement, StatementKind,
    Type as ParserType, TypeAssignable, TypeAssignableKind, TypeKind, AST,
};

struct Context<'a> {
    compiler: &'a Compiler,
    namespace: usize,
    variables: Vec<String>,
}

impl Context<'_> {
    fn shadow(&mut self, variable: &str) {
        if !self.shadowed(variable) {
            self.variables.push(variable.to_string());
        }
    }

    fn shadowed(&self, variable: &str) -> bool {
        return self.variables.iter().rfind(|&v| v == variable).is_some();
    }
}

fn assignable_dependencies(
    ctx: &mut Context,
    assignable: &Assignable,
) -> BTreeSet<(String, usize)> {
    use AssignableKind::*;
    match &assignable.kind {
        Variant { enum_ass, value, .. } => assignable_dependencies(ctx, enum_ass)
            .union(&dependencies(ctx, value))
            .cloned()
            .collect(),
        Read(ident) => match ctx.compiler.namespaces[ctx.namespace].get(&ident.name) {
            Some(_) if !ctx.shadowed(&ident.name) => [(ident.name.clone(), ctx.namespace)]
                .iter()
                .cloned()
                .collect(),
            _ => BTreeSet::new(),
        },
        Call(ass, exprs) => assignable_dependencies(ctx, ass)
            .union(
                &exprs
                    .iter()
                    .map(|expr| dependencies(ctx, expr))
                    .flatten()
                    .collect(),
            )
            .cloned()
            .collect(),
        ArrowCall(expr, ass, exprs) => dependencies(ctx, expr)
            .iter()
            .chain(assignable_dependencies(ctx, ass).iter())
            .cloned()
            .chain(exprs.iter().map(|e| dependencies(ctx, e)).flatten())
            .collect(),
        Access(ass, field) => {
            // Get namespace access recursively
            // NOTE: This will ignore the actual namespace as a dependency, which
            // is not a problem since the compiler already initializes namespaces
            // before the dependency analysis.
            fn recursive_namespace(ctx: &mut Context, ass: &Assignable) -> Result<usize, ()> {
                match &ass.kind {
                    Access(lhs, field) => {
                        let namespace = recursive_namespace(ctx, lhs)?;
                        match ctx.compiler.namespaces[namespace].get(&field.name) {
                            Some(Name::Namespace(ns)) => Ok(*ns),
                            _ => Err(()),
                        }
                    }
                    Read(ident) => {
                        // Might be shadowed here
                        let shadowed = ctx.shadowed(&ident.name);
                        match ctx.compiler.namespaces[ctx.namespace].get(&ident.name) {
                            Some(Name::Namespace(ns)) if !shadowed => Ok(*ns),
                            _ => Err(()),
                        }
                    }
                    _ => Err(()),
                }
            }
            match recursive_namespace(ctx, ass) {
                Ok(namespace) => match ctx.compiler.namespaces[namespace].get(&field.name) {
                    Some(_) => [(field.name.clone(), namespace)].iter().cloned().collect(),
                    _ => BTreeSet::new(),
                },
                Err(_) => assignable_dependencies(ctx, ass),
            }
        }
        Index(ass, expr) => assignable_dependencies(ctx, ass)
            .union(&dependencies(ctx, expr))
            .cloned()
            .collect(),
        Expression(expr) => dependencies(ctx, expr),
    }
}

fn type_assignable_dependencies(
    ctx: &mut Context,
    assignable: &TypeAssignable,
) -> BTreeSet<(String, usize)> {
    use TypeAssignableKind::*;
    match &assignable.kind {
        Read(ident) => match ctx.compiler.namespaces[ctx.namespace].get(&ident.name) {
            Some(_) => [(ident.name.clone(), ctx.namespace)]
                .iter()
                .cloned()
                .collect(),
            _ => BTreeSet::new(),
        },
        Access(ass, field) => {
            // Get namespace access recursively
            // NOTE: This will ignore the actual namespace as a dependency, which
            // is not a problem since the compiler already initializes namespaces
            // before the dependency analysis.
            fn recursive_namespace(ctx: &mut Context, ass: &TypeAssignable) -> Result<usize, ()> {
                match &ass.kind {
                    Access(lhs, field) => {
                        let namespace = recursive_namespace(ctx, lhs)?;
                        match ctx.compiler.namespaces[namespace].get(&field.name) {
                            Some(Name::Namespace(ns)) => Ok(*ns),
                            _ => Err(()),
                        }
                    }
                    Read(ident) => match ctx.compiler.namespaces[ctx.namespace].get(&ident.name) {
                        Some(Name::Namespace(ns)) => Ok(*ns),
                        _ => Err(()),
                    },
                }
            }
            match recursive_namespace(ctx, ass) {
                Ok(namespace) => match ctx.compiler.namespaces[namespace].get(&field.name) {
                    Some(_) => [(field.name.clone(), namespace)].iter().cloned().collect(),
                    _ => BTreeSet::new(),
                },
                Err(_) => BTreeSet::new(),
            }
        }
    }
}

fn type_dependencies(ctx: &mut Context, ty: &ParserType) -> BTreeSet<(String, usize)> {
    use TypeKind::*;
    match &ty.kind {
        Implied | Resolved(_) | Generic(_) => BTreeSet::new(),

        Grouping(ty) => type_dependencies(ctx, ty),
        UserDefined(assignable) => type_assignable_dependencies(ctx, &assignable),

        Fn { params, ret, .. } => params
            .iter()
            .chain([ret.as_ref()])
            .map(|t| type_dependencies(ctx, t))
            .flatten()
            .collect(),

        Tuple(fields) => fields
            .iter()
            .map(|t| type_dependencies(ctx, t))
            .flatten()
            .collect(),

        List(kind) | Set(kind) => type_dependencies(ctx, kind),

        Dict(a, b) => [type_dependencies(ctx, a), type_dependencies(ctx, b)]
            .iter()
            .flatten()
            .cloned()
            .collect(),
    }
}

fn statement_dependencies(ctx: &mut Context, statement: &Statement) -> BTreeSet<(String, usize)> {
    use StatementKind::*;
    match &statement.kind {
        Assignment { target, value, .. } => dependencies(ctx, value)
            .union(&assignable_dependencies(ctx, target))
            .cloned()
            .collect(),

        If { condition, pass, fail } => [
            dependencies(ctx, condition),
            statement_dependencies(ctx, pass),
            statement_dependencies(ctx, fail),
        ]
        .iter()
        .flatten()
        .cloned()
        .collect(),

        Case { to_match, branches, fall_through } => [
            dependencies(ctx, to_match),
            statement_dependencies(ctx, fall_through),
        ]
        .iter()
        .cloned()
        .chain(
            branches
                .iter()
                .map(|branch| statement_dependencies(ctx, &branch.body))
                .collect::<BTreeSet<_>>(),
        )
        .flatten()
        .collect(),

        Loop { condition, body } => dependencies(ctx, condition)
            .union(&statement_dependencies(ctx, body))
            .cloned()
            .collect(),

        Block { statements } => {
            let vars_before = ctx.variables.len();
            let deps = statements
                .iter()
                .map(|stmt| statement_dependencies(ctx, stmt))
                .flatten()
                .collect();
            ctx.variables.truncate(vars_before);
            deps
        }

        Definition { ident, value, ty, .. } => {
            ctx.shadow(&ident.name);
            dependencies(ctx, value)
                .union(&type_dependencies(ctx, ty))
                .cloned()
                .collect()
        }

        Ret { value } | StatementExpression { value } => dependencies(ctx, value),

        ExternalDefinition { ty, .. } => type_dependencies(ctx, ty),

        Blob { name, fields: sub_types } | Enum { name, variants: sub_types } => {
            ctx.shadow(&name);
            sub_types
                .values()
                .map(|t| type_dependencies(ctx, t))
                .flatten()
                .collect()
        }

        // If it seems weird that From statements have dependencies, just think
        // of them as several reads at the same time (spoiler: that's what they are).
        FromUse { file, imports, .. } => {
            let old_ns = ctx.namespace;
            ctx.namespace = ctx
                .compiler
                .namespace_id_to_path
                .iter()
                .find_map(|(ns, path)| if path == file { Some(*ns) } else { None })
                .unwrap();
            let deps = imports
                .iter()
                .map(|(name, _)| {
                    assignable_dependencies(
                        ctx,
                        &Assignable {
                            span: name.span,
                            kind: AssignableKind::Read(name.clone()),
                        },
                    )
                })
                .flatten()
                .collect();
            ctx.namespace = old_ns;
            deps
        }

        Break | Continue | EmptyStatement | IsCheck { .. } | Unreachable | Use { .. } => {
            BTreeSet::new()
        }
    }
}

fn dependencies(ctx: &mut Context, expression: &Expression) -> BTreeSet<(String, usize)> {
    use ExpressionKind::*;
    match &expression.kind {
        Get(assignable) => assignable_dependencies(ctx, assignable),

        Neg(expr) | Not(expr) | Parenthesis(expr) => dependencies(ctx, expr),

        Comparison(lhs, _, rhs)
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

        IfExpression { condition, pass, fail } => [pass, fail, condition]
            .iter()
            .map(|expr| dependencies(ctx, expr))
            .flatten()
            .collect(),

        // Functions are a bit special. They only create dependencies once
        // called, which is a problem. It is currently impossible to know when
        // a function is going to be called after being read, so for our
        // purposes defining the function requires all dependencies.
        Function { body, params, .. } => {
            let vars_before = ctx.variables.len();
            params.iter().for_each(|(ident, _)| ctx.shadow(&ident.name));
            let type_deps = params
                .iter()
                .map(|(_, ty)| type_dependencies(ctx, ty))
                .flatten()
                .collect();
            let deps = statement_dependencies(ctx, body);
            ctx.variables.truncate(vars_before);
            [deps, type_deps].iter().flatten().cloned().collect()
        }
        Blob { blob, fields } => type_assignable_dependencies(ctx, blob)
            .union(
                &fields
                    .iter()
                    .map(|(_, expr)| dependencies(ctx, expr))
                    .flatten()
                    .collect(),
            )
            .cloned()
            .collect(),

        Tuple(exprs) | List(exprs) | Set(exprs) | Dict(exprs) => exprs
            .iter()
            .map(|expr| dependencies(ctx, expr))
            .flatten()
            .collect(),

        // No dependencies
        Float(_) | Int(_) | Str(_) | Bool(_) | Nil => BTreeSet::new(),
    }
}

fn order(
    to_order: BTreeMap<(String, usize), (BTreeSet<(String, usize)>, (&Statement, usize))>,
) -> Result<Vec<(&Statement, usize)>, Vec<(&Statement, usize)>> {
    enum State {
        Inserting,
        Inserted,
    }

    fn recurse<'a>(
        global: &(String, usize),
        to_order: &BTreeMap<(String, usize), (BTreeSet<(String, usize)>, (&'a Statement, usize))>,
        inserted: &mut BTreeMap<(String, usize), State>,
        ordered: &mut Vec<(&'a Statement, usize)>,
    ) -> Result<(), Vec<(&'a Statement, usize)>> {
        match inserted.entry(global.clone()) {
            Vacant(entry) => entry.insert(State::Inserting),
            Occupied(entry) => {
                return match entry.get() {
                    State::Inserting => Err(Vec::new()),
                    State::Inserted => Ok(()),
                }
            }
        };

        let (deps, statement) = to_order.get(&global).expect(&format!(
            "Trying to find an identifier that does not exist ({:?})",
            global.0
        ));
        for dep in deps {
            recurse(dep, to_order, inserted, ordered).map_err(|mut cycle| {
                cycle.push(*statement);
                cycle
            })?;
        }
        ordered.push(*statement);
        inserted.insert(global.clone(), State::Inserted);

        Ok(())
    }

    let mut ordered = Vec::new();
    let mut inserted = BTreeMap::new();
    for (name, _) in to_order.iter() {
        recurse(name, &to_order, &mut inserted, &mut ordered)?;
    }

    Ok(ordered)
}

pub(crate) fn initialization_order<'a>(
    tree: &'a AST,
    compiler: &Compiler,
) -> Result<Vec<(&'a Statement, usize)>, Vec<(&'a Statement, usize)>> {
    let path_to_namespace_id: HashMap<_, _> = compiler
        .namespace_id_to_path
        .iter()
        .map(|(a, b)| (b.clone(), *a))
        .collect();
    let mut to_order = BTreeMap::new();
    let mut is_checks = Vec::new();
    for (path, module) in tree.modules.iter() {
        let namespace = path_to_namespace_id[path];
        for statement in module.statements.iter() {
            use StatementKind::*;
            match &statement.kind {
                FromUse { imports, .. } => {
                    let mut ctx = Context { compiler, namespace, variables: Vec::new() };
                    imports.iter().for_each(|(ident, alias)| {
                        let name = &alias.as_ref().unwrap_or(ident).name;
                        to_order.insert(
                            (name.clone(), namespace),
                            (
                                statement_dependencies(&mut ctx, statement),
                                (statement, namespace),
                            ),
                        );
                    });
                }

                Blob { name, .. }
                | Enum { name, .. }
                | Use {
                    name: NameIdentifier::Implicit(Identifier { name, .. }),
                    ..
                }
                | Use {
                    name: NameIdentifier::Alias(Identifier { name, .. }),
                    ..
                }
                | ExternalDefinition { ident: Identifier { name, .. }, .. }
                | Definition { ident: Identifier { name, .. }, .. } => {
                    let mut ctx = Context { compiler, namespace, variables: Vec::new() };
                    to_order.insert(
                        (name.clone(), namespace),
                        (
                            statement_dependencies(&mut ctx, statement),
                            (statement, namespace),
                        ),
                    );
                }

                IsCheck { .. } => is_checks.push((statement, namespace)),

                _ => {}
            }
        }
    }
    return order(to_order).map(|mut o| {
        o.extend(is_checks);
        o
    });
}
