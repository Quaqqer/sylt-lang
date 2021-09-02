use std::cell::RefCell;
use std::collections::{hash_map::Entry, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use sylt_common::error::Error;
use sylt_common::prog::Prog;
use sylt_common::{Blob, Block, Op, RustFunction, Type, Value};
use sylt_parser::expression::ComparisonKind;
use sylt_parser::statement::NameIdentifier;
use sylt_parser::{
    Context as ParserContext,
    Assignable, AssignableKind, Expression, ExpressionKind, Identifier, Module, Op as ParserOp,
    Span, Statement, StatementKind, Type as ParserType, TypeKind, VarKind, AST,
};

mod typechecker;

type VarSlot = usize;

#[derive(Debug, Clone)]
struct Variable {
    name: String,
    ty: Type,
    slot: usize,
    line: usize,
    kind: VarKind,

    captured: bool,
    active: bool,
}

impl Variable {
    fn new(name: String, kind: VarKind, ty: Type, slot: usize, span: Span) -> Self {
        Self {
            name,
            ty,
            slot,
            kind,
            line: span.line,

            captured: false,
            active: false,
        }
    }
}

#[derive(Debug, Clone)]
struct Upvalue {
    parent: usize,
    upupvalue: bool,

    name: String,
    ty: Type,
    slot: usize,
    line: usize,
    kind: VarKind,
}

enum Lookup {
    Upvalue(Upvalue),
    Variable(Variable),
}

impl Upvalue {
    fn capture(var: &Variable) -> Self {
        Self {
            parent: var.slot,
            upupvalue: false,

            name: var.name.clone(),
            ty: var.ty.clone(),
            slot: 0,
            line: var.line,
            kind: var.kind,
        }
    }

    fn loft(up: &Upvalue) -> Self {
        Self {
            parent: up.slot,
            upupvalue: true,
            slot: 0,
            ..up.clone()
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct Context {
    block_slot: BlockID,
    namespace: NamespaceID,
    scope: usize,
    frame: usize,
}

impl Context {
    fn from_namespace(namespace: NamespaceID) -> Self {
        Self {
            namespace,
            block_slot: 0,
            scope: 0,
            frame: 0,
        }
    }
}

type Namespace = HashMap<String, Name>;
type ConstantID = usize;
type NamespaceID = usize;
type BlobID = usize;
type BlockID = usize;
#[derive(Debug, Copy, Clone)]
enum Name {
    Global(ConstantID),
    Blob(BlobID),
    Namespace(NamespaceID),
}

#[derive(Debug, Copy, Clone)]
struct LoopFrame {
    continue_addr: usize,
    break_addr: usize,
    stack_size: usize,
}

#[derive(Debug)]
/// Emulates the runtime stackframe.
/// [variables] and [upvalues] are used like stacks.
struct Frame {
    variables: Vec<Variable>,
    upvalues: Vec<Upvalue>,
}

impl Frame {
    fn new(name: &str, span: Span) -> Self {
        let variables = vec![Variable::new(
            name.to_string(),
            VarKind::Const,
            Type::Void,
            0,
            span,
        )];
        Self {
            variables,
            upvalues: Vec::new(),
        }
    }
}

struct Compiler {
    blocks: Vec<Block>,
    namespace_id_to_path: HashMap<NamespaceID, PathBuf>,

    namespaces: Vec<Namespace>,
    blobs: Vec<Blob>,

    loops: Vec<LoopFrame>,
    frames: Vec<Frame>,
    functions: HashMap<String, (usize, RustFunction, Type)>,

    panic: bool,
    errors: Vec<Error>,

    strings: Vec<String>,
    constants: Vec<Value>,

    values: HashMap<Value, usize>,
}

#[macro_export]
macro_rules! error {
    ($compiler:expr, $ctx:expr, $span:expr, $( $msg:expr ),+ ) => {
        if !$compiler.panic {
            $compiler.panic = true;

            let msg = format!($( $msg ),*).into();
            let err = Error::CompileError {
                file: $compiler.file_from_namespace($ctx.namespace).into(),
                span: $span,
                message: Some(msg),
            };
            $compiler.errors.push(err);
        }
    };
}

impl Compiler {
    fn new() -> Self {
        Self {
            blocks: Vec::new(),

            namespace_id_to_path: HashMap::new(),
            namespaces: Vec::new(),
            blobs: Vec::new(),

            loops: Vec::new(),
            frames: Vec::new(),
            functions: HashMap::new(),

            panic: false,
            errors: Vec::new(),

            strings: Vec::new(),
            constants: Vec::new(),

            values: HashMap::new(),
        }
    }

    fn push_frame_and_block(&mut self, ctx: Context, name: &str, span: Span) -> Context {
        let file_as_path = PathBuf::from(self.file_from_namespace(ctx.namespace));

        let block = Block::new(&name, ctx.namespace, &file_as_path);
        self.blocks.push(block);

        self.frames.push(Frame::new(name, span));
        Context {
            block_slot: self.blocks.len() - 1,
            frame: self.frames.len() - 1,
            ..ctx
        }
    }

    fn pop_frame(&mut self, ctx: Context) -> Frame {
        assert_eq!(
            self.frames.len() - 1,
            ctx.frame,
            "Can only pop top stackframe"
        );
        self.frames.pop().unwrap()
    }

    fn file_from_namespace(&self, namespace: usize) -> &Path {
        self.namespace_id_to_path.get(&namespace).unwrap()
    }

    fn string(&mut self, string: &str) -> usize {
        self.strings
            .iter()
            .enumerate()
            .find_map(|(i, x)| if x == string { Some(i) } else { None })
            .unwrap_or_else(|| {
                let slot = self.strings.len();
                self.strings.push(string.into());
                slot
            })
    }

    fn constant(&mut self, value: Value) -> Op {
        let slot = match self.values.entry(value.clone()) {
            Entry::Vacant(e) => {
                let slot = self.constants.len();
                e.insert(slot);
                self.constants.push(value);
                slot
            }
            Entry::Occupied(e) => *e.get(),
        };
        Op::Constant(slot)
    }

    fn add_op(&mut self, ctx: Context, span: Span, op: Op) -> usize {
        self.blocks
            .get_mut(ctx.block_slot)
            .expect("Invalid block id")
            .add(op, span.line)
    }

    fn patch(&mut self, ctx: Context, ip: usize, op: Op) {
        self.blocks
            .get_mut(ctx.block_slot)
            .expect("Invalid block id")
            .ops[ip] = op;
    }

    fn next_ip(&mut self, ctx: Context) -> usize {
        self.blocks
            .get_mut(ctx.block_slot)
            .expect("Invalid block id")
            .curr()
    }

    fn emit_pop_until_size(&mut self, ctx: Context, span: Span, target_size: usize) {
        let vars: Vec<_> = self.frames[ctx.frame].variables.iter().skip(target_size).rev().cloned().collect();
        for var in &vars {
            if var.captured {
                self.add_op(ctx, span, Op::PopUpvalue);
            } else {
                self.add_op(ctx, span, Op::Pop);
            }
        }
    }

    fn pop_until_size(&mut self, ctx: Context, span: Span, target_size: usize) {
        self.emit_pop_until_size(ctx, span, target_size);
        self.frames[ctx.frame].variables.truncate(target_size);
    }

    fn assignable(&mut self, ass: &Assignable, ctx: Context) -> Option<usize> {
        use AssignableKind::*;

        match &ass.kind {
            Read(ident) => {
                return self.read_identifier(&ident.name, ass.span, ctx, ctx.namespace);
            }
            Call(f, expr) => {
                self.assignable(f, ctx);
                for expr in expr.iter() {
                    self.expression(expr, ctx);
                }
                self.add_op(ctx, ass.span, Op::Call(expr.len()));
            }
            ArrowCall(pre, f, expr) => {
                self.expression(pre, ctx);
                self.assignable(f, ctx);
                self.add_op(ctx, ass.span, Op::Swap);
                for expr in expr.iter() {
                    self.expression(expr, ctx);
                }
                self.add_op(ctx, ass.span, Op::Call(expr.len() + 1));
            }
            Access(a, field) => {
                if let Some(namespace) = self.assignable(a, ctx) {
                    return self.read_identifier(&field.name, field.span, ctx, namespace);
                } else {
                    let slot = self.string(&field.name);
                    self.add_op(ctx, field.span, Op::GetField(slot));
                }
            }
            Index(a, b) => {
                self.assignable(a, ctx);
                if let ExpressionKind::Int(n) = b.kind {
                    self.add_op(ctx, ass.span, Op::GetConstIndex(n));
                } else {
                    self.expression(b, ctx);
                    self.add_op(ctx, ass.span, Op::GetIndex);
                }
            }
            Expression(expr) => {
                self.expression(expr, ctx);
            }
        }
        None
    }

    fn un_op(&mut self, a: &Expression, ops: &[Op], span: Span, ctx: Context) {
        self.expression(&a, ctx);
        for op in ops {
            self.add_op(ctx, span, *op);
        }
    }

    fn bin_op(&mut self, a: &Expression, b: &Expression, ops: &[Op], span: Span, ctx: Context) {
        self.expression(&a, ctx);
        self.expression(&b, ctx);
        for op in ops {
            self.add_op(ctx, span, *op);
        }
    }

    fn push(&mut self, value: Value, span: Span, ctx: Context) {
        let value = self.constant(value);
        self.add_op(ctx, span, value);
    }

    fn expression(&mut self, expression: &Expression, ctx: Context) {
        use ComparisonKind::*;
        use ExpressionKind::*;

        match &expression.kind {
            Get(a) => {
                self.assignable(a, ctx);
            }

            TypeConstant(ty) => {
                let resolved_ty = self.resolve_type(ty, ctx);
                let ty_constant = self.constant(Value::Ty(resolved_ty));
                self.add_op(ctx, expression.span, ty_constant);
            }

            Add(a, b) => self.bin_op(a, b, &[Op::Add], expression.span, ctx),
            Sub(a, b) => self.bin_op(a, b, &[Op::Sub], expression.span, ctx),
            Mul(a, b) => self.bin_op(a, b, &[Op::Mul], expression.span, ctx),
            Div(a, b) => self.bin_op(a, b, &[Op::Div], expression.span, ctx),

            Comparison(a, cmp, b) => match cmp {
                Equals => self.bin_op(a, b, &[Op::Equal], expression.span, ctx),
                NotEquals => self.bin_op(a, b, &[Op::Equal, Op::Not], expression.span, ctx),
                Greater => self.bin_op(a, b, &[Op::Greater], expression.span, ctx),
                GreaterEqual => self.bin_op(a, b, &[Op::Less, Op::Not], expression.span, ctx),
                Less => self.bin_op(a, b, &[Op::Less], expression.span, ctx),
                LessEqual => self.bin_op(a, b, &[Op::Greater, Op::Not], expression.span, ctx),
                Is => self.bin_op(a, b, &[Op::Is], expression.span, ctx),
                In => self.bin_op(a, b, &[Op::Contains], expression.span, ctx),
            }

            AssertEq(a, b) => self.bin_op(a, b, &[Op::Equal, Op::Assert], expression.span, ctx),

            Neg(a) => self.un_op(a, &[Op::Neg], expression.span, ctx),

            And(a, b) => {
                self.expression(a, ctx);

                self.add_op(ctx, expression.span, Op::Copy(1));
                let jump = self.add_op(ctx, expression.span, Op::Illegal);
                self.add_op(ctx, expression.span, Op::Pop);

                self.expression(b, ctx);

                let op = Op::JmpFalse(self.next_ip(ctx));
                self.patch(ctx, jump, op);
            }
            Or(a, b) => {
                self.expression(a, ctx);

                self.add_op(ctx, expression.span, Op::Copy(1));
                let skip = self.add_op(ctx, expression.span, Op::Illegal);
                let jump = self.add_op(ctx, expression.span, Op::Illegal);

                let op = Op::JmpFalse(self.next_ip(ctx));
                self.patch(ctx, skip, op);
                self.add_op(ctx, expression.span, Op::Pop);

                self.expression(b, ctx);
                let op = Op::Jmp(self.next_ip(ctx));
                self.patch(ctx, jump, op);
            }
            Not(a) => self.un_op(a, &[Op::Not], expression.span, ctx),

            Duplicate(a) => self.un_op(a, &[Op::Copy(1)], expression.span, ctx),

            Parenthesis(expr) => self.expression(expr, ctx),

            IfExpression {
                condition,
                pass,
                fail,
            } => {
                self.expression(condition, ctx);

                let skip = self.add_op(ctx, expression.span, Op::Illegal);

                self.expression(pass, ctx);
                let out = self.add_op(ctx, expression.span, Op::Illegal);
                let op = Op::JmpFalse(self.next_ip(ctx));
                self.patch(ctx, skip, op);

                self.expression(fail, ctx);
                let op = Op::Jmp(self.next_ip(ctx));
                self.patch(ctx, out, op);

                self.add_op(ctx, expression.span, Op::Union);
            }

            IfShort {
                condition,
                fail,
                ..
            } => {
                // Results in 2 values pushed on the stack - since there's a Duplicate in
                // there!
                self.expression(condition, ctx);

                let skip = self.add_op(ctx, expression.span, Op::Illegal);
                let out = self.add_op(ctx, expression.span, Op::Illegal);

                // Only done during the typechecker - mitigates the pop-operation
                // so the types can be compound.
                self.add_op(ctx, expression.span, Op::Copy(1));

                let op = Op::JmpFalse(self.next_ip(ctx));
                self.patch(ctx, skip, op);

                self.add_op(ctx, expression.span, Op::Pop);
                self.expression(fail, ctx);
                let op = Op::Jmp(self.next_ip(ctx));
                self.patch(ctx, out, op);

                self.add_op(ctx, expression.span, Op::Union);
            }


            Function {
                name,
                params,
                ret,
                body,
            } => {
                let file = self.file_from_namespace(ctx.namespace).display();
                let name = format!("fn {} {}:{}", name, file, expression.span.line);

                // === Frame begin ===
                let inner_ctx = self.push_frame_and_block(ctx, &name, expression.span);
                let mut param_types = Vec::new();
                for (ident, ty) in params.iter() {
                    param_types.push(self.resolve_type(&ty, inner_ctx));
                    let param = self.define(&ident.name, VarKind::Const, ident.span);
                    self.activate(param);
                }
                let ret = self.resolve_type(&ret, inner_ctx);
                let ty = Type::Function(param_types, Box::new(ret));
                self.blocks[inner_ctx.block_slot].ty = ty.clone();

                self.statement(&body, inner_ctx);

                if !all_paths_return(&body) {
                    let nil = self.constant(Value::Nil);
                    self.add_op(inner_ctx, body.span, nil);
                    self.add_op(inner_ctx, body.span, Op::Return);
                }

                self.blocks[inner_ctx.block_slot].upvalues = self
                    .pop_frame(inner_ctx)
                    .upvalues
                    .into_iter()
                    .map(|u| (u.parent, u.upupvalue, u.ty))
                    .collect();
                let function = Value::Function(Rc::new(Vec::new()), ty, inner_ctx.block_slot);
                // === Frame end ===

                let function = self.constant(function);
                self.add_op(ctx, expression.span, function);
            }

            Instance { blob, fields } => {
                self.assignable(blob, ctx);
                for (name, field) in fields.iter() {
                    let name = self.constant(Value::Field(name.clone()));
                    self.add_op(ctx, field.span, name);
                    self.expression(field, ctx);
                }
                self.add_op(ctx, expression.span, Op::Call(fields.len() * 2));
            }

            Tuple(x) | List(x) | Set(x) | Dict(x) => {
                for expr in x.iter() {
                    self.expression(expr, ctx);
                }
                self.add_op(
                    ctx,
                    expression.span,
                    match &expression.kind {
                        Tuple(_) => Op::Tuple(x.len()),
                        List(_) => Op::List(x.len()),
                        Set(_) => Op::Set(x.len()),
                        Dict(_) => Op::Dict(x.len()),
                        _ => unreachable!(),
                    },
                );
            }

            Float(a) => self.push(Value::Float(*a), expression.span, ctx),
            Bool(a) => self.push(Value::Bool(*a), expression.span, ctx),
            Int(a) => self.push(Value::Int(*a), expression.span, ctx),
            Str(a) => self.push(Value::String(Rc::new(a.clone())), expression.span, ctx),
            Nil => self.push(Value::Nil, expression.span, ctx),
        }
    }

    fn resolve_and_capture(&mut self, name: &str, frame: usize, span: Span) -> Result<Lookup, ()> {
        // Frame 0 has globals which cannot be captured.
        if frame == 0 {
            return Err(());
        }

        let variables = &self.frames[frame].variables;
        for var in variables.iter().rev() {
            if &var.name == name && var.active {
                return Ok(Lookup::Variable(var.clone()));
            }
        }

        let upvalues = &self.frames[frame].upvalues;
        for up in upvalues.iter().rev() {
            if &up.name == name {
                return Ok(Lookup::Upvalue(up.clone()));
            }
        }

        let up = match self.resolve_and_capture(name, frame - 1, span) {
            Ok(Lookup::Upvalue(up)) => Upvalue::loft(&up),
            Ok(Lookup::Variable(var)) => Upvalue::capture(&var),
            _ => {
                return Err(());
            }
        };
        let up = self.upvalue(up, frame);
        Ok(Lookup::Upvalue(up))
    }

    fn read_identifier(
        &mut self,
        name: &str,
        span: Span,
        ctx: Context,
        namespace: usize,
    ) -> Option<usize> {
        match self.resolve_and_capture(name, ctx.frame, span) {
            Ok(Lookup::Upvalue(up)) => {
                let op = Op::ReadUpvalue(up.slot);
                self.add_op(ctx, span, op);
            }

            Ok(Lookup::Variable(var)) => {
                let op = Op::ReadLocal(var.slot);
                self.add_op(ctx, span, op);
            }

            Err(()) => match self.namespaces[namespace].get(name) {
                Some(Name::Global(slot)) => {
                    let op = Op::ReadGlobal(*slot);
                    self.add_op(ctx, span, op);
                }
                Some(Name::Blob(blob)) => {
                    let op = Op::Constant(*blob);
                    self.add_op(ctx, span, op);
                }
                Some(Name::Namespace(new_namespace)) => return Some(*new_namespace),
                None => {
                    if let Some((slot, _, _)) = self.functions.get(name) {
                        let slot = *slot;
                        let op = self.constant(Value::ExternFunction(slot));
                        self.add_op(ctx, span, op);
                    } else {
                        error!(
                            self,
                            ctx,
                            span,
                            "Cannot read '{}' in '{}'",
                            name,
                            self.file_from_namespace(namespace).display()
                        );
                    }
                }
            },
        }
        None
    }

    fn set_identifier(&mut self, name: &str, span: Span, ctx: Context, namespace: usize) {
        match self.resolve_and_capture(name, ctx.frame, span) {
            Ok(Lookup::Upvalue(up)) => {
                let op = Op::AssignUpvalue(up.slot);
                self.add_op(ctx, span, op);
                return;
            }

            Ok(Lookup::Variable(var)) => {
                let op = Op::AssignLocal(var.slot);
                self.add_op(ctx, span, op);
                return;
            }

            Err(()) => match self.namespaces[namespace].get(name) {
                Some(Name::Global(slot)) => {
                    let var = &self.frames[0].variables[*slot];
                    if var.kind.immutable() && ctx.frame != 0 {
                        error!(self, ctx, span, "Cannot mutate constant '{}'", name);
                    } else {
                        let op = Op::AssignGlobal(var.slot);
                        self.add_op(ctx, span, op);
                    }
                }

                _ => {
                    error!(
                        self,
                        ctx,
                        span,
                        "Cannot assign '{}' in '{}'",
                        name,
                        self.file_from_namespace(namespace).display()
                    );
                }
            },
        }
    }

    fn resolve_type_namespace(
        &mut self,
        assignable: &Assignable,
        namespace: usize,
        ctx: Context,
    ) -> Option<usize> {
        use AssignableKind::*;
        match &assignable.kind {
            Access(inner, ident) => self
                .resolve_type_namespace(&inner, namespace, ctx)
                .and_then(|namespace| self.namespaces[namespace].get(&ident.name))
                .and_then(|o| match o {
                    Name::Namespace(namespace) => Some(*namespace),
                    _ => None,
                })
                .or_else(|| {
                    error!(
                        self,
                        ctx,
                        assignable.span,
                        "While parsing namespace access '{}' is not a namespace",
                        ident.name
                    );
                    None
                }),
            Read(ident) => {
                self
                .namespaces[namespace].get(&ident.name)
                .and_then(|o| match o {
                    Name::Namespace(namespace) => Some(*namespace),
                    _ => None,
                })
                .or_else(|| {
                    error!(
                        self,
                        ctx,
                        assignable.span,
                        "While parsing namespace '{}' is not a namespace",
                        ident.name
                    );
                None
                })
            }
            ArrowCall(..) | Call(..) => {
                error!(self, ctx, assignable.span, "Cannot have calls in types");
                None
            }
            Index(_, _) => {
                error!(self, ctx, assignable.span, "Cannot have indexing in types");
                None
            }
            Expression(_) => {
                error!(self, ctx, assignable.span, "Cannot have expressions in types");
                None
            }
        }
    }

    fn resolve_type_ident(
        &mut self,
        assignable: &Assignable,
        namespace: usize,
        ctx: Context,
    ) -> Type {
        use AssignableKind::*;
        match &assignable.kind {
            Read(ident) => self.namespaces[namespace]
                .get(&ident.name)
                .and_then(|name| match name {
                    Name::Blob(blob) => Some(Type::Instance(*blob)),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    error!(
                        self,
                        ctx, assignable.span, "While parsing type '{}' is not a blob", ident.name
                    );
                    Type::Void
                }),
            Access(inner, ident) => self
                .resolve_type_namespace(&inner, namespace, ctx)
                .and_then(|namespace| self.namespaces[namespace].get(&ident.name))
                .and_then(|name| match name {
                    Name::Blob(blob) => Some(Type::Instance(*blob)),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    error!(
                        self,
                        ctx, assignable.span, "While parsing type '{}' is not a blob", ident.name
                    );
                    Type::Void
                }),
            ArrowCall(..) | Call(..) => {
                error!(self, ctx, assignable.span, "Cannot have calls in types");
                Type::Void
            }
            Index(..) => {
                error!(self, ctx, assignable.span, "Cannot have indexing in types");
                Type::Void
            }
            Expression(_) => {
                error!(self, ctx, assignable.span, "Cannot have expressions in types");
                Type::Void
            }
        }
    }

    fn resolve_type(&mut self, ty: &ParserType, ctx: Context) -> Type {
        use TypeKind::*;
        match &ty.kind {
            Implied => Type::Unknown,
            Resolved(ty) => ty.clone(),
            UserDefined(assignable) => self.resolve_type_ident(&assignable, ctx.namespace, ctx),
            Union(a, b) => match (self.resolve_type(a, ctx), self.resolve_type(b, ctx)) {
                (Type::Union(_), _) => panic!("Didn't expect union on RHS - check parser"),
                (a, Type::Union(mut us)) => {
                    us.insert(a);
                    Type::Union(us)
                }
                (a, b) => Type::Union(vec![a, b].into_iter().collect()),
            },
            Fn(params, ret) => {
                let params = params.iter().map(|t| self.resolve_type(t, ctx)).collect();
                let ret = Box::new(self.resolve_type(ret, ctx));
                Type::Function(params, ret)
            }
            Tuple(fields) => {
                Type::Tuple(fields.iter().map(|t| self.resolve_type(t, ctx)).collect())
            }
            List(kind) => Type::List(Box::new(self.resolve_type(kind, ctx))),
            Set(kind) => Type::Set(Box::new(self.resolve_type(kind, ctx))),
            Dict(key, value) => Type::Dict(
                Box::new(self.resolve_type(key, ctx)),
                Box::new(self.resolve_type(value, ctx)),
            ),
            Generic(name) => Type::Generic(name.name.clone()),
        }
    }

    fn define(&mut self, name: &str, kind: VarKind, span: Span) -> VarSlot {
        let frame = &mut self.frames.last_mut().unwrap().variables;
        let slot = frame.len();
        let var = Variable::new(name.to_string(), kind, Type::Unknown, slot, span);
        frame.push(var);
        slot
    }

    fn upvalue(&mut self, mut up: Upvalue, frame: usize) -> Upvalue {
        let ups = &mut self.frames[frame].upvalues;
        let slot = ups.len();
        up.slot = slot;
        ups.push(up.clone());
        up
    }

    fn activate(&mut self, slot: VarSlot) {
        self.frames.last_mut().unwrap().variables[slot].active = true;
    }

    fn statement(&mut self, statement: &Statement, ctx: Context) {
        use StatementKind::*;
        self.panic = false;

        match &statement.kind {
            Use { .. } | EmptyStatement => {}

            Blob { name, fields } => {
                if let Some(Name::Blob(slot)) = self.namespaces[ctx.namespace].get(name) {
                    let slot = *slot;
                    self.blobs[slot].fields = fields
                        .clone()
                        .into_iter()
                        .map(|(k, v)| (k, self.resolve_type(&v, ctx)))
                        .collect();
                } else {
                    error!(
                        self,
                        ctx,
                        statement.span,
                        "No blob with the name '{}' in this namespace (#{})",
                        name,
                        ctx.namespace
                    );
                }
            }

            IsCheck { lhs, rhs } => {
                let lhs = self.resolve_type(lhs, ctx);
                let rhs = self.resolve_type(rhs, ctx);
                if let Err(msg) = rhs.fits(&lhs, &self.blobs) {
                    error!(
                        self,
                        ctx, statement.span,
                        "Is-check failed - {}",
                        msg
                    );
                }
            }

            #[rustfmt::skip]
            Definition { ident, kind, ty, value } => {
                // TODO(ed): Don't use type here - type check the tree first.
                self.expression(value, ctx);

                if ctx.frame == 0 {
                    // Global
                    self.set_identifier(&ident.name, statement.span, ctx, ctx.namespace);
                } else {
                    // Local variable
                    let slot = self.define(&ident.name, *kind, statement.span);
                    let ty = self.resolve_type(ty, ctx);
                    let op = if let Op::Constant(ty) = self.constant(Value::Ty(ty)) {
                        if kind.force() {
                            Op::Force(ty)
                        } else {
                            Op::Define(ty)
                        }
                    } else {
                        error!(self, ctx, statement.span, "Failed to add type declaration");
                        Op::Illegal
                    };
                    self.add_op(ctx, statement.span, op);
                    self.activate(slot);
                }
            }

            #[rustfmt::skip]
            Assignment { target, value, kind } => {
                use AssignableKind::*;
                use ParserOp::*;

                let mutator = |kind| matches!(kind, Add | Sub | Mul | Div);

                let write_mutator_op = |comp: &mut Self, ctx, kind| {
                    let op = match kind {
                        Add => Op::Add,
                        Sub => Op::Sub,
                        Mul => Op::Mul,
                        Div => Op::Div,
                        Nop => {
                            return;
                        }
                    };
                    comp.add_op(ctx, statement.span, op);
                };

                match &target.kind {
                    Read(ident) => {
                        if mutator(*kind) {
                            self.read_identifier(&ident.name, statement.span, ctx, ctx.namespace);
                        }
                        self.expression(value, ctx);

                        write_mutator_op(self, ctx, *kind);

                        self.set_identifier(&ident.name, statement.span, ctx, ctx.namespace);
                    }
                    ArrowCall(..) | Call(..) => {
                        error!(
                            self,
                            ctx, statement.span, "Cannot assign to result from function call"
                        );
                    }
                    Access(a, field) => {
                        if let Some(namespace) = self.assignable(a, ctx) {
                            if mutator(*kind) {
                                self.read_identifier(&field.name, statement.span, ctx, namespace);
                            }
                            self.expression(value, ctx);

                            write_mutator_op(self, ctx, *kind);

                            self.set_identifier(&field.name, statement.span, ctx, namespace);
                        } else {
                            let slot = self.string(&field.name);

                            if mutator(*kind) {
                                self.add_op(ctx, statement.span, Op::Copy(1));
                                self.add_op(ctx, field.span, Op::GetField(slot));
                            }
                            self.expression(value, ctx);

                            write_mutator_op(self, ctx, *kind);

                            self.add_op(ctx, field.span, Op::AssignField(slot));
                        }
                    }
                    Index(a, b) => {
                        self.assignable(a, ctx);
                        self.expression(b, ctx);

                        if mutator(*kind) {
                            self.add_op(ctx, statement.span, Op::Copy(2));
                            self.add_op(ctx, statement.span, Op::GetIndex);
                        }
                        self.expression(value, ctx);
                        write_mutator_op(self, ctx, *kind);

                        self.add_op(ctx, statement.span, Op::AssignIndex);
                    }
                    Expression(_) => {
                        unreachable!("Cannot assign to 'AssignableKind::Expression'");
                    }
                }
            }

            StatementExpression { value } => {
                self.expression(value, ctx);
                self.add_op(ctx, statement.span, Op::Pop);
            }

            Block { statements } => {
                let stack_size = self.frames[ctx.frame].variables.len();

                for statement in statements {
                    self.statement(statement, ctx);
                }

                self.pop_until_size(ctx, statement.span, stack_size);
            }

            Loop { condition, body } => {
                let start = self.next_ip(ctx);
                self.expression(condition, ctx);
                let jump_from = self.add_op(ctx, condition.span, Op::Illegal);

                // Skip the next op - it's for the break
                //  start: .. condition ..
                //         JmpFalse(over)
                //  break: Jmp(end)
                //   over: .. loop ..
                //    end: ..
                self.add_op(ctx, condition.span, Op::Jmp(jump_from + 3));
                let break_from = self.add_op(ctx, condition.span, Op::Illegal);

                let stack_size = self.frames[ctx.frame].variables.len();
                self.loops.push(LoopFrame {
                    continue_addr: start,
                    break_addr: break_from,
                    stack_size,
                });
                self.statement(body, ctx);
                self.loops.pop();

                self.add_op(ctx, body.span, Op::Jmp(start));
                let out = self.next_ip(ctx);
                self.patch(ctx, jump_from, Op::JmpFalse(out));
                self.patch(ctx, break_from, Op::Jmp(out));
            }

            #[rustfmt::skip]
            If { condition, pass, fail } => {
                self.expression(condition, ctx);

                let jump_from = self.add_op(ctx, condition.span, Op::Illegal);
                self.statement(pass, ctx);
                let jump_out = self.add_op(ctx, condition.span, Op::Illegal);
                self.statement(fail, ctx);

                self.patch(ctx, jump_from, Op::JmpFalse(jump_out + 1));

                let end = self.next_ip(ctx);
                self.patch(ctx, jump_out, Op::Jmp(end));
            }

            Continue {} => match self.loops.last().cloned() {
                Some(LoopFrame { stack_size, continue_addr, .. }) => {
                    // TODO(ed): Remove this crutch when the typechecker is fixed.
                    // We emit dummy values that are popped in the typechecker.
                    let type_checker_skip = self.add_op(ctx, statement.span, Op::Illegal);
                    let current_stack_size = self.frames[ctx.frame].variables.len();
                    let nil = self.constant(Value::Nil);
                    for _ in 0..(current_stack_size - stack_size) {
                        self.add_op(ctx, statement.span, nil);
                    }
                    let end = self.next_ip(ctx);
                    self.patch(ctx, type_checker_skip, Op::Jmp(end));

                    self.emit_pop_until_size(ctx, statement.span, stack_size);
                    self.add_op(ctx, statement.span, Op::Jmp(continue_addr));
                }
                None => {
                    error!(self, ctx, statement.span, "`continue` statement not in a loop");
                }
            }

            Break {} => match self.loops.last().cloned() {
                Some(LoopFrame { stack_size, break_addr, .. }) => {
                    // TODO(ed): Remove this crutch when the typechecker is fixed.
                    // We emit dummy values that are popped in the typechecker.
                    let type_checker_skip = self.add_op(ctx, statement.span, Op::Illegal);
                    let current_stack_size = self.frames[ctx.frame].variables.len();
                    let nil = self.constant(Value::Nil);
                    for _ in 0..(current_stack_size - stack_size) {
                        self.add_op(ctx, statement.span, nil);
                    }
                    let end = self.next_ip(ctx);
                    self.patch(ctx, type_checker_skip, Op::Jmp(end));

                    self.emit_pop_until_size(ctx, statement.span, stack_size);
                    self.add_op(ctx, statement.span, Op::Jmp(break_addr));
                }
                None => {
                    error!(self, ctx, statement.span, "`continue` statement not in a loop");
                }
            }

            Unreachable {} => {
                self.add_op(ctx, statement.span, Op::Unreachable);
            }

            Ret { value } => {
                self.expression(value, ctx);
                self.add_op(ctx, statement.span, Op::Return);
            }
        }
    }

    fn module_functions(&mut self, module: &Module, ctx: Context) {
        for statement in module.statements.iter() {
            match statement.kind {
                StatementKind::Definition {
                    value:
                        Expression {
                            kind: ExpressionKind::Function { .. },
                            ..
                        },
                    ..
                } => {
                    self.statement(statement, ctx);
                }
                _ => (),
            }
        }
    }

    fn module_not_functions(&mut self, module: &Module, ctx: Context) {
        for statement in module.statements.iter() {
            match statement.kind {
                StatementKind::Definition {
                    value:
                        Expression {
                            kind: ExpressionKind::Function { .. },
                            ..
                        },
                    ..
                } => (),
                _ => {
                    self.statement(statement, ctx);
                }
            }
        }
    }

    fn compile(
        mut self,
        typecheck: bool,
        mut tree: AST,
        functions: &[(String, RustFunction, String)],
    ) -> Result<Prog, Vec<Error>> {
        assert!(!tree.modules.is_empty(), "Cannot compile an empty program");
        let name = "/preamble/";
        let mut block = Block::new(name, 0, &tree.modules[0].0);
        block.ty = Type::Function(Vec::new(), Box::new(Type::Void));
        self.blocks.push(block);
        self.frames.push(Frame::new(name, Span::zero()));
        let mut ctx = Context {
            block_slot: self.blocks.len() - 1,
            frame: self.frames.len() - 1,
            ..Context::from_namespace(0)
        };

        let path_to_namespace_id = self.extract_globals(&tree);

        let num_functions = functions.len();
        self.functions = functions
            .to_vec()
            .into_iter()
            .enumerate()
            .map(|(i, (s, f, sig))| (s.clone(), (i, f, self.resolve_type(&parse_signature(&s, &sig), ctx))))
            .collect();
        assert_eq!(
            num_functions,
            self.functions.len(),
            "There are {} names and {} extern functions - some extern functions share name",
            self.functions.len(),
            num_functions
        );


        for (path, module) in tree.modules.iter() {
            ctx.namespace = path_to_namespace_id[path];
            self.module_functions(module, ctx);
        }

        for (path, module) in tree.modules.iter() {
            ctx.namespace = path_to_namespace_id[path];
            self.module_not_functions(module, ctx);
        }

        if !self.errors.is_empty() {
            return Err(self.errors);
        }

        if typecheck {
            typechecker::solve(&mut self, &mut tree, &path_to_namespace_id)?;
        }

        self.read_identifier("start", Span::zero(), ctx, 0);
        self.add_op(ctx, Span::zero(), Op::Call(0));

        let module = &tree.modules[0].1;
        let nil = self.constant(Value::Nil);
        self.add_op(ctx, module.span, nil);
        self.add_op(ctx, module.span, Op::Return);

        self.pop_frame(ctx);

        if self.errors.is_empty() {
            Ok(Prog {
                blocks: self
                    .blocks
                    .into_iter()
                    .map(|x| Rc::new(RefCell::new(x)))
                    .collect(),
                functions: functions.iter().map(|(_, f, _)| *f).collect(),
                blobs: self.blobs,
                constants: self.constants,
                strings: self.strings,
            })
        } else {
            Err(self.errors)
        }
    }

    // TODO(ed): This should probably be cleaned up and moves out of the compiler?
    fn extract_globals(&mut self, tree: &AST) -> HashMap<PathBuf, usize> {
        let mut path_to_namespace_id = HashMap::<PathBuf, usize>::new();
        for (path, _) in tree.modules.iter() {
            let slot = path_to_namespace_id.len();
            match path_to_namespace_id.entry(path.into()) {
                Entry::Vacant(vac) => {
                    vac.insert(slot);
                    self.namespaces.push(Namespace::new());
                }

                Entry::Occupied(_) => {
                    error!(
                        self,
                        Context::from_namespace(slot),
                        Span::zero(),
                        "Reading file '{}' twice! How?",
                        path.display()
                    );
                }
            }
        }

        self.namespace_id_to_path = path_to_namespace_id
            .iter()
            .map(|(a, b)| (*b, (*a).clone()))
            .collect();

        for (path, module) in tree.modules.iter() {
            let slot = path_to_namespace_id[path];
            let ctx = Context::from_namespace(slot);

            let mut namespace = self.namespaces[slot].clone();
            for statement in module.statements.iter() {
                use StatementKind::*;
                match &statement.kind {
                    Blob { name, .. } => match namespace.entry(name.to_owned()) {
                        Entry::Vacant(_) => {
                            let id = self.blobs.len();
                            self.blobs.push(crate::Blob::new(id, slot, name));
                            let blob = self.constant(Value::Blob(id));
                            if let Op::Constant(slot) = blob {
                                namespace.insert(name.to_owned(), Name::Blob(slot));
                            } else {
                                unreachable!();
                            }
                        }

                        Entry::Occupied(_) => {
                            error!(
                                self,
                                ctx,
                                statement.span,
                                "A global variable with the name '{}' already exists",
                                name
                            );
                        }
                    },

                    // Handled below.
                    _ => (),
                }
            }
            self.namespaces[slot] = namespace;
        }

        for (path, module) in tree.modules.iter() {
            let slot = path_to_namespace_id[path];
            let ctx = Context::from_namespace(slot);

            let mut namespace = self.namespaces[slot].clone();
            for statement in module.statements.iter() {
                use StatementKind::*;
                match &statement.kind {
                    Use { path: _, name, file } => {
                        let ident = match name {
                            NameIdentifier::Implicit(ident) => ident,
                            NameIdentifier::Alias(ident) => ident,
                        };
                        match namespace.entry(ident.name.clone()) {
                            Entry::Vacant(vac) => {
                                let other = path_to_namespace_id[file];
                                vac.insert(Name::Namespace(other));
                            }
                            Entry::Occupied(_) => {
                                error!(
                                    self,
                                    ctx,
                                    ident.span,
                                    "A global variable with the name '{}' already exists",
                                    ident.name
                                );
                            }
                        }
                    }

                    // Already handled in the loop before.
                    Blob { .. } => (),

                    // Handled in the loop after - so namespaces are structured correctly.
                    Definition { .. } => {}

                    // Handled later - since we need the type information.
                    IsCheck { .. } => (),

                    _ => (),
                }
            }
            self.namespaces[slot] = namespace;
        }

        for (path, module) in tree.modules.iter() {
            let slot = path_to_namespace_id[path];
            let ctx = Context::from_namespace(slot);

            let mut namespace = self.namespaces[slot].clone();
            for statement in module.statements.iter() {
                use StatementKind::*;
                match &statement.kind {
                    #[rustfmt::skip]
                    Definition { ident: Identifier { name, .. }, kind, ty, .. } => {
                        let var = self.define(name, *kind, statement.span);
                        self.activate(var);

                        match namespace.entry(name.to_owned()) {
                            Entry::Vacant(_) => {
                                namespace.insert(name.to_owned(), Name::Global(var));
                            }
                            Entry::Occupied(_) => {
                                error!(
                                    self,
                                    ctx,
                                    statement.span,
                                    "A global variable with the name '{}' already exists",
                                    name
                                );
                            }
                        }

                        // Just fill in an empty slot since we have no idea.
                        // Unknown is overwritten by the Op::Force in the type checker.
                        let unknown = self.constant(Value::Unknown);
                        self.add_op(ctx, Span::zero(), unknown);

                        let ty = self.resolve_type(ty, ctx);
                        let op = if let Op::Constant(ty) = self.constant(Value::Ty(ty)) {
                            Op::Force(ty)
                        } else {
                            error!(self, ctx, statement.span, "Failed to resolve the type");
                            Op::Illegal
                        };
                        self.add_op(ctx, Span::zero(), op);
                    }

                    Use { ..  } => { }

                    // Already handled in the loop before.
                    Blob { .. } => (),

                    // Handled later - since we need the type information.
                    IsCheck { .. } => (),

                    // Valid here, just ignore it.
                    EmptyStatement => (),

                    _ => {
                        error!(self, ctx, statement.span, "Invalid outer statement");
                    }
                }
            }
            self.namespaces[slot] = namespace;
        }
        path_to_namespace_id
    }
}

// TODO(ed): Move this up into sylt?
fn parse_signature(func_name: &str, sig: &str) -> ParserType {
    let token_stream = sylt_tokenizer::string_to_tokens(sig);
    let tokens: Vec<_> = token_stream.iter().map(|p| p.token.clone()).collect();
    let spans: Vec<_> = token_stream.iter().map(|p| p.span).collect();
    let path = PathBuf::from(func_name);
    let ctx = ParserContext::new(&tokens, &spans, &path, &path);
    match sylt_parser::parse_type(ctx) {
        Ok((_, ty)) => ty,
        Err((_, errs)) => {
            for err in errs {
                eprintln!("{}", err);
            }
            panic!("Error parsing function signature for {}", func_name);
        }
    }
}

pub fn compile(typecheck: bool, prog: AST, functions: &[(String, RustFunction, String)]) -> Result<Prog, Vec<Error>> {
    Compiler::new().compile(typecheck, prog, functions)
}

fn all_paths_return(statement: &Statement) -> bool {
    match &statement.kind {
        StatementKind::Use { .. }
        | StatementKind::Blob { .. }
        | StatementKind::IsCheck { .. }
        | StatementKind::Assignment { .. }
        | StatementKind::Definition { .. }
        | StatementKind::StatementExpression { .. }
        | StatementKind::Unreachable
        | StatementKind::Continue
        | StatementKind::Break
        | StatementKind::EmptyStatement => false,

        StatementKind::If { pass, fail, .. } => all_paths_return(pass) && all_paths_return(fail),

        StatementKind::Loop { body, .. } => all_paths_return(body),
        StatementKind::Block { statements } => statements.iter().any(all_paths_return),

        StatementKind::Ret { .. } => true,
    }
}

pub(crate) fn first_ok_or_errs<I, T, E>(mut iter: I) -> Result<T, Vec<E>>
where I: Iterator<Item = Result<T, E>>
{
    let mut errs = Vec::new();
    loop {
        match iter.next() {
            Some(Ok(t)) => return Ok(t),
            Some(Err(e)) => errs.push(e),
            None => return Err(errs),
        }
    }
}
