/**
 * @name Use-after-free after kfree (teaching)
 * @description Flags dereferences (including array/field access) of a pointer variable after it is freed with kfree.
 * @kind problem
 * @problem.severity warning
 * @id lab/uaf
 */

import cpp

/** True if `e` is a dereference-like use of variable `p` (e.g., `*p`, `p->f`, `p[i]`). */
predicate isDerefUseOf(Expr e, Variable p) {
	exists(PointerDereferenceExpr pde, VariableAccess va |
		e = pde and
		va = pde.getOperand().(VariableAccess) and
		va.getTarget() = p
	)
	or
	exists(PointerFieldAccess pfa, VariableAccess va |
		e = pfa and
		va = pfa.getQualifier().(VariableAccess) and
		va.getTarget() = p
	)
	or
	exists(ArrayExpr ae, VariableAccess va |
		e = ae and
		va = ae.getArrayBase().(VariableAccess) and
		va.getTarget() = p
	)
}

/**
 * A lightweight ordering predicate: `later` starts after `earlier` (same file).
 * This is a teaching simplification; it does not prove reachability.
 */
predicate occursAfter(Stmt later, Stmt earlier) {
	later.getLocation().getStartLine() > earlier.getLocation().getStartLine() and
	later.getFile() = earlier.getFile()
}

from FunctionCall freeCall, VariableAccess freedArg, Variable p,
	 Stmt useStmt, Expr useExpr
where
	freeCall.getTarget().hasName("kfree") and
	freedArg = freeCall.getArgument(0).(VariableAccess) and
	p = freedArg.getTarget() and
	useStmt.getEnclosingFunction() = freeCall.getEnclosingFunction() and
	occursAfter(useStmt, freeCall.getEnclosingStmt()) and
	useExpr.getEnclosingStmt() = useStmt and
	isDerefUseOf(useExpr, p)
select useExpr, "Pointer '" + p.getName() + "' is freed by kfree and later dereferenced (possible UAF)."

