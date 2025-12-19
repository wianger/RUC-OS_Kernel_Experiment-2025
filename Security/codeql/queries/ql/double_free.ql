/**
 * @name Double free via kfree (teaching)
 * @description Flags two calls to kfree on the same pointer variable in the same function (by source order).
 * @kind problem
 * @problem.severity warning
 * @id lab/double-free
 */

import cpp

predicate occursAfter(Stmt later, Stmt earlier) {
	later.getLocation().getStartLine() > earlier.getLocation().getStartLine() and
	later.getFile() = earlier.getFile()
}

from FunctionCall free1, FunctionCall free2,
	 VariableAccess arg1, VariableAccess arg2,
	 Variable p
where
	free1.getTarget().hasName("kfree") and
	free2.getTarget().hasName("kfree") and
	free1 != free2 and
	arg1 = free1.getArgument(0).(VariableAccess) and
	arg2 = free2.getArgument(0).(VariableAccess) and
	p = arg1.getTarget() and
	arg2.getTarget() = p and
	free1.getEnclosingFunction() = free2.getEnclosingFunction() and
	occursAfter(free2.getEnclosingStmt(), free1.getEnclosingStmt())
select free2,
	"Pointer '" + p.getName() + "' is freed more than once with kfree (possible double free)."

