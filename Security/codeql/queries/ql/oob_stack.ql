/**
 * @name Stack out-of-bounds write (teaching)
 * @description Flags array writes guarded by an insufficient upper bound compared to the stack array size.
 * @kind problem
 * @problem.severity warning
 * @id lab/stack-oob
 */

import cpp

/** Finds a check of the form `idx < literal` in the same function. */
predicate hasUpperBoundCheck(Function f, Variable idx, Literal lim) {
	exists(BinaryOperation cond, VariableAccess va |
		cond.getEnclosingFunction() = f and
		cond.getOperator() = "<" and
		lim = cond.getAnOperand() and lim.getValue().regexpMatch("(?s)\\s*[0-9]+\\s*") and
		va = cond.getAnOperand() and va.getTarget() = idx
	)
}

from ArrayExpr access, VariableAccess arrUse, LocalVariable arr, ArrayType arrType,
		 VariableAccess idxUse, Variable idx, Literal lim, int size
where
	arrUse = access.getArrayBase().(VariableAccess) and
	arr = arrUse.getTarget() and
	arr.getType() = arrType and
	size = arrType.getArraySize() and
	idxUse = access.getArrayOffset().(VariableAccess) and
	idx = idxUse.getTarget() and
	hasUpperBoundCheck(access.getEnclosingFunction(), idx, lim)
select access, "Array of size " + size.toString() + " may be indexed up to literal " + lim.getValue() + "."
