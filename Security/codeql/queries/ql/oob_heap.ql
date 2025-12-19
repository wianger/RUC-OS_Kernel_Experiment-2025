/**
 * @name Heap out-of-bounds write after kmalloc (teaching)
 * @description Flags writes that index a kmalloc'ed buffer using the same variable that was used as the element count.
 * @kind problem
 * @problem.severity warning
 * @id lab/heap-oob
 */

import cpp

/**
 * Holds when `arr` is initialized or assigned from a call to `kmalloc`, and the allocation size expression
 * includes the variable `idx` (typically `idx * sizeof(T)` or `sizeof(T) * idx`).
 */
predicate kmallocWithIndex(LocalVariable arr, Variable idx, FunctionCall alloc) {
	exists(BinaryOperation mul, VariableAccess idxUse |
		alloc.getTarget().hasName("kmalloc") and
		mul = alloc.getArgument(0).(BinaryOperation) and
		mul.getOperator() = "*" and
		idxUse = mul.getAnOperand().(VariableAccess) and idxUse.getTarget() = idx and
		(
			arr.getInitializer().getExpr() = alloc or
			exists(AssignExpr asgn, VariableAccess lhs |
				asgn.getRValue() = alloc and
				lhs = asgn.getLValue().(VariableAccess) and
				lhs.getTarget() = arr
			)
		)
	)
}

from ArrayExpr access, VariableAccess baseUse, LocalVariable arr,
	 VariableAccess idxUse, Variable idx,
	 FunctionCall alloc
where
	baseUse = access.getArrayBase().(VariableAccess) and
	arr = baseUse.getTarget() and
	idxUse = access.getArrayOffset().(VariableAccess) and
	idx = idxUse.getTarget() and
	kmallocWithIndex(arr, idx, alloc)
select access,
	"Index variable is used both as allocation element-count and as an index; this can be one-past-the-end (heap OOB)."

