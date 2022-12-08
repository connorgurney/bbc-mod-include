Synopsis:
	This module hooks into the extension for setting a variable provided by
	the mod_ssi_func module for apache and provides a set of math functions
	working on numbers. These functions are:
	  cmp  - compare two values
	  neg  - negative of the value
	  mult - multiply multiple values
	  div  - interger division of multiple values
	  mod  - modulo division of multiple values
	  add  - addition of multiple values

parameters:
	for all operations except "cmp" the following parameters are expected:
	value	-- value(s) to be used for the computing

	the following parameters are used by "cmp":
	a	-- value a
	b	-- value b
	op	-- comparison operator
		     eq - true if "a" equals "b"
		     ne - true if "a" not equals "b"
		     lt - true if "a" is less than "b"
		     gt - true if "a" is greater than "b"
		     le - true if "a" is less or equal to "b"
		     ge - true if "a" is greater or equal to "b"

result:
	The result of the mathematical operation will be returned for all
	operations except "cmp".
	The result of "cmp" is 0 if the condition evaluates to false and
	1 if true.

examples:
	The following would set "sum" to the result of the addition of 
	2 and 4:
	  <!--#func var="sum" func="add" value="2" value="4" -->

	The following would set "cond" to 1 because "sum" of the
	previous example would be 4 which is equal to 4:
	  <!--#func var="cond" func="cmp" a="${sum}" op="eq" b="4" -->

See:
	mod_ssi_func
	mod_ssi_func_rnd
	mod_ssi_func_flastmod
