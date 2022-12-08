Synopsis:
	The mod_ssi_func module hooks into apache's mod_include and provides
	the "func" directive which sets an variable with the output of the
	specified function. This module is a parent module, and as such has 		no user fuctionality on its own without further modules, see below.

Paramters:
	The func directive takes two parameters which must be in the
	following order:
	 var  -- specifies the variable the result of the function
	         is beeing stored in
	 func -- specifies the function to be used.
	All additional parameters are passed to the function.

Results:
	The result of the function is stored in the variable.

Examples:
	The following is assuming that a "add" function exists:
	  <!--#func var="sum" func="add" value="1" value="2" -->
	  <!--#echo var="sum" -->
	This example stores the sum of the addition (1+2=3) into the
	variable "sum" which then get outputed via the echo directive

See:
	mod_ssi_func_rnd
	mod_ssi_func_math
	mod_ssi_func_flastmod
