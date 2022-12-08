Synopsis:
	This module hooks into the extension for setting a variable provided by
	the mod_ssi_func module for apache and provides a random function
	via that way. It runs to two modes, a 'min-max' mode with number ranges,
	and an item mode, where variable is set from a list of items. 

parameters:
	min	-- lower end of range
	max	-- upper end of range 
	item	-- list of items to randomly use the value 

result:
	A random number or an item value is returned.

examples:
	The following would set the variable "0", "1" or "2" :
	  <!--#func var="rnd" func="random" min="0" max="2" -->
	  
 	The following would set the variable "rnd" to "red" or "green" or
 	"blue" :
	  <!--#func var="rnd" func="random" item="red" item="green" item="blue" -->

	The following ranges can be used :
	  <!--#func var="rnd" func="random" min="-10" max="10" -->
	  <!--#func var="rnd" func="random" min="0" max="10"  -->
	  <!--#func var="rnd" func="random" min="-50" max="-40" -->

See:
	mod_ssi_func
	mod_ssi_func_math
	mod_ssi_func_flastmod
