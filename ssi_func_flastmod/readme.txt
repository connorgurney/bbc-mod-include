Synopsis:
	This module hooks into the extension for setting a variable provided by
	the mod_ssi_func module for apache and provides the last file
	modification time via the function "flastmod".

parameters:
	The same as the flastmod directive of the mod_include module.
	http://httpd.apache.org/docs-2.0/mod/mod_include.html#element.flastmod
	The file path is available as in file includes, i.e. "includes/file.ssi", but 
	not "/site/includes/file.ssi".  As with includes it also allows for a 
	virtual call rather than file which supports full paths.

result:
	The text flastmod of mod_include would output is stored in the variable
	specified to the mod_ssi_func func directive.

examples:
	Emulating the flastmod directive of the mod_include module:
 	  <!--#func var="indexlastmod" func="flastmod" file="index.html" -->
	  <!--#echo var="indexlastmod" -->
	  or
	  <!--#func var="indexlastmod" func="flastmod" virtual="/site/index.html" -->
 	  <!--#echo var="indexlastmod" -->
See:
	mod_ssi_func
	mod_ssi_func_rnd
	mod_ssi_func_math
