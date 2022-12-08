Synopsis:
	The mod_ssi_setsplitvars module hooks into apache mod_include and
	provides a "setsplitvars" directive to split a string into parts of
	variables and values.

Paramters (must be used in the statement in the following order):
	delimeter  -- the character (or characters) which delimits the var=val
		      value pairs, default is '&'
	separator  -- the character (or separators) which seperates the var=val
		      value pairs, default is '='
	allow      -- allow this variable to be set even if it is already set
		      or the name does not contain [a-z]
	decoding   -- takes the values, url, entity, url_entity (ie both),
		      none, default is none
		      see echo encoding http://httpd.apache.org/docs-2.0/mod/mod_include.html#element.echo
	value	   -- the string to split

Results:
	All the variables are set with their corresponding values if the
	following restrictions are met:
	- variable is not allready set*
	- variable name contains at least one char wich is not [A-Z_]
	( * these can be set using allow as above)

Examples:
	The following sets the variable "hello" to "world" and "foo" to "bar":
	<!--#setsplitvars value="hello=world&foo=bar" -->
	
	It can be used to separate the Query String
	<!--#setsplitvars value="$QUERY_STRING" -->
	
	or the user cookie string for postcoder information
	<!--#setsplitvars delimeter="; " value="$HTTP_COOKIE" -->

