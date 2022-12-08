# BBC mod_include functionality

## mod_ssi_func

The `mod_ssi_func` module hooks into Apache's mod_include and provides the
`func` directive which sets an variable with the output of the specified
function. This module is a parent module, and as such has no user fuctionality
on its own without further modules, see below.

## mod_ssi_func_flastmod

The `mod_ssi_func_flastmod` hooks into the extension for setting a variable
provided by the `mod_ssi_func` module for Apache and provides the last file
modification time via the function `flastmod`.

## mod_ssi_func_math

This module hooks into the extension for setting a variable provided by the
`mod_ssi_func` module for Apache and provides a set of math functions working
on numbers.

## mod_ssi_func_rnd

This module hooks into the extension for setting a variable provided by the
`mod_ssi_func` module for apache and provides a random function via that way.
It runs to two modes, a "min-max" mode with number ranges, and an item mode,
where variable is set from a list of items.

## mod_ssi_setsplitvars

The mod_ssi_setsplitvars module hooks into `mod_include` and provides a
"setsplitvars" directive to split a string into parts of variables and values.
