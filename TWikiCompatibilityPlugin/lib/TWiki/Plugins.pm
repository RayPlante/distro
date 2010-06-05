package TWiki::Plugins;

use strict;
use warnings;

use Foswiki::Plugins;

# Compatible version of TWiki::Plugins. Note that this has to be versioned
# separately from $Foswiki::Plugins::VERSION.
our $VERSION = 1.2;

*TWiki::Plugins::SESSION = \*Foswiki::Plugins::SESSION;

1;
