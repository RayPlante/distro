package EmptyPluginSuite;

use strict;
use warnings;

use Unit::TestSuite;
our @ISA = 'Unit::TestSuite';

sub name { 'EmptyPluginSuite' }

sub include_tests { qw(EmptyPluginTests) }

1;
