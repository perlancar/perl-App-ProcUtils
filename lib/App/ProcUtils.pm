package App::ProcUtils;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

our %SPEC;

$SPEC{list_parents} = {
    v => 1.1,
    summary => 'List all the parents of the current process',
};
sub list_parents {
    require Proc::Find::Parents;
    [200, "OK", Proc::Find::Parents::get_parent_processes()];
}

1;
# ABSTRACT: Command line utilities related to processes

=head1 SYNOPSIS

This distribution provides the following command-line utilities:

# INSERT_EXECS_LIST
