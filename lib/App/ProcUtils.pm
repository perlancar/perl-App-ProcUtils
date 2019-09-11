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
    [200, "OK", Proc::Find::Parents::get_parent_processes(
        $$, {method=>'proctable'})];
}

$SPEC{table} = {
    v => 1.1,
    summary => 'Run Proc::ProcessTable and display the result',
};
sub table {
    require Proc::ProcessTable;

    my $t = Proc::ProcessTable->new;

    my $resmeta = {
        'table.fields' => [
            # follows the order of 'ps aux'
            "uid",
            "pid",
            "pctcpu",
            "pctmem",
            "size",
            "rss",
            "ttydev",
            "ttynum",
            "state",
            "start",
            "time",
            "cmndline",

            "cmajflt",
            "cminflt",
            "cstime",
            "ctime",
            "cutime",
            "cwd",
            "egid",
            "euid",
            "exec",
            "fgid",
            "flags",
            "fname",
            "fuid",
            "gid",
            "majflt",
            "minflt",
            "pgrp",
            "ppid",
            "priority",
            "sess",
            "sgid",
            "stime",
            "suid",
            "utime",
            "wchan",

            # not included
            # environ
        ],
    };

    my @rows;
    for my $p (@{ $t->table }) {
        my $row = {%$p};
        $row->{cmdline} = join(" ", grep {$_ ne ''} @{ $row->{cmdline} });
        push @rows, $row;
    }

    [200, "OK", \@rows, $resmeta];
}

1;
# ABSTRACT: Command line utilities related to processes

=head1 SYNOPSIS

This distribution provides the following command-line utilities:

# INSERT_EXECS_LIST
