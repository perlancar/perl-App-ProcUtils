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

    my @res;
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
        ],
    };

    for my $p (@{ $t->table }) {
        push @res, {%$p};
    }

    [200, "OK", \@res, $resmeta];
}

$SPEC{grep_parents} = {
    v => 1.1,
    summary => 'Look up parents\' processes based on name and other attributes',
    description => <<'_',

This utility is similar to <prog:pgrep> except that we only look at our
descendants (parent, parent's parent, and so on up to PID 1).

_
    args => {
        pattern => {
            summary => 'Only match processes whose name/cmdline match the pattern',
            schema => 'str*',
            pos => 0,
            tags => ['category:filtering'],
        },
        count => {
            summary => 'Suppress normal output; instead print a count of matching processes',
            schema => 'true*',
            cmdline_aliases => {c=>{}},
            tags => ['category:display'],
        },
        full => {
            summary => 'The pattern is normally only matched against the process name. When -f is set, the full command line is used.',
            schema => 'true*',
            cmdline_aliases => {f=>{}},
            tags => ['category:filtering'],
        },
        pgroup => {
            summary => 'Only match processes in the process group IDs listed',
            schema => ['array*', of=>'uint*', 'x.perl.coerce_rules' => ['str_comma_sep']],
            cmdline_aliases => {g=>{}},
            tags => ['category:filtering'],
        },
        group => {
            summary => 'Only match processes whose real group ID is listed. Either the numerical or symbolical value may be used.',
            schema => ['array*', of=>'str*', 'x.perl.coerce_rules' => ['str_comma_sep']],
            cmdline_aliases => {G=>{}},
            tags => ['category:filtering'],
        },
        list_name => {
            summary => 'List the process name as well as the process ID',
            schema => ['true*'],
            cmdline_aliases => {l=>{}},
            tags => ['category:display'],
        },
        list_full => {
            summary => 'List the full command line as well as the process ID',
            schema => ['true*'],
            cmdline_aliases => {a=>{}},
            tags => ['category:display'],
        },
        session => {
            summary => 'Only match processes whose process session ID is listed',
            schema => ['array*', of=>'uint*', 'x.perl.coerce_rules' => ['str_comma_sep']],
            cmdline_aliases => {s=>{}},
            tags => ['category:filtering'],
        },
        terminal => {
            summary => 'Only match processes whose controlling terminal is listed. The terminal name should be specified without the "/dev/" prefix.',
            schema => ['array*', of=>'str*', 'x.perl.coerce_rules' => ['str_comma_sep']],
            cmdline_aliases => {t=>{}},
            tags => ['category:filtering'],
        },
        euid => {
            summary => 'Only match processes whose effective user ID is listed. Either the numerical or symbolical value may be used.',
            schema => ['array*', of=>'str*', 'x.perl.coerce_rules' => ['str_comma_sep']],
            cmdline_aliases => {u=>{}},
            tags => ['category:filtering'],
        },
        uid => {
            summary => 'Only match processes whose user ID is listed. Either the numerical or symbolical value may be used.',
            schema => ['array*', of=>'str*', 'x.perl.coerce_rules' => ['str_comma_sep']],
            cmdline_aliases => {U=>{}},
            tags => ['category:filtering'],
        },
        inverse => {
            summary => 'Negates the matching',
            schema => ['true*'],
            cmdline_aliases => {v=>{}},
            tags => ['category:filtering'],
        },
        exact => {
            summary => 'Only match processes whose names (or command line if -f is specified) exactly match the pattern',
            schema => ['true*'],
            cmdline_aliases => {x=>{}},
            tags => ['category:filtering'],
        },
        # XXX --ns (root only, currently Proc::ProcessTable doesn't output this)
        # XXX --nslist (root only, currently Proc::ProcessTable doesn't output this)
    },
    links => [
        'prog:pgrep',
    ],
};
sub grep_parents {
    require Proc::Find::Parents;

    my %args = @_;

    my $ppids = Proc::Find::Parents::get_parent_processes(
        $$, {method=>'proctable'});

    # convert to numerical
    if ($args{group} && @{$args{group}}) {
        for (@{ $args{group} }) {
            if (/\D/) {
                my @ent = getgrnam($_);
                $_ = @ent ? $ent[2] : -1;
            }
        }
    }
    if ($args{uid} && @{$args{uid}}) {
        for (@{ $args{uid} }) {
            if (/\D/) {
                my @ent = getpwnam($_);
                $_ = @ent ? $ent[2] : -1;
            }
        }
    }
    if ($args{euid} && @{$args{euid}}) {
        for (@{ $args{euid} }) {
            if (/\D/) {
                my @ent = getpwnam($_);
                $_ = @ent ? $ent[2] : -1;
            }
        }
    }

    my @res;
    for my $p (@$ppids) {
        my $match = 1;
      MATCHING: {

            if (defined $args{pattern}) {
                if ($args{exact}) {
                    if ($args{full}) {
                        do { $match = 0; last MATCHING } unless $p->{cmdline} eq $args{pattern};
                    } else {
                        do { $match = 0; last MATCHING } unless $p->{name}    eq $args{pattern};
                    }
                } else {
                    if ($args{full}) {
                        do { $match = 0; last MATCHING } unless $p->{cmdline} =~ /$args{pattern}/;
                    } else {
                        do { $match = 0; last MATCHING } unless $p->{name}    =~ /$args{pattern}/;
                    }
                }
            }

            if ($args{pgroup} && @{$args{pgroup}}) {
                my $found = 0;
                for (@{ $args{pgroup} }) {
                    if ($_ == $p->{pgrp}) {
                        $found++; last;
                    }
                }
                do { $match = 0; last MATCHING } unless $found;
            }

            if ($args{group} && @{$args{group}}) {
                my $found = 0;
                for (@{ $args{group} }) {
                    if ($_ == $p->{gid}) {
                        $found++; last;
                    }
                }
                do { $match = 0; last MATCHING } unless $found;
            }

            if ($args{uid} && @{$args{uid}}) {
                my $found = 0;
                for (@{ $args{uid} }) {
                    if ($_ == $p->{uid}) {
                        $found++; last;
                    }
                }
                do { $match = 0; last MATCHING } unless $found;
            }

            if ($args{euid} && @{$args{euid}}) {
                my $found = 0;
                for (@{ $args{euid} }) {
                    if ($_ == $p->{euid}) {
                        $found++; last;
                    }
                }
                do { $match = 0; last MATCHING } unless $found;
            }

            if ($args{session} && @{$args{session}}) {
                my $found = 0;
                for (@{ $args{session} }) {
                    if ($_ == $p->{sess}) {
                        $found++; last;
                    }
                }
                do { $match = 0; last MATCHING } unless $found;
            }

            if ($args{terminal} && @{$args{terminal}}) {
                my $found = 0;
                $p->{ttydev} =~ s!^/dev/!!;
                for (@{ $args{terminal} }) {
                    if ($_ eq $p->{ttydev}) {
                        $found++; last;
                    }
                }
                do { $match = 0; last MATCHING } unless $found;
            }

        } # MATCHING

        if ($args{inverse}) {
            push @res, $p unless $match;
        } else {
            push @res, $p if $match;
        }
    }

    my $res = "";
    if ($args{count}) {
        $res .= scalar(@res) . "\n";
    } elsif ($args{list_full}) {
        for (@res) {
            $res .= "$_->{pid} $_->{cmdline}\n";
        }
    } elsif ($args{list_name}) {
        for (@res) {
            $res .= "$_->{pid} $_->{name}\n";
        }
    } else {
        for (@res) {
            $res .= "$_->{pid}\n";
        }
    }

    [200, "OK", $res, {
        'cmdline.skip_format'=>1,
        'cmdline.exit_code' => @res ? 0:1,
    }];
}

1;
# ABSTRACT: Command line utilities related to processes

=head1 SYNOPSIS

This distribution provides the following command-line utilities:

# INSERT_EXECS_LIST
