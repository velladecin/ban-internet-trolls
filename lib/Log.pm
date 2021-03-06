package Log;
use strict;
use warnings;
use POSIX qw(strftime);

=head1 NAME

Log - global logging for this project

=head1 SYNOPSIS

    use Log;
    my $l = Log->open(logfile=>'/path/to/file', debug=>0|1, flushlog=>0|1);

=over 8

logfile must be given

flushlog defaults to B<0> (don't flush)

=back

    $l->info("info msg");
    $l->warn("warning msg");
    $l->crit("critical msg");
    $l->debug("debug msg");

=head2 Methods

=over 8

=item C<open>

See SYNOPSIS

=item C<close>

Close log file handle

=back

=cut

sub open {
    my $class = shift;
    my %self = @_;

    die "Must give 'logfile' argument to ". __PACKAGE__
        unless $self{logfile};

    $self{flushlog} ||= 0;
    $self{debug} ||= 0;

    open $self{_logfh}, '>>', $self{logfile}
        or die "Cannot open file '$self{logfile}', $!";

    return bless \%self, $class;
}

sub close {
    my $self = shift;
    close $self->{_logfh}
        if fileno $self->{_logfh};
}

=over 8

=item C<info>

Inputs INFO level message together with date+time in designated log file

Also see B<flushlog> in SYNOPSIS

=item C<warn>

Inputs WARNING level together with date+time message in designated log file

Also see B<flushlog> in SYNOPSIS

=item C<crit>

Inputs CRITICAL level together with date+time message in designated log file

=item C<debug>

Input DEBUG level together with date+time message in designated log file

Also see B<flushlog> in SYNOPSIS

=back

=cut

sub info { _log(shift, 'INFO',      @_) }
sub warn { _log(shift, 'WARNING',   @_) }
sub crit { _log(shift, 'CRITICAL',  @_) }
sub debug {
    my ($self, @msg) = @_;

    _log($self, 'DEBUG', @msg)
        if $self->{debug};
}

sub _log {
    my ($self, $level, @msg) = @_;
    chomp @msg;

    my $now = strftime '%Y-%m-%d %H:%M:%S', localtime();

    my $oldfh;
    if ($self->{flushlog}) {
        $oldfh = select($self->{_logfh});
        $|++;
    }

    my $log = $self->{_logfh};
    print $log "$now [$level]  @msg\n";

    if ($oldfh and fileno $oldfh) {
        select($oldfh);
    }
}

sub is_debug { return $_[0]->{debug}; }

sub setdebug {
    my ($self, $value) = @_;

    # accept 1/0
    unless (defined $value) {
        $self->warn("Undefined value for setdebug(), ignoring..");
        return 0;
    }

    if ($value < 0) {
        $self->warn("Negative numbers not accepted by setdebug(), ignoring..");
        return 0;
    }

    $value = 1
        if $value > 1;

    $self->{debug} = $value;

    1;
}


1;
