package IpBan::Config;
use strict;
use warnings;
use File::Basename qw(dirname);
use IpBan::SSH;
use IpBan::RSYNC;
use Data::Dumper;

my %DEFAULT = (
    debug => 0,
    conf => '/etc/banit/banit.conf',
    log => '/var/log/banit.log',
);

sub new {
    my ($class, $configfile, $logfile, $debug) = @_;
    $configfile ||= $DEFAULT{conf};
    $logfile ||= $DEFAULT{log};
    $debug ||= $DEFAULT{debug};

    die "Cannot find config file '$configfile'"
        unless -f $configfile;

    __validate_logfile($logfile);

    open CONF, '<', $configfile or die $!;
    my @conf = <CONF>;
    chomp @conf;
    close CONF;

    return bless {
        configfile => $configfile,
        config => \@conf,
        logfile => $logfile,
        debug => $debug,
    }, $class;
}


##
## Methods

sub configfile  { return $_[0]->{configfile}; }

sub logfile {
    my ($self, $value) = @_;

    $self->{logfile} = $value
        if defined $value;

    return $self->{logfile};
}

sub debug {
    my ($self, $value) = @_;

    $self->{debug} = $value
        if defined $value;

    return $self->{debug};
}

sub parse {
    my $self = shift;

    my $service;
    my %service;
    my @services;

    my $global = my $services = 0;
    for my $line (@{$self->{config}}) {
        next if $line =~ /^\s*#/;
        next if $line =~ /^\s*$/;

        # config section header

        if (my ($header) = $line =~ /^\[([A-Za-z]+)\]/) {
            if ($header =~ /^global$/i) {
                $global = 1;
                $services = 0;
            }
            elsif ($header =~ /^services$/i) {
                $services = 1;
                $global = 0;
            }
            else {
                die "Unknown config section: $header";
            }

            next;
        }

        # config sections

        if ($global) {
            $line =~ s/\s//g;
            my ($k, $v) = split /=/, $line;

            if ($k eq 'logfile') {
                __validate_logfile($v);
                $self->logfile($v);
                next;
            }

            if ($k eq 'debug') {
                $self->debug($v);
                next;
            }

            warn "Unknown config option $k";
            next;
        }

        if ($services) {
            $line =~ s/\s//g;

            # service header
            my $previousS = $service;
            if ($line =~ /^\s*\:[A-Za-z]+\:\s*$/) {
                ($service) = $line =~ /\:([A-Za-z]+)\:/;
                $service = uc $service;

                if ($previousS and $previousS ne $service) {
                    # service definition end
                    push @services, __service($previousS, %service);
                }

                %service = ();
                next;
            }

            # service definition
            my ($k, $v) = split /=/, $line;
            $service{$k} = lc $v;
        }
    }

    # last service
    push @services, __service($service, %service);

    return @services;
}


##
## Private :)

sub __validate_logfile {
    my $logfile = shift;

    my $logdir = dirname($logfile);
    die "Cannot find log dir '$logdir'"
        unless -d $logdir;

    die "Logfile must be a regular file"
        if -e $logfile and ! -f $logfile;

    1;
}

sub __service {
    my ($service, %service) = @_;

    # require service name
    die "No service name given"
        unless $service and length $service;

    # require 'some' service details
    die "No service definition given"
        unless keys %service;

    return "IpBan::$service"->new(%service);
}


1;
