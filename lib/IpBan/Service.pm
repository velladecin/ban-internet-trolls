package IpBan::Service;
use strict;
use warnings;

=head1 NAME

IpBan::Service - abstract class for a 'service'

=head1 SYNOPSIS

    Child class:

    use parent 'IpBan::Service';
    sub new {
        $self->SUPER::__init(%args); 
    }

=cut

# Defaults unless user specified
my %DEFAULT = (
    proto   => 'tcp',
    ipver   => 'ip4',
    bantime => 300,      # seconds
    banfilter => '5/60', # 5 connection attempts withing 60 seconds
);

sub __init {
    my ($self, %args) = @_;

    ##
    ## The below must/should already exist (defined in child packages)

    # name
    $self->{name} = $args{name};

    # port
    die "Port must be a number" unless $args{port} =~ /^\d+$/;
    $self->{port} = $args{port};

    # authlog
    die "No such file '$args{authlog}'" unless -f $args{authlog};
    $self->{authlog} = $args{authlog};

    # authlog search
    $self->{authlogsearch} = $args{authlogsearch};

    ##
    ## The below may or may not exist, give defaults if missing

    # proto
    my $proto = $args{proto} || $DEFAULT{proto};
    die "Protocol must be one of TCP, UDP" unless $proto =~ /^(tcp|udp)$/;
    $self->{proto} = $proto;

    # ipver
    my $ipver = $args{ipver} || $DEFAULT{ipver};
    my @ipvers = $ipver =~ /,/ ? split(/,/, $ipver) : $ipver;
    for (@ipvers) {
        die "Ipver must be in IP4[,IP6] format"
            unless /^(ip4|ip6)$/;
    }
    $self->{ipver} = $ipver;

    # bantime
    my $bantime = $args{bantime} || $DEFAULT{bantime};
    die "Bantime must be number (of seconds)" unless $bantime =~ /^\d+$/;
    $self->{bantime} = $bantime;

    # banfilter
    my $banfilter = $args{banfilter} || $DEFAULT{banfilter};
    die "Banfilter must be in format 'int/int' (connection attempts/time period [seconds])" unless $banfilter =~ m|^\d+/\d+$|;
    $self->{banfilter} = $banfilter;

    # whitelisting
    my @whitelist = ();
    if ($args{whitelist} and length $args{whitelist}) {
        # IPs
        $args{whitelist} =~ s/\s//g;
        @whitelist = split /,/, $args{whitelist};
    }
    $self->{whitelist} = \@whitelist;

    1;
}

sub getid        { return $_[0]->{proto}. ":" .$_[0]->{port} } # proto+port is unique
sub getname      { return $_[0]->{name}      }
sub getport      { return $_[0]->{port}      }
sub getproto     { return $_[0]->{proto}     }
sub getipver     { return wantarray ? split(',', $_[0]->{ipver}) : $_[0]->{ipver} }
sub getbantime   { return $_[0]->{bantime}   }
sub getbanfilter { return $_[0]->{banfilter} }
sub getauthlog   { return $_[0]->{authlog}   }
sub getauthlogsearch { return $_[0]->{authlogsearch} }
sub getwhitelist { return wantarray ? @{$_[0]->{whitelist}} : $_[0]->{whitelist} }


1;
