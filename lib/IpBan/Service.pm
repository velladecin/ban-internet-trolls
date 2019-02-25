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
    bantime => 300,         # seconds
    'bantime-grace' => 60,  # seconds
    banfilter => '5/60',    # 5 connection attempts withing 60 seconds
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
    __die_ifnotint($bantime, "Bantime must be a number");
    $self->{bantime} = $bantime;

    # bantime-grace
    my $bantimegrace = $args{'bantime-grace'} || $DEFAULT{'bantime-grace'};
    __die_ifnotint($bantimegrace, "Bantime-grace must be a number");
    $self->{'bantime-grace'} = $bantimegrace;

    # banfilter
    my $banfilter = $args{banfilter} || $DEFAULT{banfilter};
    die "Banfilter must be in format 'int/int' (connection attempts/time period [seconds])" unless $banfilter =~ m|^\d+/\d+$|;
    $self->{banfilter} = $banfilter;

    # black/white listing
    for my $type (qw(whitelist4 whitelist6 blacklist4 blacklist6)) {
        my @list = ();

        if ($args{$type} and length $args{$type}) {
            # IPs
            $args{$type} =~ s/\s//g;
            @list = split /,/, $args{$type};
        }

        $self->{$type} = \@list;
    }

=head
    if ($args{whitelist4} and length $args{whitelist4}) {
        # IPs
        $args{whitelist4} =~ s/\s//g;
        @whitelist = split /,/, $args{whitelist4};
    }

    my @whitelist = ();
    if ($args{whitelist} and length $args{whitelist}) {
        # IPs
        $args{whitelist} =~ s/\s//g;
        @whitelist = split /,/, $args{whitelist};
    }
    $self->{whitelist} = \@whitelist;

    # blacklisting
    my @blacklist = ();
    if ($args{blacklist} and length $args{blacklist}) {
        # IPs
        $args{blacklist} =~ s/\s//g;
        @blacklist = split /,/, $args{blacklist};
    }
    $self->{blacklist} = \@blacklist;
=cut

    1;
}

sub getid           { return $_[0]->{proto}. ":" .$_[0]->{port} } # proto+port is unique
sub getname         { return $_[0]->{name}      }
sub getport         { return $_[0]->{port}      }
sub getproto        { return $_[0]->{proto}     }
sub getipver        { return wantarray ? split(',', $_[0]->{ipver}) : $_[0]->{ipver} }
sub getbantime      { return $_[0]->{bantime}   }
sub getbantimegrace { return $_[0]->{'bantime-grace'} }
sub getbanfilter    { return $_[0]->{banfilter} }
sub getauthlog      { return $_[0]->{authlog}   }
sub getauthlogsearch { return $_[0]->{authlogsearch} }
sub getwhitelist4   { return wantarray ? @{$_[0]->{whitelist4}} : $_[0]->{whitelist4} }
sub getwhitelist6   { return wantarray ? @{$_[0]->{whitelist6}} : $_[0]->{whitelist6} }
sub getblacklist4   { return wantarray ? @{$_[0]->{blacklist4}} : $_[0]->{blacklist4} }
sub getblacklist6   { return wantarray ? @{$_[0]->{blacklist6}} : $_[0]->{blacklist6} }


#
# Private

sub __die_ifnotint {
    my ($val, $msg) = shift;
    die $msg unless $val =~ /^\d+$/;
}


1;
