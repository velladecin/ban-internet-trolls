package IpBan::Service;
use strict;
use warnings;
use Net::Patricia;
use Data::Dumper;

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

my %RGX = (
    ip4addr => qr|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$|,
    ip6addr => qr|^[a-fA-F0-9:]+(?:/\d{1,3})?$|, # TODO improve this
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
        my %iplist = ();

        # TODO XXX Separating white/black lists due to range introduction.
        # Eventually they both will be done the same way.

        # blacklist
        if ($type =~ /^black/) {
            if ($args{$type} and length $args{$type}) {
                # IPs
                $args{$type} =~ s/\s//g;
                # make sure IPs are unique - defend against user error
                $iplist{$_} = 1 for split /,/, $args{$type};
            }

            $self->{$type} = [keys %iplist];
            next;
        }

        # whitelist
        my ($rgx, $afinet) = $type =~ /4/
            ? ($RGX{ip4addr}, AF_INET) : ($RGX{ip6addr}, AF_INET6);

        my $patty = Net::Patricia->new($afinet);

        if ($args{$type} and length $args{$type}) {
            $args{$type} =~ s/\s//g;

            for my $ip (split /,/, $args{$type}) {
                unless ($ip =~ $rgx) {
                    # TODO fix this to logfile
                    print ">>> WARNING: invalid ip4 addr: $ip, skipping..\n";
                    next;
                }

                # make IPs unique / defend against user error
                $iplist{$ip} = 1
            }
        }

        $patty->add_string($_, 1)
            for keys %iplist;

        $self->{$type}{raw} = [keys %iplist];
        $self->{$type}{patricia} = $patty;
    }

    1;
}

sub in_whitelist4 {
    my ($self, $ip) = @_;
    return $self->{whitelist4}{patricia}->match_string($ip);
}

sub in_whitelist6 {
    my ($self, $ip) = @_;
    return $self->{whitelist6}{patricia}->match_string($ip);
}


#
# Getters

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
sub getwhitelist4   { return wantarray ? @{$_[0]->{whitelist4}{raw}} : $_[0]->{whitelist4}{raw} }
sub getwhitelist6   { return wantarray ? @{$_[0]->{whitelist6}{raw}} : $_[0]->{whitelist6}{raw} }
sub getblacklist4   { return wantarray ? @{$_[0]->{blacklist4}} : $_[0]->{blacklist4} }
sub getblacklist6   { return wantarray ? @{$_[0]->{blacklist6}} : $_[0]->{blacklist6} }


#
# Private

sub __die_ifnotint {
    my ($val, $msg) = shift;
    die $msg unless $val =~ /^\d+$/;
}


1;
