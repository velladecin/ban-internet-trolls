package IpBan;
use strict;
use warnings;
use Data::Dumper;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Log;

my $IPT4 = '/sbin/iptables';
my $IPT6 = '/sbin/ip6tables';
my %SERVICE = (
    ssh     => {proto=>'tcp', port=>22},
    rsync   => {proto=>'tcp', port=>873},
    # add more here
);
my $IPBANID = 'IPBANxkeivFHio5qdiIHFi3nf';

=head1 NAME

IpBan - will ban IPs, via iptables

=head1 SYNOPSIS

    my $ib = IpBan->new(logfile=>'/path/to/file', ipver=>'ip4|ip6|ip4+ip6');

=over 8

B<logfile> - if not given no logging will take place

B<ipver> - one of ip4, ip6, ip4+ip6. Defaults to ip4.

B<commentstring> - for easy filtering of iptables rules and is required. It should be reasonably descriptive and reasonably unique.

=back

    $ib->ban4('1.1.1.1');
    $ib->unban4('1.1.1.1');

=cut

=head2 Methods

=over 8

=item C<new()>

See SYNOPSIS

=back

=cut

sub new {
    my ($class, $log) = @_;

    die "Expecting Log object as parameter for IpBan"
        unless ref $log eq 'Log';

    my $self = bless {log=>$log}, $class;
    $self->__init();

    return $self;
}

sub __init {
    my $self = shift;

    $self->{log}->info("Collecting currently banned IPs from netfilter");

    # -A INPUT -s 116.31.116.49/32 -p tcp -m tcp --dport 22 -m comment --comment "<$IPBANID>" -j REJECT --reject-with icmp-port-unreachable
    my %ban4;
    my %ban6;
    my $now = time();
    for my $line (grep /$IPBANID/, qx($IPT4 -S INPUT)) {
        chomp $line;

        my ($ip, $proto, $port) = $line =~ m|-s\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/32)\s-p\s([a-z]+)\s.*--dport\s(\d+)\s|;

        unless ($ip and $proto and $port) {
            $self->{log}->warn("Could not retrieve service details from rule :: '$line' :: ip:'$ip', proto:'$proto', port:'$port'");
            next;
        }

        $self->{log}->info("Found: $ip, $proto, $port");

        # as we cannot say when this IP was banned,
        # just make it now..
        $ban4{"$proto:$port"} = {
            $ip => {
                start => $now,
                lastseen => $now,
            },
        }
    }

    $self->{log}->info("IPv4: None")
        unless keys %ban4;

    # TODO ipv6
=head
    my %ban6;
    for my $line (grep /$IPBANID/, qx($IPT6 -S INPUT)) {
        chomp $line;

        my ($ip, $proto, $port) = $line =~ m||;

        print ">>> $line\n";
    }

    $self->{log}->info("IPv6: None")
        unless keys %ban6;
=cut

    $self->{ip4}{banned} = \%ban4;
    $self->{ip6}{banned} = \%ban6;
}

=over 8

=item C<ban4(ip)>

=item C<unban4(ip)>

=item C<ban6>

=item C<unban6>

=back

=cut

sub ban4 {
    my ($self, $ip) = @_;
    return unless $ip =~ m|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/32)?$|;
}

sub unban4 {
    my ($self, $ip) = @_;
}

=over 8

=item C<get_banned4()>

returns hash with all IPv4 banned IPs and times when they were banned

=item C<get_banned6()>

returns hash with all IPv6 banned IPs and times when they were banned

=item C<get_banned()>

returns hash with all IPv4+IPv6 banned IPs and times when they were banned

=back

=cut

sub get_banned4 { __get_banned(shift, '4');  }
sub get_banned6 { __get_banned(shift, '6');  }
sub get_banned  { __get_banned(shift, '46'); }
sub __get_banned {
    my ($self, $type) = @_;

    my %return;
    @return{keys %{$self->{ip4}{banned}}} = values %{$self->{ip4}{banned}} if $type =~ /^4$/;
    @return{keys %{$self->{ip6}{banned}}} = values %{$self->{ip6}{banned}} if $type =~ /^6$/;

    return %return;
}

sub ingest4 { __ingest(shift, 'ip4', @_); }
sub ingest6 { __ingest(shift, 'ip6', @_); }
sub __ingest {
    my ($self, $ipver, $ip, $count, $sid) = @_;

    # 1. banned         - currently banned
    # 2. candidates     - fail to auth but not often enough yet to be banned

    die "Invalid ipver '$ipver'"
        unless $ipver =~ /^ip(4|6)$/;

    $ip = "$ip/32" if $ipver =~ /4/;
    
    my $now = time();
    if ($self->{$ipver}{banned}{$sid}{$ip}) {
        $self->{$ipver}{banned}{$sid}{$ip}{lastseen} = $now;
    }
    elsif ($self->{$ipver}{candidate}{$sid}{$ip}) {
        $self->{$ipver}{candidate}{$sid}{$ip}{count} += $count;
        $self->{$ipver}{candidate}{$sid}{$ip}{lastseen} = $now;
    }
    else {
        $self->{$ipver}{candidate}{$sid}{$ip} = {
            start => $now,
            count => $count,
            lastseen => $now,
        };
    }

    1;
}

sub enforce {
    my ($self, $service) = @_;
print Dumper $self;

    my $sid = $service->getid();
    my $now = time();

    for my $ipver ($service->getipver()) {
        # banned
        my $bbase = $self->{$ipver}{banned}{$sid};
        for my $ip (keys %$bbase) {
            # if currently banned and still trolls (lastseen within the designated 'bantime', see config for details)
            # then take no action (ban continues), othewise un-ban that IP
            my $tdelta = $now - $bbase->{$ip}{lastseen};

            # tdelta can be negative - daylight saving
            # in this case update lastseen to now and move on
            if ($tdelta < 0) {
                $self->{log}->warn("Negative time delta($tdelta) for banned IP($ip), re-setting lastseen to now($now) and moving on");
                $bbase->{$ip}{lastseen} = $now;
                next;
            }

            # lastseen timestamp is updated during ingest (above)
            # the only possible action here is to UN-ban
            if ($tdelta > $service->getbantime()) {
                $self->{log}->info("*** UN-banning: $ip, $sid");
#print "*** UN-banning: $ip, $sid\n";
                delete $bbase->{$ip};

                # physically un-ban
                my $unban = sprintf '%s -D INPUT %s', # full iptables rule
                    $ipver =~ /4/ ? $IPT4 : $IPT6,
                    sprintf('-p %s -s %s --dport %d -m comment --comment %s -j REJECT', $service->getproto(), $ip, $service->getport(), $IPBANID);

                qx($unban);
            }
        }

        # candidates
        my ($maxcount, $secs) = split /\//, $service->getbanfilter();

        my $cbase = $self->{$ipver}{candidate}{$sid};
        for my $ip (keys %$cbase) {
            # 1. if count satisfies banfilter (see config for details) then remove this candidate, move her/him to banned and physically ban them,
            #   check count irrespective of time, any candidate entry should never be more than banfilter time + read_authfile_frequency old
            if ($cbase->{$ip}{count} >= $maxcount) {
                $self->{log}->info("!!! Banning: $ip, $sid");
#print "!!! Banning: $ip, $sid\n";
                # add to banned
                $self->{$ipver}{banned}{$sid}{$ip} = {
                    start => $now,
                    lastseen => $cbase->{$ip}{lastseen} || $now,
                };

                # delete candidate
                delete $cbase->{$ip};

                # physically ban
                my $ban = sprintf '%s -I INPUT 1 %s', # full iptables rule
                    $ipver =~ /4/ ? $IPT4 : $IPT6,
                    sprintf('-p %s -s %s --dport %d -m comment --comment %s -j REJECT', $service->getproto(), $ip, $service->getport(), $IPBANID);

                qx($ban);
                next;
            }

            my $tdelta = $now - $cbase->{$ip}{start};

            # 2. if count does not satisfy banfilter and time is exceeded
            #   then remove from candidates (restart counts)
            if ($tdelta > $secs) {
                $self->{log}->info("Removing candidate $ip, total count: ", $cbase->{$ip}{count});
                delete $cbase->{$ip};
            }

            # 3. if count does not satisfy banfilter and time is not exceeded
            #   then do nothing and continue
            next;
        }
    }
}


1;
