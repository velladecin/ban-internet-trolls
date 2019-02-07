package IpBan;
use strict;
use warnings;
use Data::Dumper;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Log;

my $IPT4 = '/sbin/iptables';
my $IPT6 = '/sbin/ip6tables';
my $IPBANID = 'IPBANxkeivFHio5qdiIHFi3nf';

=head1 NAME

IpBan - will ban IPs, via iptables

=head1 SYNOPSIS

    my $ib = IpBan->new(Log);

=over 8

B<Log> - object of Log instance (see lib)
         You can create your own Log as long as it implements
         info, warn, crit methods

=back

    $ib->ingest4(1.1.1.1, count, sid);
    $ib->ingest6(a:b:c:d:e:f:1:2, count, sid);

    $ib->enforce(service);

=cut

=head2 Methods

=over 8

=item C<new(Log)>

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

    $self->{log}->info("Collecting currently banned IPs (from netfilter)");

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
        $ban4{"$proto:$port"}{$ip} = {
            start => $now,
            lastseen => $now,
        }
    }

    $self->{log}->info("IPv4: None")
        unless keys %ban4;

    # TODO ipv6
#    my %ban6;
#    for my $line (grep /$IPBANID/, qx($IPT6 -S INPUT)) {
#        chomp $line;
#
#        my ($ip, $proto, $port) = $line =~ m||;
#
#        print ">>> $line\n";
#    }
#
#    $self->{log}->info("IPv6: None")
#        unless keys %ban6;

    $self->{ip4}{banned} = \%ban4;
    $self->{ip6}{banned} = \%ban6;
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

    # TODO fix this -> ip4}{banned}{..} structure has changed

    my %return;
    @return{keys %{$self->{ip4}{banned}}} = values %{$self->{ip4}{banned}} if $type =~ /^4$/;
    @return{keys %{$self->{ip6}{banned}}} = values %{$self->{ip6}{banned}} if $type =~ /^6$/;

    return %return;
}

=over 8

=item C<ingest4(ip, count, sid)>

ingest IPv4 IP together with count (of failed logins) and service id (proto:port)


=item C<ingest6(ip, count, sid)>

ingest IPv6 IP together with count (of failed logins) and service id (proto:port)

=back

=cut

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
    my $gbase = $self->{$ipver}{grace};
    my $bbase = $self->{$ipver}{banned};
    my $cbase = $self->{$ipver}{candidate};

    if (keys %$gbase && $gbase->{$sid}{$ip}) {
        $self->linfo("Ingest & update grace cache for $ip");
        $gbase->{$sid}{$ip}{lastseen} = $now;
    }
    elsif (keys %$bbase && $bbase->{$sid}{$ip}) {
        # we should not need to do anything with 'banned',
        # but there may be a little race condition, where when keepalive
        # connection is used we can get additional auth fail attempt even
        # after we have banned the IP. Should be max of 2 attempts..
        $self->linfo("Ingest & update banned!!! cache for $ip - how did this happen??");
        $bbase->{$sid}{$ip}{lastseen} = $now;
    }
    elsif (keys %$cbase && $cbase->{$sid}{$ip}) {
        $cbase->{$sid}{$ip}{count} += $count;
        $cbase->{$sid}{$ip}{lastseen} = $now;
        $self->linfo("Ingest & update candidate cache for $ip, count ", $cbase->{$sid}{$ip}{count});
    }
    else {
        $self->linfo("Ingest & add to candidate cache $ip, count $count");
        $cbase->{$sid}{$ip} = {
            start => $now,
            count => $count,
            lastseen => $now,
        };
    }

    1;
}

sub enforce {
    my ($self, $service) = @_;

    print Dumper $self
        if $self->_debug();

    my $sid = $service->getid();
    my $now = time();

    for my $ipver ($service->getipver()) {
        # grace-time
        my $gbase = $self->{$ipver}{grace}{$sid};
        for my $ip (keys %$gbase) {
            unless ($gbase->{$ip}{lastseen}) {
                my $gdelta = $now - $gbase->{$ip}{start};
                # ban grace time expired,
                # this fully 'un-bans' a user
                if ($gdelta > $service->getbantimegrace()) {
                    $self->linfo("^^^ Removing from bantime-grace pool: $ip, $sid");
                    goto DELETE_FROM_GRACE;
                }

                next;
            }

            # ban her again..
            my $gdelta = $gbase->{$ip}{lastseen} - $gbase->{$ip}{start};

            $self->linfo("!!! Banning: $ip, $sid, breached bantime-grace in ${gdelta}s");
            $self->{$ipver}{banned}{$sid}{$ip} = {
                start => $now,
                lastseen => $now,
            };

            # physically ban
            my $ipt = $ipver =~ /4/ ? $IPT4 : $IPT6;
            __ban($ipt, $service->getproto(), $ip, $service->getport());

            DELETE_FROM_GRACE:
            delete $gbase->{$ip};
        }

        # banned
        my $bbase = $self->{$ipver}{banned}{$sid};
        for my $ip (keys %$bbase) {
            # if currently banned and still trolls (lastseen within the designated 'bantime', see config for details)
            # then take no action (ban continues), othewise un-ban that IP
            my $tdelta = $now - $bbase->{$ip}{lastseen};

            # tdelta can be negative - daylight saving
            # in this case update lastseen to now and move on
            if ($tdelta < 0) {
                $self->lwarn("Negative time delta($tdelta) for banned IP($ip), re-setting lastseen to now($now) and moving on");
                $bbase->{$ip}{lastseen} = $now;
                next;
            }

            # lastseen timestamp is updated during ingest (above)
            # the only possible action here is to UN-ban
            if ($tdelta > $service->getbantime()) {
                $self->linfo("*** UN-banning: $ip, $sid (entering bantime-grace: ", $service->getbantimegrace(). "s)");
                delete $bbase->{$ip};

                # add to grace-time
                $self->{$ipver}{grace}{$sid}{$ip} = { start => $now }; 

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
                $self->linfo("!!! Banning: $ip, $sid, total count: ", $cbase->{$ip}{count});
                # add to banned
                $self->{$ipver}{banned}{$sid}{$ip} = {
                    start => $now,
                    lastseen => $cbase->{$ip}{lastseen} || $now,
                };

                # delete candidate
                delete $cbase->{$ip};

                # physically ban
                my $ipt = $ipver =~ /4/ ? $IPT4 : $IPT6;
                __ban($ipt, $service->getproto(), $ip, $service->getport());

                next;
            }

            my $tdelta = $now - $cbase->{$ip}{start};

            # 2. if count does not satisfy banfilter and time is exceeded
            #   then remove from candidates (restart counts)
            if ($tdelta > $secs) {
                $self->linfo("Removing candidate $ip, total count: ", $cbase->{$ip}{count});
                delete $cbase->{$ip};
            }

            # 3. if count does not satisfy banfilter and time is not exceeded
            #   then do nothing and continue
            next;
        }

        my %counts;
        for my $type (qw(grace banned candidate)) {
            if ($self->{$ipver}{$type} && keys %{$self->{$ipver}{$type}}) {
                my $base = $self->{$ipver}{$type};

                for my $sid (keys %$base) {
                    $counts{$sid}{$type} = [ sort keys %{$base->{$sid}} ];
                }
            }
            else {
                $counts{none}{$type} = [];
            }
        }

        for my $sid (sort keys %counts) {
            for my $type (sort keys %{$counts{$sid}}) {
                my $count = scalar @{$counts{$sid}{$type}};
                $self->ldebug("SID: $sid, $type count: $count, IPs:", join(', ', @{$counts{$sid}{$type}}));
            }
        }
    }
}

sub reconcile {
    my $self = shift;
    #-A INPUT -s 129.213.119.45/32 -p tcp -m tcp --dport 22 -m comment --comment IPBANxkeivFHio5qdiIHFi3nf -j REJECT --reject-with icmp-port-unreachable

    my %rules;
    my $rulecount = 0;
    for my $rule (qx($IPT4 -S INPUT | grep $IPBANID)) {
        my ($ip, $proto, $port, $action) =
            $rule =~ m|-A INPUT -s (\d+\.\d+\.\d+\.\d+/32) -p (\w+) .* --dport (\d+) .* -j ([A-Z]+).*$|; 

        unless ($ip and $proto and $port and $action) {
            $self->lcrit("Could not retrieve all values from iptables for reconciliation: ip:$ip, proto:$proto, port:$port, action:$action");
            next;
        }

        my $sid = "$proto:$port";
        $rules{$sid}{$ip} = 1;
        $rulecount++;
    }

    $self->ldebug("Reconciling: $rulecount rules,", scalar(keys %rules), "sid");

    # TODO fix this to loop thru ip4, ip6

    # Run thru what we have collected above, 
    # and look it up in $self to reconcile each entry
    my $bbase = $self->{ip4}{banned};
    my $now = time();
    for my $sid (keys %rules) {
        for my $ip (keys %{$rules{$sid}}) {
            if ($bbase->{$sid}{$ip}) {
                $bbase->{$sid}{$ip}{reconciled} = 1
            }
            else {
                # Before adding to banned, better make sure
                # that the entry does not exist in candidates or grace.
                # There's a miniscule chance of a race condition..
                my $gbase = $self->{ip4}{grace};
                my $cbase = $self->{ip4}{candidate};
                $bbase->{$sid}{$ip} = {
                    start => $now,
                    lastseen => $now,
                    reconciled => 1,
                };
            }
        }
    }

    # Run thru self and remove anything that's not reconciled
    for my $sid (keys %$bbase) {
        for my $ip (keys %{$bbase->{$sid}}) {
            unless ($bbase->{$sid}{$ip}{reconciled}) {
                # TODO - input to bantime-grace
                $self->lwarn("Removing from in-memory(banned) collection due to reconciliation: $sid, $ip");
                delete $bbase->{$sid}{$ip};
                next;
            }

            # remove the flag!
            delete $bbase->{$sid}{$ip}{reconciled};
        }
    }

    1;
}

#
# Logging

sub lclose {
    my $self = shift;
    $self->{log}->close();
}

sub linfo {
    my ($self, @msg) = @_;
    $self->{log}->info(@msg)
        if $self->{log};
}
sub lwarn {
    my ($self, @msg) = @_;
    $self->{log}->warn(@msg)
        if $self->{log};
}
sub lcrit {
    my ($self, @msg) = @_;
    $self->{log}->crit(@msg)
        if $self->{log};
}
sub ldebug {
    my ($self, @msg) = @_;
    $self->{log}->debug(@msg)
        if $self->{log} and $self->{log}->is_debug();
}


#
# Protected Subs

# TODO remove this and debugging Dumper in enforce()
sub _debug { return $_[0]->{log}->is_debug(); }


#
# Private

sub __ban {
    my ($ipt, $proto, $ip, $port) = @_;

    my $ban = sprintf '%s -I INPUT 1 -p %s -s %s --dport %d -m comment --comment %s -j REJECT',
        $ipt, $proto, $ip, $port, $IPBANID;

    qx($ban);

    1;
}


1;
