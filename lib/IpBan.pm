package IpBan;
use strict;
use warnings;
use Data::Dumper;
use NetAddr::IP;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Log;

my $IPT4 = '/sbin/iptables';
my $IPT6 = '/sbin/ip6tables';
my $IPBANID = 'IPBANxkeivFHio5qdiIHFi3nf';
my $IPBANBLID = 'IPBANblacklist';

my @Ipver = qw(ip4 ip6);

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
    my ($class, $log, $blacklist) = @_;

    die "Expecting Log object as parameter for IpBan"
        unless ref $log eq 'Log';

    my $selfbody = {
        log => $log,
        ip4 => { blacklist => $blacklist->{ip4} || {} },
        ip6 => { blacklist => $blacklist->{ip6} || {} },
    };

    my $self = bless $selfbody, $class;
    $self->__init();

    return $self;
}

sub __init {
    my $self = shift;

    $self->_blreconcile(1);

    my $now = time();
    for my $ipver (@Ipver) {
        my %collection;
        my ($rules, $rulecount) = $self->__getdynrules($ipver);
        $self->linfo("Reconciling dynamic $ipver: $rulecount rules,", scalar(keys %$rules), "sid on service start (config vs netfilter)");

        # on startup we cannot say when the IP was banned,
        # so.. just make it now
        for my $sid (keys %$rules) {
            for my $ip (keys %{$rules->{$sid}}) {
                $rules->{$sid}{$ip} = {
                    start => $now,
                    lastseen => $now,
                };
            }
        }

        $self->{$ipver}{banned} = $rules;
    }
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

    $ip = "$ip/32"  if $ipver eq 'ip4';
    $ip = "$ip/128" if $ipver eq 'ip6';
    
    my $now = time();
    my $gbase = $self->{$ipver}{grace};
    my $bbase = $self->{$ipver}{banned};
    my $cbase = $self->{$ipver}{candidate};

    if (keys %$gbase && $gbase->{$sid}{$ip}) {
        $self->linfo("Ingest & update grace cache for $sid, $ip");
        $gbase->{$sid}{$ip}{lastseen} = $now;
    }
    elsif (keys %$bbase && $bbase->{$sid}{$ip}) {
        # we should not need to do anything with 'banned',
        # but there may be a little race condition, where when keepalive
        # connection is used we can get additional auth fail attempt even
        # after we have banned the IP. Should be max of 2 attempts..
        $self->linfo("Ingest & update banned cache for $ip - already banned but still using keep-alive conn");
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
            __ban($ipt, $service->getproto(), $ip, $service->getport(), $IPBANID);

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
                #$self->linfo("!!! Banning: $ip, $sid, total count: ", $cbase->{$ip}{count});
                $self->linfo(
                    sprintf '!!! Banning: %s, %s(%s), total count: %d',
                        $ip, $service->getname(), $sid, $cbase->{$ip}{count}
                );
                # add to banned
                $self->{$ipver}{banned}{$sid}{$ip} = {
                    start => $now,
                    lastseen => $cbase->{$ip}{lastseen} || $now,
                };

                # delete candidate
                delete $cbase->{$ip};

                # physically ban
                my $ipt = $ipver =~ /4/ ? $IPT4 : $IPT6;
                __ban($ipt, $service->getproto(), $ip, $service->getport(), $IPBANID);

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

    # reconcile blacklists
    $self->_blreconcile();

    for my $ipv (@Ipver) {
        my ($rules, $rulecount) = $self->__getdynrules($ipv);
        $self->ldebug("Reconciling $ipv: $rulecount rules,", scalar(keys %$rules), "sid");

        # Run thru what we have collected above, 
        # and look it up in $self to reconcile each entry
        my $bbase = $self->{$ipv}{banned};

        my $now = time();
        for my $sid (keys %$rules) {
            for my $ip (keys %{$rules->{$sid}}) {
                if ($bbase->{$sid}{$ip}) {
                    $bbase->{$sid}{$ip}{reconciled} = 1
                }
                else {
                    # Before adding to banned, better make sure
                    # that the entry does not exist in candidates or grace.
                    # There's a miniscule chance of a race condition..
                    my $gbase = $self->{$ipv}{grace};
                    my $cbase = $self->{$ipv}{candidate};
                    delete $gbase->{$sid}{$ip} if $gbase->{$sid}{$ip};
                    delete $cbase->{$sid}{$ip} if $cbase->{$sid}{$ip};

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
                    $self->lwarn("Removing from in-memory(banned) collection due to reconciliation: $ipv, $sid, $ip");
                    delete $bbase->{$sid}{$ip};
                    next;
                }

                # remove the flag!
                delete $bbase->{$sid}{$ip}{reconciled};
            }
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
sub lsetdebug {
    my ($self, $value) = @_;
    return $self->{log}->setdebug($value);
}



#
# Protected Subs

# TODO remove this and debugging Dumper in enforce()
sub _debug { return $_[0]->{log}->is_debug(); }

sub _blreconcile {
    my ($self, $init) = @_;

    IPver: for my $ipver (@Ipver) {
        my ($blrules, $blcount) = $self->__getblrules($ipver);
        my $lmsg = sprintf 'Reconciling blacklist %s: %d rules, %d sid',
                    $ipver, $blcount, scalar(keys %$blrules);

        $init ? $self->linfo($lmsg. " on service start (config vs netfilter)")
              : $self->ldebug($lmsg);

        my ($cmd, $subnet, $afinet) = $ipver eq 'ip4'
            ? ($IPT4, "/32") : ($IPT6, "/128");

        my $blbase = $self->{$ipver}{blacklist};

        # if no blacklist given, remove all existing blacklist rules
        unless (keys %$blbase) {
            for my $sid (keys %$blrules) {
                my ($proto, $port) = split /:/, $sid;

                for my $ip (keys %{$blrules->{$sid}}) {
                    $self->linfo("*** UN-banning: $ip, $sid (previously blacklisted, but current blacklist is empty)");
                    __unban($cmd, $proto, $ip, $port, $IPBANBLID)
                }
            }

            # nothing else to do here
            next IPver;
        }

        # iptables change 1.1.1.100/24 to 1.1.1.0/24 and ip6tables change 0:0:0 to ::
        # NetAddr::IP (see blacklist init processing) on the other hand returns 0:0:0 (ipv6).
        # So we can never be sure that the string representation of IPs will actually match..
        # Translate them to integers and compare those.

        my %blbase_n = my %blrules_n = ();

        for my $sid (keys %$blbase) {
            my ($proto, $port) = split /:/, $sid;

            for my $ip (@{$blbase->{$sid}}) {
                # add subnet only if it does not exist
                my $ips = $ip =~ m|/\d+$| ? $ip : $ip . $subnet;

                my $i = NetAddr::IP->new($ips)->numeric();
                $blbase_n{$sid}{$i} = [ $cmd, $proto, $ips, $port, $IPBANBLID ];
            }

            for my $ips (keys %{$blrules->{$sid}}) { # these come with /subnets
                my $i = NetAddr::IP->new($ips)->numeric();
                $blrules_n{$sid}{$i} = [ $cmd, $proto, $ips, $port, $IPBANBLID ];
            }
        }

        # Go thru given blacklist and remove each from the current rules.
        # Whatever is left needs to be removed, whatever is missing needs to be added.

        for my $sid (keys %blbase_n) {
            for my $ip (keys %{$blbase_n{$sid}}) {
                if ($blrules_n{$sid} and $blrules_n{$sid}{$ip}) {
                    delete $blrules_n{$sid}{$ip};
                    next;
                }

                # if not found then ban
                my @dets = @{ $blbase_n{$sid}{$ip} };
                $self->linfo("!!! Banning: $dets[2], $sid (blacklisted)");
                __ban(@dets);
            }

            # un-ban whatever is left
            if (keys %{$blrules_n{$sid}}) {
                for my $ip (keys %{$blrules_n{$sid}}) {
                    my @dets = @{ $blrules_n{$sid}{$ip} };
                    $self->linfo("*** UN-banning: $dets[2], $sid (previously defined in blacklist)");
                    __unban(@dets);
                }
            }
        }
    }

    1;
}


#
# Private

sub __getrulesdetails {
    my ($self, $ipver, $comstring, $init) = @_;

    $self->linfo("Collecting currently banned $ipver IPs (from netfilter)")
        if $init;

    my ($cmd, $rgx) = $ipver eq 'ip4'
# -A INPUT -s 95.85.12.206/32 -p tcp -m tcp --dport 22 -m comment --comment IPBANxkeivFHio5qdiIHFi3nf -j REJECT --reject-with icmp-port-unreachable
        ? ($IPT4, qr|-s\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+)\s-p\s([a-z]+)\s.*--dport\s(\d+)\s|)
# -A INPUT -s 2407:500::2:b15b:efb2/128 -p tcp -m tcp --dport 22 -m comment --comment IPBANxkeivFHio5qdiIHFi3nf -j REJECT --reject-with icmp6-port-unreachable
        : ($IPT6, qr|-s\s([a-f0-9:]+/\d+)\s-p\s([a-z]+)\s.*--dport\s(\d+)\s|);

    my @return;
    for my $line (grep /$comstring/, qx($cmd -S INPUT)) {
        chomp $line;

        my ($ip, $proto, $port) = $line =~ $rgx;

        unless ($ip and $proto and $port) {
            $self->lwarn("Could not retrieve service details for $ipver rule :: '$line' :: ip:'$ip', proto:'$proto', port:'$port'");
            next;
        }

        $self->linfo("Found $ipver: $ip, $proto, $port")
            if $init;

        push @return, [$ip, $proto, $port];
    }

    return @return;
}

sub __getblrules {
    my ($self, $ipver) = @_;
    return $self->__getrules($IPBANBLID, $ipver, 'blacklist');
}

sub __getdynrules {
    my ($self, $ipver) = @_;
    return $self->__getrules($IPBANID, $ipver, 'dynamic rules');
}

sub __getrules {
    my ($self, $comstring, $ipver, $ruletype) = @_;

    $self->ldebug("Retrieving netfilter rules: $ipver / $ruletype");

    my %rules;
    my $rulecount = 0;
    for my $arr ($self->__getrulesdetails($ipver, $comstring)) {
        my ($ip, $proto, $port) = @$arr;

        # Manage doubled up rules here too..
        my $sid = "$proto:$port";
        if ($rules{$sid}{$ip}) {
            # doubled up
            $self->lwarn("~~~ Removing: $ip, $sid, doubled up netfilter rule (will stay banned)");
            __unban($ipver eq 'ip4' ? $IPT4 : $IPT6, $proto, $ip, $port, $comstring);
        }
        else {
            # single
            $rules{$sid}{$ip} = 1;
            $rulecount++;
        }
    }

    return \%rules, $rulecount;
}

sub __ban {
    my ($ipt, $proto, $ip, $port, $comment) = @_;

    my $ban = sprintf '%s -I INPUT 1 -p %s -s %s --dport %d -m comment --comment %s -j REJECT',
        $ipt, $proto, $ip, $port, $comment;

    qx($ban);

    1;
}

sub __unban {
    my ($ipt, $proto, $ip, $port, $comment) = @_;

    my $unban = sprintf '%s -D INPUT -p %s -s %s --dport %d -m comment --comment %s -j REJECT',
        $ipt, $proto, $ip, $port, $comment;

    qx($unban);

    1;
}


1;
