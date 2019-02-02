package IpBan::SSH;
use strict;
use warnings;
use parent 'IpBan::Service';

my $PORT = 22;
my $AUTHLOG = '/var/log/auth.log';
my %AUTHLOG_SEARCH = (
    daemon => qr/sshd\[\d+\]/,
    match => {
        'Failed password' => {
            ip4 => qr/from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port /
        },
        # This is really the same connection as above
        # TODO confirm this from logs!
        #'Disconnected from' => {
        #    ip4 => qr/from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port /
        #},
    },
);

# TODO - investigate this
=head
Feb  2 23:57:11 loubi sshd[15276]: Failed password for root from 218.92.1.174 port 16029 ssh2
Feb  2 23:57:11 loubi sshd[15276]: error: maximum authentication attempts exceeded for root from 218.92.1.174 port 16029 ssh2 [preauth]
Feb  2 23:57:11 loubi sshd[15276]: Disconnecting: Too many authentication failures [preauth]
Feb  2 23:57:11 loubi sshd[15276]: PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=218.92.1.174  user=root
Feb  2 23:57:11 loubi sshd[15276]: PAM service(sshd) ignoring max retries; 6 > 3
=cut

sub new {
    my $class = shift;
    my %args = @_;

    # configurable
    $args{port} ||= $PORT;
    $args{authlog} ||= $AUTHLOG;
    # hardcoded
    $args{name} = 'ssh';
    $args{authlogsearch} = \%AUTHLOG_SEARCH; 

    my $self = bless {}, $class;
    $self->SUPER::__init(%args);

    return $self;
}


1;
