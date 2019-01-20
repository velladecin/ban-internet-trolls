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
        'Disconnected from' => {
            ip4 => qr/from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port /
        },
    },
);

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
