package IpBan::RSYNC;
use strict;
use warnings;
use parent 'IpBan::Service';

my $PORT = 873;
my $AUTHLOG = '/var/log/rsyncd.log';
my %AUTHLOG_SEARCH = (
    match => {
        'connect from' => {
            ip4 => qr/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/,
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
    $args{name} = 'rsync';
    $args{authlogsearch} = \%AUTHLOG_SEARCH;

    my $self = bless {}, $class;
    $self->SUPER::_init(%args);

    return $self;
}

1;
