use strict;
use warnings;

use vars (qw($Self));

local $ENV{REMOTE_USER}         = 'remote@example.com';
local $ENV{HTTP_X_REMOTE_EMAIL} = 'mail@example.com';

my $Login;

if ( $ENV{REMOTE_USER} ) {
    $Login = $ENV{REMOTE_USER};
}
elsif ( $ENV{HTTP_X_REMOTE_EMAIL} ) {
    $Login = $ENV{HTTP_X_REMOTE_EMAIL};
}

$Self->Is(
    $Login,
    'remote@example.com',
    'REMOTE_USER has priority',
);

1;