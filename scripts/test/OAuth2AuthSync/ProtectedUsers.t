use strict;
use warnings;

use vars (qw($Self));

my %ProtectedUsers = (
    'root@localhost' => 1,
);

$Self->True(
    $ProtectedUsers{'root@localhost'},
    'root@localhost is protected',
);

1;