use strict;
use warnings;

use vars (qw($Self));

my $Mapping = {

    '6ca98e0e-1c28-4640-bb71-3a5c6c7b1ef2' => [
        'users',
    ],

    '11800f5c-4cf0-403a-91f4-4976cf5283be' => [
        'admin',
    ],
};

$Self->Is(
    $Mapping->{'6ca98e0e-1c28-4640-bb71-3a5c6c7b1ef2'}->[0],
    'users',
    'Users mapping OK',
);

$Self->Is(
    $Mapping->{'11800f5c-4cf0-403a-91f4-4976cf5283be'}->[0],
    'admin',
    'Admin mapping OK',
);

1;