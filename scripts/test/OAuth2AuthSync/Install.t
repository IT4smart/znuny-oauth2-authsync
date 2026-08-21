use strict;
use warnings;

use vars (qw($Self));

$Self->True(
    -f $Kernel::OM->Get('Kernel::Config')->Get('Home')
    . '/Kernel/System/AuthSync/OAuth2AuthSync.pm',
    'Module installed',
);

$Self->True(
    -f $Kernel::OM->Get('Kernel::Config')->Get('Home')
    . '/Kernel/Config/Files/XML/OAuth2AuthSync.xml',
    'Config installed',
);

1;