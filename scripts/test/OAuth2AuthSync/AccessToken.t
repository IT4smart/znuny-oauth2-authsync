use strict;
use warnings;

use vars (qw($Self));

use MIME::Base64 qw(encode_base64url);
use JSON;

my $Header = encode_base64url(
    '{"alg":"none"}'
);

my $Payload = encode_base64url(
    encode_json(
        {
            email       => 'raphael.lekies@it4smart.com',
            given_name  => 'Raphael',
            family_name => 'Lekies',
        }
    )
);

my $Token = "$Header.$Payload.";

my @Parts = split /\./, $Token;

$Self->True(
    scalar(@Parts) >= 2,
    'JWT payload available',
);

1;