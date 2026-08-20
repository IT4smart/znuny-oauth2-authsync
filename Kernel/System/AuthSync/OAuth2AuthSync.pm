package Kernel::System::AuthSync::OAuth2AuthSync;

use strict;
use warnings;

use MIME::Base64 qw(decode_base64url);
use JSON qw(decode_json);

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::User',
    'Kernel::System::Group',
    'Kernel::System::Log',
);

sub new {
    my ( $Type, %Param ) = @_;

    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

sub _ReadAccessToken {
    my ( $Self ) = @_;

    my $Token = $ENV{HTTP_X_ACCESS_TOKEN};

    return if !$Token;

    my @Parts = split /\./, $Token;

    return if scalar @Parts < 2;

    my $Payload;

    eval {
        $Payload = decode_base64url( $Parts[1] );
    };

    return if !$Payload;

    my $Claims;

    eval {
        $Claims = decode_json($Payload);
    };

    return if !$Claims;

    return $Claims;
}

sub _DetermineLogin {
    my ( $Self, $Claims ) = @_;

    return $ENV{REMOTE_USER}
        if $ENV{REMOTE_USER};

    return $ENV{HTTP_X_REMOTE_EMAIL}
        if $ENV{HTTP_X_REMOTE_EMAIL};

    return $Claims->{preferred_username}
        if $Claims
        && $Claims->{preferred_username};

    return $Claims->{email}
        if $Claims
        && $Claims->{email};

    return;
}

sub Sync {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $UserObject   = $Kernel::OM->Get('Kernel::System::User');
    my $GroupObject  = $Kernel::OM->Get('Kernel::System::Group');
    my $LogObject    = $Kernel::OM->Get('Kernel::System::Log');

    my $Claims = $Self->_ReadAccessToken();

    my $UserLogin =
        $Param{User}
        || $Self->_DetermineLogin($Claims);

    return if !$UserLogin;

    $LogObject->Log(
        Priority => 'notice',
        Message  => "OAuth2AuthSync: UserLogin <$UserLogin>",
    );

    my %ProtectedUsers = map { $_ => 1 }
        @{ $ConfigObject->Get('OAuth2AuthSync::ProtectedUsers') || [] };

    if ( $ProtectedUsers{$UserLogin} ) {

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: User <$UserLogin> is protected",
        );

        return 1;
    }

    my $Email =
           $ENV{HTTP_X_REMOTE_EMAIL}
        || ($Claims && $Claims->{email})
        || $UserLogin;

    my $FirstName =
           $ENV{HTTP_X_REMOTE_GIVEN_NAME}
        || ($Claims && $Claims->{given_name})
        || '';

    my $LastName =
           $ENV{HTTP_X_REMOTE_FAMILY_NAME}
        || ($Claims && $Claims->{family_name})
        || '';

    my $DisplayName =
           $ENV{HTTP_X_REMOTE_NAME}
        || ($Claims && $Claims->{name})
        || '';

    if ( !$FirstName && !$LastName && $DisplayName ) {

        if ( $DisplayName =~ /^(.+?)\s+(.+)$/ ) {
            $FirstName = $1;
            $LastName  = $2;
        }
    }

    my $UserID = $UserObject->UserLookup(
        UserLogin => $UserLogin,
    );

    if (!$UserID) {

        $LogObject->Log(
            Priority => 'notice',
            Message  => "OAuth2AuthSync: Creating <$UserLogin>",
        );

        $UserID = $UserObject->UserAdd(
            UserLogin     => $UserLogin,
            UserFirstname => $FirstName || 'OAuth2',
            UserLastname  => $LastName  || 'User',
            UserEmail     => $Email,
            ValidID       => 1,
            UserID        => 1,
        );

        if (!$UserID) {

            $LogObject->Log(
                Priority => 'error',
                Message  => "OAuth2AuthSync: User creation failed",
            );

            return;
        }
    }

    $UserObject->UserUpdate(
        UserID        => $UserID,
        UserLogin     => $UserLogin,
        UserFirstname => $FirstName,
        UserLastname  => $LastName,
        UserEmail     => $Email,
        ValidID       => 1,
        ChangeUserID  => 1,
    );

    #
    # Read Group Mapping
    #
    my $GroupMapping =
        $ConfigObject->Get('OAuth2AuthSync::GroupMapping') || {};

    #
    # Read Groups from Header or JWT
    #
    my @EntraGroups;

    if ( $ENV{HTTP_X_REMOTE_GROUPS} ) {

        @EntraGroups =
            split /\s*,\s*/, $ENV{HTTP_X_REMOTE_GROUPS};

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: Groups Header <$ENV{HTTP_X_REMOTE_GROUPS}>",
        );
    }
    elsif (
        $Claims
        && ref $Claims->{groups} eq 'ARRAY'
        )
    {

        @EntraGroups = @{ $Claims->{groups} };

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: Using groups from JWT",
        );
    }

    if (!@EntraGroups) {

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: No Entra groups received",
        );

        return 1;
    }

    GROUP:
    for my $EntraGroup (@EntraGroups) {

        my $Mapped = $GroupMapping->{$EntraGroup};

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: EntraGroup <$EntraGroup>",
        );

        next GROUP if !$Mapped;

        my @ZnunyGroups;

        if ( ref $Mapped eq 'ARRAY' ) {
            @ZnunyGroups = @{$Mapped};
        }
        else {
            @ZnunyGroups = ($Mapped);
        }

        for my $ZnunyGroup (@ZnunyGroups) {

            $LogObject->Log(
                Priority => 'notice',
                Message =>
                    "OAuth2AuthSync: Mapping <$EntraGroup> -> <$ZnunyGroup>",
            );

            my $GroupID = $GroupObject->GroupLookup(
                Group => $ZnunyGroup,
            );

            if (!$GroupID) {

                $LogObject->Log(
                    Priority => 'error',
                    Message =>
                        "OAuth2AuthSync: GroupLookup failed for <$ZnunyGroup>",
                );

                next;
            }

            $LogObject->Log(
                Priority => 'notice',
                Message =>
                    "OAuth2AuthSync: Found GroupID <$GroupID>",
            );

            my $Success =
                $GroupObject->PermissionGroupUserAdd(
                    UID           => $UserID,
                    GID           => $GroupID,
                    PermissionKey => 'rw',
                    UserID        => 1,
                );

            $LogObject->Log(
                Priority => 'notice',
                Message =>
                    "OAuth2AuthSync: PermissionGroupUserAdd "
                  . "UID=$UserID "
                  . "GID=$GroupID "
                  . "RESULT="
                  . ( defined $Success ? $Success : 'undef' ),
            );
        }
    }

    return 1;
}

1;